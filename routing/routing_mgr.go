package routing

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/weishi258/go-iptables/iptables"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/ipset"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	TABLE_MANGLE     = "mangle"
	CHAIN_TPROXY     = "RED_FROG_TPROXY"
	CHAIN_DIVERT     = "RED_FROG_DIVERT"
	CHAIN_RED_FROG   = "RED_FROG"
	CHAIN_PREROUTING = "PREROUTING"

	IPSET_RED_FROG_V4 = "RED_FROG_IPSET_V4"
	IPSET_RED_FROG_V6 = "RED_FROG_IPSET_V6"

	ROUTING_PRIORITY = 1
)
const (
	CACHE_PATH = "routing_mgr_cache.yaml"
)

type RoutingMgrCache struct {
	IPv4 map[string][]net.IP `yaml:"ipv4"`
	IPv6 map[string][]net.IP `yaml:"ipv6"`
}

type RoutingMgr struct {
	sync.RWMutex
	ipListV4 map[string][]net.IP
	ipListV6 map[string][]net.IP

	ip4tbl *iptables.IPTables
	ip6tbl *iptables.IPTables

	ignoreIPNet []*net.IPNet
	ipSetV4     *ipset.IPSet
	ipSetV6     *ipset.IPSet

	routingTableNum int
	markMast        string
}

func StartRoutingMgr(port int, mark string, routingTableNum int, ignoreIP []string, interfaceName []string, bIPSet bool) (ret *RoutingMgr, err error) {
	logger := log.GetLogger()
	ret = &RoutingMgr{}
	ret.routingTableNum = routingTableNum
	ret.markMast = mark

	if err = ret.addDelRoutingRule(mark, routingTableNum, false, true); err != nil {
		return
	}
	logger.Debug("Add routing rule ipv4 successful")
	if err = ret.addDelRoutingRoute(routingTableNum, false, true); err != nil {
		return
	}
	logger.Debug("Add routing route ipv4 successful")
	if err = ret.addDelRoutingRule(mark, routingTableNum, true, true); err != nil {
		return
	}
	logger.Debug("Add routing rule ipv6 successful")
	if err = ret.addDelRoutingRoute(routingTableNum, true, true); err != nil {
		return
	}
	logger.Debug("Add routing route ipv6 successful")

	if bIPSet {
		if ret.ipSetV4, err = ipset.New(IPSET_RED_FROG_V4, "hash:ip", &ipset.Params{Timeout: 0, HashFamily: "inet", MaxElem: 4294967295}); err != nil {
			logger.Warn("IPSetV4 init failed, so fallback to using iptables", zap.String("error", err.Error()))
		}
		if ret.ipSetV6, err = ipset.New(IPSET_RED_FROG_V6, "hash:ip", &ipset.Params{Timeout: 0, HashFamily: "inet6", MaxElem: 4294967295}); err != nil {
			logger.Warn("IPSetV6 init failed, so fallback to using ip6tables", zap.String("error", err.Error()))
		}
	}

	if ignoreIP != nil {
		ret.ignoreIPNet = make([]*net.IPNet, 0)
		for _, ipStr := range ignoreIP {
			if _, ipnet, err := net.ParseCIDR(ipStr); err == nil {
				ret.ignoreIPNet = append(ret.ignoreIPNet, ipnet)
			} else {
				logger.Warn("IgnoreIP format is invalid", zap.String("error", err.Error()))
			}
		}
	}
	ret.ipListV4 = make(map[string][]net.IP)
	ret.ipListV6 = make(map[string][]net.IP)

	// lets create new iptabls chains
	if ret.ip4tbl, err = iptables.New(); err != nil {
		err = errors.Wrap(err, "Create IPTables handler failed")
		return
	}
	if err = ret.createTProxyMarkChain(port, mark, false); err != nil {
		return
	}
	if err = ret.createDivertChain(false, mark); err != nil {
		return
	}
	if err = ret.createRedFrogChain(false); err != nil {
		return
	}
	if err = ret.initPreRoutingChain(false, interfaceName); err != nil {
		return
	}
	logger.Info("IPTables v4 successful created")

	if ret.ip6tbl, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil {
		err = errors.Wrap(err, "Create IPTables handler failed")
		return
	}

	if err = ret.createTProxyMarkChain(port, mark, true); err != nil {
		return
	}
	if err = ret.createDivertChain(true, mark); err != nil {
		return
	}
	if err = ret.createRedFrogChain(true); err != nil {
		return
	}
	if err = ret.initPreRoutingChain(true, interfaceName); err != nil {
		return
	}
	logger.Info("IPTables v6 successful created")
	logger.Info("Start routing manager successful")
	return
}

func (c *RoutingMgr) createTProxyMarkChain(port int, mark string, isIPv6 bool) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}
	if err = handler.ClearChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil {
		err = errors.Wrap(err, fmt.Sprintf("Create/Flush %s chain failed", CHAIN_TPROXY))
		return
	}
	if err = handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-p", "tcp", "-j", "TPROXY", "--tproxy-mark", mark, "--on-port", strconv.FormatInt(int64(port), 10)); err != nil {
		err = errors.Wrapf(err, "Append into %s chain failed", CHAIN_TPROXY)
		return
	}
	if err = handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-p", "udp", "-j", "TPROXY", "--tproxy-mark", mark, "--on-port", strconv.FormatInt(int64(port), 10)); err != nil {
		err = errors.Wrapf(err, "Append into %s chain failed", CHAIN_TPROXY)
		return
	}
	if err = handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-j", "ACCEPT"); err != nil {
		err = errors.Wrapf(err, "Append into %s chain failed", CHAIN_TPROXY)
		return
	}
	return
}

func (c *RoutingMgr) createDivertChain(isIPv6 bool, mark string) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}
	if err = handler.ClearChain(TABLE_MANGLE, CHAIN_DIVERT); err != nil {
		err = errors.Wrap(err, fmt.Sprintf("Create/Flush %s chain failed", CHAIN_DIVERT))
		return
	}

	if err = handler.Append(TABLE_MANGLE, CHAIN_DIVERT, "-j", "MARK", "--set-mark", mark); err != nil {
		err = errors.Wrapf(err, "Append into %s chain failed", CHAIN_DIVERT)
		return
	}
	if err = handler.Append(TABLE_MANGLE, CHAIN_DIVERT, "-j", "ACCEPT"); err != nil {
		err = errors.Wrapf(err, "Append into %s chain failed", CHAIN_DIVERT)
		return
	}
	return
}

func (c *RoutingMgr) createRedFrogChain(isIPv6 bool) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}
	if err = handler.ClearChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil {
		err = errors.Wrap(err, fmt.Sprintf("Create/Flush %s chain failed", CHAIN_RED_FROG))
	}

	// add divert
	if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-m", "socket", "-j", CHAIN_DIVERT); err != nil {
		err = errors.Wrap(err, "Append into RED_FROG chain to avoid double tap for TProxy")
		return
	}

	if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "RETURN"); err != nil {
		err = errors.Wrap(err, "Append into RED_FROG chain to return established connection")
		return
	}

	if isIPv6 {
		for _, ipNet := range c.ignoreIPNet {
			if ipNet.IP.To4() == nil {
				if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipNet.String(), "-j", "RETURN"); err != nil {
					err = errors.Wrap(err, "Append into RED_FROG chain failed")
					return
				}
			}
		}
		// add dns filter
		if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "udp", "--dport", "53", "-j", CHAIN_TPROXY); err != nil {
			err = errors.Wrap(err, "Append into RED_FROG chain for DNS filter failed")
			return
		}
		if c.ipSetV6 != nil {
			// add ipset filter
			if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-m", "set", "--set", IPSET_RED_FROG_V6, "dst", "-j", CHAIN_TPROXY); err != nil {
				err = errors.Wrapf(err, "Append into RED_FROG chain %s filter failed", IPSET_RED_FROG_V6)
				return
			}
		}
	} else {
		for _, ipNet := range c.ignoreIPNet {
			if ipNet.IP.To4() != nil {
				if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipNet.String(), "-j", "RETURN"); err != nil {
					err = errors.Wrap(err, "Append into RED_FROG chain failed")
					return
				}
			}
		}
		// add dns filter
		if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "udp", "--dport", "53", "-j", CHAIN_TPROXY); err != nil {
			err = errors.Wrap(err, "Append into RED_FROG chain for DNS filter failed")
			return
		}

		if c.ipSetV4 != nil {
			// add ipset filter
			if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-m", "set", "--set", IPSET_RED_FROG_V4, "dst", "-j", CHAIN_TPROXY); err != nil {
				err = errors.Wrapf(err, "Append into RED_FROG chain for %s filter failed", IPSET_RED_FROG_V4)
				return
			}
		}
	}

	return
}

func (c *RoutingMgr) deletePrerouting(iptbl *iptables.IPTables) error {
	if rules, err := iptbl.List(TABLE_MANGLE, CHAIN_PREROUTING); err != nil {
		err = errors.Wrapf(err, "List chain %s -> %s failed", TABLE_MANGLE, CHAIN_PREROUTING)
		return err
	} else {
		for _, rule := range rules {
			stubs := strings.Split(rule, " ")
			length := len(stubs)
			if length >= 4 {
				if stubs[length-1] == CHAIN_RED_FROG && stubs[length-2] == "-j" {
					if err = iptbl.Delete(TABLE_MANGLE, CHAIN_PREROUTING, stubs[2:]...); err != nil {
						err = errors.Wrapf(err, "Delete rule from chain %s -> %s: %v failed", TABLE_MANGLE, CHAIN_PREROUTING, stubs[2:])
						return err
					}
				}
			}
		}
	}

	return nil
}
func (c *RoutingMgr) initPreRoutingChain(isIPv6 bool, interfaceName []string) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}

	if err = c.deletePrerouting(handler); err != nil {
		return
	}

	interfaceAdded := false
	if len(interfaceName) > 0 {
		for _, name := range interfaceName {
			if len(name) > 0 {
				if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-p", "tcp", "-i", name, "-j", CHAIN_RED_FROG); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}
				if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-p", "udp", "-i", name, "-j", CHAIN_RED_FROG); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}
				interfaceAdded = true
			}
		}
	}
	if !interfaceAdded {
		if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-p", "tcp", "-j", CHAIN_RED_FROG); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain failed")
			return
		}
		if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-p", "udp", "-j", CHAIN_RED_FROG); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain failed")
			return
		}
	}

	return
}

func (c *RoutingMgr) clearIPTables(iptbl *iptables.IPTables) {
	logger := log.GetLogger()

	if err := c.deletePrerouting(iptbl); err != nil {
		logger.Error("Delete rule from chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_PREROUTING), zap.String("error", err.Error()))
	}

	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_RED_FROG), zap.String("error", err.Error()))
	} else if err = iptbl.DeleteChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil {
		logger.Error("Delete chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_RED_FROG), zap.String("error", err.Error()))
	}
	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_DIVERT); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_DIVERT), zap.String("error", err.Error()))
	} else if err = iptbl.DeleteChain(TABLE_MANGLE, CHAIN_DIVERT); err != nil {
		logger.Error("Delete chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_DIVERT), zap.String("error", err.Error()))
	}
	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_TPROXY), zap.String("error", err.Error()))
	} else if err = iptbl.DeleteChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil {
		logger.Error("Delete chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_TPROXY), zap.String("error", err.Error()))
	}

	if c.ipSetV4 != nil {
		if err := c.ipSetV4.Destroy(); err != nil {
			logger.Error("Destroy IPSetV4 failed", zap.String("name", IPSET_RED_FROG_V4), zap.String("error", err.Error()))
		}
	}
	if c.ipSetV6 != nil {
		if err := c.ipSetV6.Destroy(); err != nil {
			logger.Error("Destroy IPSetV6 failed", zap.String("name", IPSET_RED_FROG_V4), zap.String("error", err.Error()))
		}
	}

	if err := c.addDelRoutingRoute(c.routingTableNum, false, false); err != nil {
		logger.Error("Delete routing route failed", zap.String("error", err.Error()))
	}
	if err := c.addDelRoutingRule(c.markMast, c.routingTableNum, false, false); err != nil {
		logger.Error("Delete routing rule failed", zap.String("error", err.Error()))
	}

	if err := c.addDelRoutingRoute(c.routingTableNum, true, false); err != nil {
		logger.Error("Delete routing route failed", zap.String("error", err.Error()))
	}
	if err := c.addDelRoutingRule(c.markMast, c.routingTableNum, true, false); err != nil {
		logger.Error("Delete routing rule failed", zap.String("error", err.Error()))
	}
}

func (c *RoutingMgr) Stop() {
	logger := log.GetLogger()
	c.serializeRoutingTable()

	c.clearIPTables(c.ip4tbl)
	c.clearIPTables(c.ip6tbl)
	logger.Info("Routing manager stopped")
}

func (c *RoutingMgr) serializeRoutingTable() (err error) {
	file, err := os.Create(config.GetPathFromWorkingDir(CACHE_PATH)) // For read access.
	if err != nil {
		err = errors.Wrapf(err, "Create routing cache file %s failed", CACHE_PATH)
		return
	}
	defer file.Close()
	c.Lock()
	// strip empty ip
	ipListV4 := make(map[string][]net.IP)
	ipListV6 := make(map[string][]net.IP)
	for domain, ips := range c.ipListV4 {
		if ips != nil && len(ips) > 0 {
			// make sure its not ip addrs
			if tempIP := net.ParseIP(domain); tempIP == nil {
				ipListV4[domain] = ips
			}
		}

	}
	for domain, ips := range c.ipListV6 {
		if ips != nil && len(ips) > 0 {
			// make sure its not ip addrs
			if tempIP := net.ParseIP(domain); tempIP == nil {
				ipListV6[domain] = ips
			}
		}
	}
	c.Unlock()

	cache := &RoutingMgrCache{ipListV4, ipListV6}
	data, err := yaml.Marshal(cache)
	if err != nil {
		err = errors.Wrap(err, "Marshal routing cache failed")
		return
	}

	if _, err = file.Write(data); err != nil {
		err = errors.Wrapf(err, "Write to routing cache file %s failed", CACHE_PATH)
	}

	return
}

func (c *RoutingMgr) deserializeRoutingTable() (ret *RoutingMgrCache, err error) {
	file, err := os.Open(config.GetPathFromWorkingDir(CACHE_PATH)) // For read access.
	if err != nil {
		err = errors.Wrapf(err, "Create routing cache file %s failed", CACHE_PATH)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		err = errors.Wrapf(err, "Create routing cache file %s failed", CACHE_PATH)
		return
	}

	ret = &RoutingMgrCache{}
	if err = yaml.Unmarshal(data, ret); err != nil {
		err = errors.Wrapf(err, "Create routing cache file %s failed", CACHE_PATH)

	}
	return
}

func (c *RoutingMgr) AddIPStr(domain string, input string) (err error) {
	return c.AddIp(domain, net.ParseIP(input))
}

func (c *RoutingMgr) isChanged(domain string, ip net.IP, isIPv6 bool) bool {
	c.Lock()
	defer c.Unlock()

	var ipMap map[string][]net.IP

	if isIPv6 {
		ipMap = c.ipListV6
	} else {
		ipMap = c.ipListV4
	}

	ips, ok := ipMap[domain]
	if !ok {
		ips = make([]net.IP, 1)
		ips[0] = ip
	} else {
		// lets check if ip already exists
		for _, elem := range ips {
			if elem.Equal(ip) {
				return false
			}
		}
		ips = append(ips, ip)
	}
	ipMap[domain] = ips
	return true
}
func (c *RoutingMgr) AddIp(domain string, ip net.IP) error {
	isIPv6 := ip.To4() == nil
	if c.isChanged(domain, ip, isIPv6) {
		if isIPv6 {
			if err := c.routingTableAddIPV6(ip); err != nil {
				log.GetLogger().Error("Add IP to routing table failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}
		} else {
			if err := c.routingTableAddIPV4(ip); err != nil {
				log.GetLogger().Error("Add IP to routing table failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}
		}
	}
	return nil
}

func (c *RoutingMgr) FlushRoutingTable() (err error) {
	logger := log.GetLogger()
	logger.Info("Flush routing table")
	return
}
func (c *RoutingMgr) PopulateRoutingTable() (err error) {
	logger := log.GetLogger()
	logger.Info("Populate routing table")

	c.RLock()
	defer c.RUnlock()

	for domain, ips := range c.ipListV4 {
		for _, ip := range ips {
			if err = c.routingTableAddIPV4(ip); err != nil {
				logger.Error("Add ip to routing table failed", zap.String("domain", domain), zap.String("ip", ip.String()), zap.String("error", err.Error()))
			} else {
				logger.Error("Add ip to routing table successful", zap.String("domain", domain), zap.String("ip", ip.String()))
			}
		}
	}
	for domain, ips := range c.ipListV6 {
		for _, ip := range ips {
			if err = c.routingTableAddIPV6(ip); err != nil {
				logger.Error("Add ip to routing table failed", zap.String("domain", domain), zap.String("ip", ip.String()), zap.String("error", err.Error()))
			} else {
				logger.Error("Add ip to routing table successful", zap.String("domain", domain), zap.String("ip", ip.String()))
			}
		}
	}

	return
}

func (c *RoutingMgr) ReloadPacList(domains map[string]bool, ips map[string]bool, ipDeleteList []string) {
	logger := log.GetLogger()
	c.Lock()
	ipv4tablesList := make(map[string]bool)
	ipv6tablesList := make(map[string]bool)

	// find out which ip need to be added
	for ipInput := range ips {
		ip := net.ParseIP(ipInput)
		if isIPv4 := ip.To4(); isIPv4 != nil {
			if _, ok := c.ipListV4[ipInput]; !ok {
				c.ipListV4[ipInput] = []net.IP{ip}
				ipv4tablesList[ip.String()] = true
			}
		} else {
			if _, ok := c.ipListV6[ipInput]; !ok {
				c.ipListV6[ipInput] = []net.IP{ip}
				ipv6tablesList[ip.String()] = true
			}
		}
	}

	ipv4tablesDeleteList := make(map[string]bool)
	ipv6tablesDeleteList := make(map[string]bool)

	// delete ip according to delete list
	for _, ipInput := range ipDeleteList {
		if ip := net.ParseIP(ipInput); ip.To4() != nil {
			ipv4tablesDeleteList[ipInput] = true
			delete(c.ipListV4, ipInput)
		} else {
			ipv6tablesDeleteList[ipInput] = true
			delete(c.ipListV6, ipInput)
		}
	}

	domainDeleteList := make([]string, 0)
	for domain, ips := range c.ipListV4 {
		// make sure its not ip address
		if isIP := net.ParseIP(domain); isIP == nil {
			keep := false
			if stubs := common.GenerateDomainStubs(domain); stubs != nil && len(stubs) > 0 {
				for _, stub := range stubs {
					if flag, ok := domains[stub]; ok {
						keep = flag
						break
					}
				}
			}
			if !keep {
				domainDeleteList = append(domainDeleteList, domain)
				for _, ip := range ips {
					ipv4tablesDeleteList[ip.String()] = true
				}

			}
		}

	}
	for _, domain := range domainDeleteList {
		delete(c.ipListV4, domain)
	}

	domainDeleteList = make([]string, 0)
	for domain, ips := range c.ipListV6 {
		if isIP := net.ParseIP(domain); isIP == nil {
			keep := false
			if stubs := common.GenerateDomainStubs(domain); stubs != nil && len(stubs) > 0 {
				for _, stub := range stubs {
					if flag, ok := domains[stub]; ok {
						keep = flag
						break
					}
				}
			}
			if !keep {
				domainDeleteList = append(domainDeleteList, domain)
				for _, ip := range ips {
					ipv6tablesDeleteList[ip.String()] = true
				}
			}
		}

	}
	for _, domain := range domainDeleteList {
		delete(c.ipListV6, domain)
	}

	c.Unlock()

	logger.Info("Reload pac list finished")

	if len(ipv4tablesList) > 0 {
		ips := composeIPList(ipv4tablesList)
		if err := c.routingTableAddIPV4List(ips); err != nil {
			logger.Error("ReloadPacList failed", zap.String("error", err.Error()))
		}
	}
	if len(ipv6tablesList) > 0 {
		ips := composeIPList(ipv6tablesList)
		if err := c.routingTableAddIPV6List(ips); err != nil {
			logger.Error("ReloadPacList failed", zap.String("error", err.Error()))
		}
	}

	if len(ipv4tablesDeleteList) > 0 {
		ips := composeIPList(ipv4tablesDeleteList)
		if err := c.routingTableDelIPv4List(ips); err != nil {
			logger.Error("ReloadPacList failed", zap.String("error", err.Error()))
		}
	}

	if len(ipv6tablesDeleteList) > 0 {
		ips := composeIPList(ipv6tablesDeleteList)
		if err := c.routingTableDelIPv6List(ips); err != nil {
			logger.Error("ReloadPacList failed", zap.String("error", err.Error()))
		}

	}
}

func (c *RoutingMgr) LoadPacList(domains map[string]bool, ips map[string]bool) {

	logger := log.GetLogger()
	c.Lock()
	ipv4tablesList := make(map[string]bool)
	ipv6tablesList := make(map[string]bool)
	for ipInput := range ips {
		ip := net.ParseIP(ipInput)
		if isIPv4 := ip.To4(); isIPv4 != nil {
			c.ipListV4[ipInput] = []net.IP{ip}
			ipv4tablesList[ip.String()] = true
		} else {
			c.ipListV6[ipInput] = []net.IP{ip}
			ipv6tablesList[ip.String()] = true
		}
	}

	if cache, err := c.deserializeRoutingTable(); err != nil {
		logger.Info("Reading routing cache failed", zap.String("error", err.Error()))
	} else {
		for domain, ips := range cache.IPv4 {
			if ips != nil && len(ips) > 0 {
				if stubs := common.GenerateDomainStubs(domain); stubs != nil && len(stubs) > 0 {
					for _, stub := range stubs {
						if _, ok := domains[stub]; ok {
							c.ipListV4[domain] = ips
							for _, ip := range ips {
								ipv4tablesList[ip.String()] = true
							}
						}
					}

				}
			}
		}
		for domain, ips := range cache.IPv6 {
			if ips != nil && len(ips) > 0 {
				if stubs := common.GenerateDomainStubs(domain); stubs != nil && len(stubs) > 0 {
					for _, stub := range stubs {
						if _, ok := c.ipListV6[stub]; ok {
							c.ipListV6[domain] = ips
							for _, ip := range ips {
								ipv6tablesList[ip.String()] = true
							}
						}
					}

				}
			}

		}
	}
	c.Unlock()

	logger.Info("Load pac list finished")

	if len(ipv4tablesList) > 0 {
		ips := composeIPList(ipv4tablesList)
		if err := c.routingTableAddIPV4List(ips); err != nil {
			logger.Error("Load pack list failed", zap.String("error", err.Error()))
		}
	}
	if len(ipv6tablesList) > 0 {
		ips := composeIPList(ipv6tablesList)
		if err := c.routingTableAddIPV6List(ips); err != nil {
			logger.Error("Load pack list failed", zap.String("error", err.Error()))
		}
	}

}
func composeIPList(ips map[string]bool) []string {
	temp := make([]string, 0)
	for ip := range ips {
		temp = append(temp, ip)
	}
	return temp
}

func (c *RoutingMgr) routingTableAddIPV4(ip net.IP) error {
	if c.ipSetV4 != nil {
		if err := c.ipSetV4.Add(ip.String(), 0); err != nil {
			return errors.Wrap(err, "Routing table add IPSetV4 failed")
		}
		log.GetLogger().Debug("Routing table add IPSetV4 successful", zap.String("ip", ip.String()))
	} else {
		if err := c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrap(err, "Routing table add IPv4 failed")
		}
		log.GetLogger().Debug("Routing table add IPv4 successful", zap.String("ip", ip.String()))
	}
	return nil
}
func (c *RoutingMgr) routingTableAddIPV4List(ips []string) error {
	if c.ipSetV4 != nil {
		for _, ip := range ips {
			if err := c.ipSetV4.Add(ip, 0); err != nil {
				return errors.Wrap(err, "Routing table add IPSetV4 failed")
			}
		}
		log.GetLogger().Debug("Routing table add IPSetV4 successful", zap.String("ip", strings.Join(ips, ",")))
	} else {
		ipsStr := strings.Join(ips, ",")
		if err := c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipsStr, "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrapf(err, "Routing table add IPv4 failed: %s", ipsStr)
		}
		log.GetLogger().Debug("Routing table add IPv4 successful", zap.String("ips", ipsStr))
	}

	return nil
}

func (c *RoutingMgr) routingTableAddIPV6(ip net.IP) error {
	if c.ipSetV6 != nil {
		if err := c.ipSetV6.Add(ip.String(), 0); err != nil {
			return errors.Wrap(err, "Routing table add IPSetV6 failed")
		}
		log.GetLogger().Debug("Routing table add IPSetV6 successful", zap.String("ip", ip.String()))
	} else {
		if err := c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrap(err, "Routing table add IPv6 failed")
		}
		log.GetLogger().Debug("Routing table add IPv6 successful", zap.String("ip", ip.String()))
	}

	return nil
}
func (c *RoutingMgr) routingTableAddIPV6List(ips []string) error {
	if c.ipSetV6 != nil {
		for _, ip := range ips {
			if err := c.ipSetV6.Add(ip, 0); err != nil {
				return errors.Wrap(err, "Routing table add IPSetV6 failed")
			}
		}
		log.GetLogger().Debug("Routing table add IPSetV6 successful", zap.String("ip", strings.Join(ips, ",")))
	} else {
		ipsStr := strings.Join(ips, ",")
		if err := c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipsStr, "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrapf(err, "Routing table add IPv6 failed: %s", ipsStr)
		}
		log.GetLogger().Debug("Routing table add IPv6 successful", zap.String("ips", ipsStr))
	}

	return nil
}

func (c *RoutingMgr) routingTableDelIPv4(ip net.IP) error {
	if c.ipSetV4 != nil {
		if err := c.ipSetV4.Del(ip.String()); err != nil {
			return errors.Wrap(err, "Routing table del IPSetV4 failed")
		}
		log.GetLogger().Debug("Routing table del IPSetV4 successful", zap.String("ip", ip.String()))
	} else {
		if err := c.ip4tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrap(err, "Routing table del IPv4 failed")
		}
		log.GetLogger().Debug("Routing table del IPv4 successful", zap.String("ip", ip.String()))
	}

	return nil
}

func (c *RoutingMgr) routingTableDelIPv4List(ips []string) error {
	if c.ipSetV4 != nil {
		for _, ip := range ips {
			if err := c.ipSetV4.Del(ip); err != nil {
				return errors.Wrap(err, "Routing table del IPSetV4 failed")
			}
		}
		log.GetLogger().Debug("Routing table del IPSetV4 successful", zap.String("ip", strings.Join(ips, ",")))
	} else {
		ipsStr := strings.Join(ips, ",")
		if err := c.ip4tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipsStr, "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrapf(err, "Routing table delete IPv4 failed: %s", ipsStr)
		}
		log.GetLogger().Debug("Routing table del IPv4 successful", zap.String("ips", ipsStr))
	}

	return nil
}

func (c *RoutingMgr) routingTableDelIPv6(ip net.IP) error {
	if c.ipSetV6 != nil {
		if err := c.ipSetV6.Del(ip.String()); err != nil {
			return errors.Wrap(err, "Routing table del IPSetV6 failed")
		}
		log.GetLogger().Debug("Routing table del IPSetV6 successful", zap.String("ip", ip.String()))
	} else {
		if err := c.ip6tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrap(err, "Routing table del IPv6 failed")
		}
		log.GetLogger().Debug("Routing table del IPv6 successful", zap.String("ip", ip.String()))
	}

	return nil
}

func (c *RoutingMgr) routingTableDelIPv6List(ips []string) error {
	if c.ipSetV6 != nil {
		for _, ip := range ips {
			if err := c.ipSetV6.Del(ip); err != nil {
				return errors.Wrap(err, "Routing table del IPSetV6 failed")
			}
		}
		log.GetLogger().Debug("Routing table del IPSetV6 successful", zap.String("ip", strings.Join(ips, ",")))
	} else {
		ipsStr := strings.Join(ips, ",")
		if err := c.ip6tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipsStr, "-j", CHAIN_TPROXY); err != nil {
			return errors.Wrapf(err, "Routing table delete IPv6 failed: %s", ipsStr)
		}
		log.GetLogger().Debug("Routing table del IPv6 successful", zap.String("ips", ipsStr))
	}

	return nil
}

func (c *RoutingMgr) addDelRoutingRule(markMask string, routingTableNum int, isIPv6 bool, bAdd bool) error {
	rule := netlink.NewRule()
	rule.Table = routingTableNum
	marks := strings.Split(markMask, "/")
	if len(marks) != 2 {
		return errors.New(fmt.Sprintf("Routing mark %s is invalid", markMask))
	}
	mark, err := strconv.ParseInt(marks[0], 0, 32)
	if err != nil {
		return errors.Wrapf(err, "Routing mark parse to int failed")
	}
	mask, err := strconv.ParseInt(marks[1], 0, 32)
	if err != nil {
		return errors.Wrapf(err, "Routing mask parse to int failed")
	}

	rule.Mark = int(mark)
	rule.Mask = int(mask)

	rule.Priority = ROUTING_PRIORITY
	var rules []netlink.Rule

	if isIPv6 {
		rule.Family = netlink.FAMILY_V6
		if rules, err = netlink.RuleList(netlink.FAMILY_V6); err != nil {
			return errors.Wrap(err, "List routing rule from ipv6 failed")
		}
	} else {
		rule.Family = netlink.FAMILY_V4
		if rules, err = netlink.RuleList(netlink.FAMILY_V4); err != nil {
			return errors.Wrap(err, "List routing rule from ipv4 failed")
		}
	}
	for _, entry := range rules {
		//log.GetLogger().Debug("Get rule", zap.Int("table", entry.Table), zap.Int("mark", entry.Mark), zap.Int("mask", entry.Mask))
		if entry.Table == rule.Table &&
			entry.Mark == rule.Mark &&
			entry.Mask == rule.Mask {
			// found one so to delete
			// set family because it does not return rule family, its a BUG!!!
			entry.Family = rule.Family
			if err = netlink.RuleDel(&entry); err != nil {
				return errors.Wrapf(err, "Delete routing rule failed: %s", entry.String())
			}
		}
	}
	if bAdd {
		if err = netlink.RuleAdd(rule); err != nil {
			return errors.Wrapf(err, "Add routing rule failed: %s", rule.String())
		}
	}

	return nil
}

func (c *RoutingMgr) addDelRoutingRoute(routingTableNum int, isIPv6 bool, bAdd bool) error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return errors.Wrapf(err, "Get loop back dev failed")
	}
	var dst *net.IPNet
	netFamily := netlink.FAMILY_V4
	if isIPv6 {
		if _, dst, err = net.ParseCIDR("::/0"); err != nil {
			return errors.Wrap(err, "Parse CIDR failed")
		}
		netFamily = netlink.FAMILY_V6
	} else {
		if _, dst, err = net.ParseCIDR("0.0.0.0/0"); err != nil {
			return errors.Wrap(err, "Parse CIDR failed")
		}
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index,
		Dst:      dst,
		Table:    routingTableNum,
		Type:     unix.RTN_LOCAL,
		Scope:    unix.RT_SCOPE_HOST,
		Priority: ROUTING_PRIORITY}

	//| netlink.RT_FILTER_TYPE | netlink.RT_FILTER_SCOPE
	if routes, err := netlink.RouteListFiltered(netFamily, route, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE); err != nil {
		return errors.Wrapf(err, "Route list failed")
	} else {
		for _, entry := range routes {
			//log.GetLogger().Debug("found routing rule", zap.Int("scope", int(entry.Scope)), zap.Int("type", entry.Type), zap.Int("table", entry.Table), zap.Int("LinkIndex", entry.LinkIndex))
			//if entry.Dst != nil{
			//	log.GetLogger().Debug(fmt.Sprintf("dst %s", entry.Dst.String()))
			//}
			//if entry.Src != nil{
			//	log.GetLogger().Debug(fmt.Sprintf("src %s", entry.Src.String()))
			//}
			//if entry.Gw != nil{
			//	log.GetLogger().Debug(fmt.Sprintf("gw %s", entry.Gw.String()))
			//}
			if entry.Type == route.Type &&
				entry.Table == route.Table &&
				entry.LinkIndex == route.LinkIndex {
				// this is to fix bug which routeList not returning dst address
				if entry.Dst == nil {
					entry.Dst = dst
				}
				if err = netlink.RouteDel(&entry); err != nil {
					return errors.Wrapf(err, "Route delete failed: %s", entry.String())

				}
			}
			//else{
			//	log.GetLogger().Debug("route aa", zap.Int("scope", int(route.Scope)), zap.Int("type", route.Type), zap.Int("table", route.Table), zap.Int("LinkIndex", route.LinkIndex))
			//}

		}
	}

	if bAdd {
		if err = netlink.RouteAdd(route); err != nil {
			return errors.Wrapf(err, "Route add failed: %s", route.String())
		}
	}

	return nil
}
