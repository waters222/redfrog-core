package routing

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/weishi258/go-iptables/iptables"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
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
	CHAIN_RED_FROG   = "RED_FROG"
	CHAIN_PREROUTING = "PREROUTING"
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
}

func StartRoutingMgr(port int, mark string, ignoreIP []string, interfaceName[] string) (ret *RoutingMgr, err error) {
	logger := log.GetLogger()
	ret = &RoutingMgr{}

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
	if err = ret.createDivertChain(port, mark, false); err != nil {
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

	if err = ret.createDivertChain(port, mark, true); err != nil {
		return
	}
	if err = ret.createRedFrogChain(true); err != nil {
		return
	}
	if err = ret.initPreRoutingChain(true, interfaceName); err != nil {
		return
	}
	logger.Info("IPTables v6 successful created")
	logger.Info("Init routing manager successful")
	return
}

func (c *RoutingMgr) createDivertChain(port int, mark string, isIPv6 bool) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}
	if err = handler.ClearChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil {
		err = errors.Wrap(err, fmt.Sprintf("Create/Flush %s chain failed", CHAIN_TPROXY))
		return
	}
	handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-p", "tcp", "-j", "TPROXY", "--tproxy-mark", mark, "--on-port", strconv.FormatInt(int64(port), 10))
	handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-p", "udp", "-j", "TPROXY", "--tproxy-mark", mark, "--on-port", strconv.FormatInt(int64(port), 10))
	handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-j", "ACCEPT")
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



	if isIPv6{
		// add dns filter
		if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", "::1/128", "-j", "RETURN"); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain to avoid loop-back addr failed")
			return
		}

		if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "udp", "--dport", "53", "-j", CHAIN_TPROXY); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain for DNS filter failed")
			return
		}


		for _, ipNet := range c.ignoreIPNet {
			if ipNet.IP.To4() == nil {
				if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipNet.String(), "-j", "RETURN"); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}
			}
		}

	}else{
		if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", "127.0.0.1/24", "-j", "RETURN"); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain failed to avoid loop-back addr ")
			return
		}
		if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "udp", "--dport", "53", "-j", CHAIN_TPROXY); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain for DNS filter failed")
			return
		}


		for _, ipNet := range c.ignoreIPNet {
			if ipNet.IP.To4() != nil {
				if err = handler.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ipNet.String(), "-j", "RETURN"); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}
			}
		}
	}


	return
}


func (c *RoutingMgr) deletePrerouting(iptbl *iptables.IPTables) error{
	if rules, err := iptbl.List(TABLE_MANGLE, CHAIN_PREROUTING); err != nil{
		err = errors.Wrapf(err, "List chain %s -> %s failed", TABLE_MANGLE, CHAIN_PREROUTING)
		return err
	}else{
		for _, rule := range rules{
			stubs := strings.Split(rule, " ")
			length := len(stubs)
			if length > 4{
				if stubs[length - 1] == CHAIN_RED_FROG && stubs[length - 2] == "-j"{
					if err = iptbl.Delete(TABLE_MANGLE, CHAIN_PREROUTING, stubs[2:]...); err != nil{
						err = errors.Wrapf(err, "Delete rule from chain %s -> %s: %v failed", TABLE_MANGLE, CHAIN_PREROUTING, stubs[2:])
						return err
					}
				}
			}
		}
	}

	return nil
}
func (c *RoutingMgr) initPreRoutingChain(isIPv6 bool, interfaceName[] string) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}

	if err = c.deletePrerouting(handler); err != nil{
		return
	}

	interfaceAdded := false
	if len(interfaceName) > 0 {
		for _, name := range interfaceName{
			if len(name) > 0{
				if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-i", name, "-j", CHAIN_RED_FROG); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}else{
					interfaceAdded = true
				}
			}
		}
	}
	if !interfaceAdded{
		if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-j", CHAIN_RED_FROG); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain failed")
			return
		}
	}

	return
}

func (c *RoutingMgr) clearIPTables(iptbl *iptables.IPTables) {
	logger := log.GetLogger()

	if err := c.deletePrerouting(iptbl); err != nil{
		logger.Error("Delete rule from chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_PREROUTING), zap.String("error", err.Error()))
	}


	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_RED_FROG), zap.String("error", err.Error()))
	}else if err = iptbl.DeleteChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil{
		logger.Error("Delete chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_RED_FROG), zap.String("error", err.Error()))
	}
	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_TPROXY), zap.String("error", err.Error()))
	}else if err = iptbl.DeleteChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil{
		logger.Error("Delete chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_TPROXY), zap.String("error", err.Error()))
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
	file, err := os.Create(CACHE_PATH) // For read access.
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
	file, err := os.Open(CACHE_PATH) // For read access.
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
func (c *RoutingMgr) AddIp(domain string, ip net.IP) (err error) {
	isIPv6 := ip.To4() == nil
	if c.isChanged(domain, ip, isIPv6) {
		if isIPv6 {
			if errAdd := c.routingTableAddIPV6(ip); errAdd != nil {
				log.GetLogger().Error("Add IP to routing table failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}
		} else {
			if errAdd := c.routingTableAddIPV4(ip); errAdd != nil {
				log.GetLogger().Error("Add IP to routing table failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}
		}
	}
	return
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
					if _, ok := domains[stub]; ok {
						keep = true
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
					if _, ok := domains[stub]; ok {
						keep = true
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
		if err := c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY); err != nil {
			logger.Error("Routing table add IPv4 failed", zap.String("ips", ips), zap.String("error", err.Error()))
		} else {
			logger.Debug("Routing table add IPv4 successful", zap.String("ips", ips))
		}
	}
	if len(ipv6tablesList) > 0 {
		ips := composeIPList(ipv6tablesList)
		if err := c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY); err != nil {
			logger.Error("Routing table add IPv6 failed", zap.String("ips", ips), zap.String("error", err.Error()))
		} else {
			logger.Debug("Routing table add IPv6 successful", zap.String("ips", ips))
		}

	}
	if len(ipv4tablesDeleteList) > 0 {
		ips := composeIPList(ipv4tablesDeleteList)
		if err := c.ip4tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY); err != nil {
			logger.Error("Routing table delete IPv4 failed", zap.String("ips", ips), zap.String("error", err.Error()))
		} else {
			logger.Debug("Routing table delete IPv4 successful", zap.String("ips", ips))
		}
	}

	if len(ipv6tablesDeleteList) > 0 {
		ips := composeIPList(ipv6tablesDeleteList)
		if err := c.ip6tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY); err != nil {
			logger.Error("Routing table delete IPv6 failed", zap.String("ips", ips), zap.String("error", err.Error()))
		} else {
			logger.Debug("Routing table delete IPv6 successful", zap.String("ips", ips))
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
		c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY)
		logger.Debug("Routing table add ipv4", zap.String("ip", ips))
	}
	if len(ipv6tablesList) > 0 {
		ips := composeIPList(ipv6tablesList)
		c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY)
		logger.Debug("Routing table add ipv6", zap.String("ip", ips))
	}

}
func composeIPList(ips map[string]bool) string {
	temp := make([]string, 0)
	for ip := range ips {
		temp = append(temp, ip)
	}
	return strings.Join(temp, ",")
}

func (c *RoutingMgr) routingTableAddIPV4(ip net.IP) (err error) {
	logger := log.GetLogger()
	if err = c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
		logger.Error("Routing table add IPv4 failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
		return
	}
	logger.Debug("Routing table add IPv4 successful", zap.String("ip", ip.String()))
	return
}
func (c *RoutingMgr) routingTableAddIPV6(ip net.IP) (err error) {
	logger := log.GetLogger()
	if err = c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
		logger.Error("Routing table add IPv6 failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
		return
	}
	logger.Debug("Routing table add IPv6 successful", zap.String("ip", ip.String()))
	return
}

func (c *RoutingMgr) routingTableDelIPv4(ip net.IP) (err error) {
	logger := log.GetLogger()

	if err = c.ip4tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
		logger.Error("Routing table del IPv4 failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
		return
	}
	logger.Debug("Routing table del IPv4 successful", zap.String("ip", ip.String()))
	return
}

func (c *RoutingMgr) routingTableDelIPv6(ip net.IP) (err error) {
	logger := log.GetLogger()

	if err = c.ip6tbl.Delete(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY); err != nil {
		logger.Error("Routing table del IPv6 failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
		return
	}
	logger.Debug("Routing table del IPv6 successful", zap.String("ip", ip.String()))
	return
}
