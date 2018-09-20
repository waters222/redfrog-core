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

func StartRoutingMgr(port int, mark string, ignoreIP []string, interfaceName string) (ret *RoutingMgr, err error) {
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

	return
}
func (c *RoutingMgr) initPreRoutingChain(isIPv6 bool, interfaceName string) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}

	if err = handler.FlushChain(TABLE_MANGLE, CHAIN_PREROUTING); err != nil {
		err = errors.Wrapf(err, "Flush chain %s -> %s failed", TABLE_MANGLE, CHAIN_PREROUTING)
		return
	}

	for _, ipNet := range c.ignoreIPNet {
		if isIPv6 {
			if ipNet.IP.To4() == nil {
				if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-d", ipNet.String(), "-j", "RETURN"); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}
			}
		} else {
			if ipNet.IP.To4() != nil {
				if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-d", ipNet.String(), "-j", "RETURN"); err != nil {
					err = errors.Wrap(err, "Append into PREROUTING chain failed")
					return
				}
			}
		}
	}
	if len(interfaceName) > 0 {
		if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-i", interfaceName, "-j", CHAIN_RED_FROG); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain failed")
			return
		}
	}else{
		if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING, "-j", CHAIN_RED_FROG); err != nil {
			err = errors.Wrap(err, "Append into PREROUTING chain failed")
			return
		}
	}


	return
}

func (c *RoutingMgr) clearIPTables(iptbl *iptables.IPTables) {
	logger := log.GetLogger()

	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_PREROUTING); err != nil {
		logger.Error("Flush chain failed", zap.String("table", TABLE_MANGLE), zap.String("chain", CHAIN_PREROUTING), zap.String("error", err.Error()))
	}

	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_RED_FROG), zap.String("error", err.Error()))
	}
	if err := iptbl.FlushChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil {
		logger.Error("Flush chain failed", zap.String("chain", CHAIN_TPROXY), zap.String("error", err.Error()))
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
	defer c.Unlock()
	cache := &RoutingMgrCache{c.ipListV4, c.ipListV6}
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

func (c *RoutingMgr) LoadPacList(domains map[string]bool, ips map[string]bool) {
	logger := log.GetLogger()

	c.Lock()
	ipv4tablesList := make([]string, 0)
	ipv6tablesList := make([]string, 0)
	for ipInput, bDomainListType := range ips {
		if bDomainListType == common.DOMAIN_BLACK_LIST {
			ip := net.ParseIP(ipInput)
			if isIPv4 := ip.To4(); isIPv4 != nil {
				c.ipListV4[ipInput] = []net.IP{ip}
				ipv4tablesList = append(ipv4tablesList, ip.String())
			} else {
				ipv6tablesList = append(ipv6tablesList, ip.String())
				c.ipListV6[ipInput] = []net.IP{ip}
			}

		}

	}
	if cache, err := c.deserializeRoutingTable(); err != nil {
		logger.Error("Reading routing cache failed", zap.String("error", err.Error()))

		for domain, bDomainListType := range domains {
			if bDomainListType == common.DOMAIN_BLACK_LIST {
				c.ipListV4[domain] = []net.IP{}
				c.ipListV6[domain] = []net.IP{}
			}
		}
	} else {
		for domain, bDomainListType := range domains {
			if bDomainListType == common.DOMAIN_BLACK_LIST {
				if ips, ok := cache.IPv4[domain]; ok {
					c.ipListV4[domain] = ips
					for _, ip := range ips {
						ipv4tablesList = append(ipv4tablesList, ip.String())
					}
				}
				if ips, ok := cache.IPv6[domain]; ok {
					c.ipListV6[domain] = ips
					for _, ip := range ips {
						ipv6tablesList = append(ipv6tablesList, ip.String())
					}
				}

			}
		}
	}
	c.Unlock()

	logger.Info("Load pac list finished")

	if len(ipv4tablesList) > 0 {
		ips := strings.Join(ipv4tablesList, ",")
		c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY)
		logger.Debug("Routing table add ipv4", zap.String("ip", ips))
	}
	if len(ipv6tablesList) > 0 {
		ips := strings.Join(ipv6tablesList, ",")
		c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ips, "-j", CHAIN_TPROXY)
		logger.Debug("Routing table add ipv6", zap.String("ip", ips))
	}

}

func (c *RoutingMgr) routingTableAddIPV4(ip net.IP) (err error) {
	logger := log.GetLogger()
	logger.Debug("routing table add ipv4", zap.String("ip", ip.String()))
	c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY)
	return
}
func (c *RoutingMgr) routingTableAddIPV6(ip net.IP) (err error) {
	logger := log.GetLogger()
	logger.Debug("routing table add ipv6", zap.String("ip", ip.String()))
	c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY)
	return
}
