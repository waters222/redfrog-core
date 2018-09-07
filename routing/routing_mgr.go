package routing

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"net"
	"strconv"
	"sync"
)

const (
	TABLE_MANGLE = "mangle"
	CHAIN_TPROXY = "RED_FROG_TPROXY"
	CHAIN_RED_FROG = "RED_FROG"
	CHAIN_PREROUTING = "PREROUTING"
)

type RoutingMgr struct{
	mux				sync.RWMutex
	ipListV4		map[string][]net.IP
	ipListV6		map[string][]net.IP

	ip4tbl 			*iptables.IPTables
	ip6tbl 			*iptables.IPTables
}


func StartRoutingMgr(port int, mark string) (ret *RoutingMgr, err error){
	logger := log.GetLogger()
	ret = &RoutingMgr{}
	ret.ipListV4 = make(map[string][]net.IP)
	ret.ipListV6 = make(map[string][]net.IP)


	// lets create new iptabls chains
	if ret.ip4tbl, err = iptables.New(); err != nil{
		err = errors.Wrap(err, "Create IPTables handler failed")
		return
	}
	if err = ret.createDivertChain(port, mark, false); err != nil{
		return
	}
	if err = ret.createRedFrogChain(false); err != nil{
		return
	}
	if err = ret.initPreRoutingChain(false); err != nil{
		return
	}
	logger.Info("IPTables v4 successful created")
	//
	//if ret.ip6tbl, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil{
	//	err = errors.Wrap(err, "Create IPTables handler failed")
	//	return
	//}
	//
	//if err = ret.createDivertChain(port, mark, true); err != nil{
	//	return
	//}
	//if err = ret.createRedFrogChain(true); err != nil{
	//	return
	//}
	//if err = ret.initPreRoutingChain(true); err != nil{
	//	return
	//}
	//logger.Info("IPTables v6 successful created")
	logger.Info("Init routing manager successful")
	return
}

func (c *RoutingMgr) createDivertChain(port int, mark string, isIPv6 bool) (err error){
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}
	if err = handler.ClearChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil{
		err = errors.Wrap(err, fmt.Sprintf("Create/Flush %s chain failed", CHAIN_TPROXY))
		return
	}
	handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-p", "tcp", "-j", "TPROXY", "--tproxy-mark", mark, "--on-port", strconv.FormatInt(int64(port), 10))
	handler.Append(TABLE_MANGLE, CHAIN_TPROXY, "-p", "udp", "-j", "TPROXY", "--tproxy-mark", mark, "--on-port", strconv.FormatInt(int64(port), 10))
	return
}

func (c *RoutingMgr) createRedFrogChain(isIPv6 bool) (err error){
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}
	if err = handler.ClearChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil{
		err = errors.Wrap(err, fmt.Sprintf("Create/Flush %s chain failed", CHAIN_RED_FROG))
	}

	return
}
func (c *RoutingMgr) initPreRoutingChain(isIPv6 bool) (err error) {
	handler := c.ip4tbl
	if isIPv6 {
		handler = c.ip6tbl
	}

	if ee := handler.Delete(TABLE_MANGLE, CHAIN_PREROUTING,   "-j", CHAIN_RED_FROG); ee != nil{
		log.GetLogger().Warn("Delete into PREROUTING chain failed", zap.String("error", ee.Error()))
	}


	if err = handler.Append(TABLE_MANGLE, CHAIN_PREROUTING,  "-j", CHAIN_RED_FROG); err != nil{
		err = errors.Wrap(err, "Append into PREROUTING chain failed")
	}

	return
}

func (c* RoutingMgr)clearIPTables(iptbl *iptables.IPTables){
	logger := log.GetLogger()
	logger.Info("Stop routing manager")
	if err := iptbl.Delete(TABLE_MANGLE, CHAIN_PREROUTING, "-p", "tcp","-j", CHAIN_RED_FROG); err != nil{
		logger.Error("Delete rule from PREROUTING failed", zap.String("error", err.Error()))
	}
	if err := iptbl.Delete(TABLE_MANGLE, CHAIN_PREROUTING, "-p", "udp","-j", CHAIN_RED_FROG); err != nil{
		logger.Error("Delete rule from PREROUTING failed", zap.String("error", err.Error()))
	}

	if err := iptbl.DeleteChain(TABLE_MANGLE, CHAIN_RED_FROG); err != nil{
		logger.Error("Delete chain failed", zap.String("chain", CHAIN_RED_FROG ), zap.String("error", err.Error()))
	}
	if err := iptbl.DeleteChain(TABLE_MANGLE, CHAIN_TPROXY); err != nil{
		logger.Error("Delete chain failed", zap.String("chain", CHAIN_TPROXY ), zap.String("error", err.Error()))
	}
}

func (c *RoutingMgr) Stop(){
	logger := log.GetLogger()
	c.clearIPTables(c.ip4tbl)
	//c.clearIPTables(c.ip6tbl)
	logger.Info("Stop routing manager")
}
func (c *RoutingMgr) AddIPStr(domain string, input string) (err error){
	return c.AddIp(domain, net.ParseIP(input))
}


func (c *RoutingMgr)isChanged(domain string, ip net.IP, isIPv6 bool) bool{
	c.mux.Lock()
	defer c.mux.Unlock()

	var ipMap map[string][]net.IP

	if isIPv6{
		ipMap = c.ipListV6
	}else{
		ipMap = c.ipListV4
	}


	ips, ok := ipMap[domain]
	if !ok{
		ips = make([]net.IP, 1)
		ips[0] = ip
	}else{
		// lets check if ip already exists
		for _, elem := range ips{
			if elem.Equal(ip){
				return false
			}
		}
		ips = append(ips, ip)
	}
	ipMap[domain] = ips
	return true
}
func (c *RoutingMgr)AddIp(domain string, ip net.IP) (err error){
	isIPv6 := ip.To4() == nil
	if c.isChanged(domain, ip, isIPv6) {
		if isIPv6{
			if errAdd := c.routingTableAddIPV6(ip); errAdd != nil{
				log.GetLogger().Error("Add IP to routing table failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}
		}else{
			if errAdd := c.routingTableAddIPV4(ip); errAdd != nil{
				log.GetLogger().Error("Add IP to routing table failed", zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}
		}
	}
	return
}

func (c *RoutingMgr)FlushRoutingTable() (err error){
	logger := log.GetLogger()
	logger.Info("Flush routing table")
	return
}
func (c *RoutingMgr)PopulateRoutingTable() (err error){
	logger := log.GetLogger()
	logger.Info("Populate routing table")

	c.mux.RLock()
	defer c.mux.RUnlock()

	for domain, ips :=range c.ipListV4{
		for _, ip := range ips {
			if err = c.routingTableAddIPV4(ip); err != nil{
				logger.Error("Add ip to routing table failed", zap.String("domain", domain), zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}else{
				logger.Error("Add ip to routing table successful", zap.String("domain", domain), zap.String("ip", ip.String()))
			}
		}
	}
	for domain, ips :=range c.ipListV6{
		for _, ip := range ips {
			if err = c.routingTableAddIPV6(ip); err != nil{
				logger.Error("Add ip to routing table failed", zap.String("domain", domain), zap.String("ip", ip.String()), zap.String("error", err.Error()))
			}else{
				logger.Error("Add ip to routing table successful", zap.String("domain", domain), zap.String("ip", ip.String()))
			}
		}
	}

	return
}

func (c *RoutingMgr)ReloadPacList(domains map[string]bool, ips map[string]bool){

	ipListV4 := make(map[string][]net.IP)
	ipListV6 := make(map[string][]net.IP)

	for ipInput, bDomainListType := range ips{
		if bDomainListType == common.DOMAIN_BLACK_LIST{
			ip := net.ParseIP(ipInput)
			if len(ip) == net.IPv4len{
				ipListV4[ipInput] = []net.IP{ip}
			}else if len(ip) == net.IPv6len{
				ipListV6[ipInput] = []net.IP{ip}
			}
		}

	}
	bChanged := func() bool{
		c.mux.RLock()
		defer c.mux.RUnlock()
		for domain, bDomainListType := range domains{
			if bDomainListType == common.DOMAIN_BLACK_LIST{
				if ips, ok := c.ipListV4[domain]; ok {
					ipListV4[domain] = ips
				}
				if ips, ok := c.ipListV6[domain]; ok {
					ipListV6[domain] = ips
				}
			}
		}
		if len(ipListV4) == len(c.ipListV4) &&
			len(ipListV6) == len(c.ipListV6){
			// do nothing since there is no change
			return false
		}
		return true

	} ()

	if bChanged {
		c.mux.Lock()
		defer c.mux.Unlock()

		c.ipListV4 = ipListV4
		c.ipListV6 = ipListV6
	}
}

func (c *RoutingMgr)routingTableAddIPV4(ip net.IP) (err error){
	logger := log.GetLogger()
	logger.Debug("routing table add ipv4", zap.String("ip", ip.String()))
	c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY)
	//c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "tcp", "-d", ip.String(), "-j", CHAIN_TPROXY)
	//c.ip4tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "udp", "-d", ip.String(), "-j", CHAIN_TPROXY)
	return
}
func (c *RoutingMgr)routingTableAddIPV6(ip net.IP) (err error){
	logger := log.GetLogger()
	logger.Debug("routing table add ipv6", zap.String("ip", ip.String()))
	//c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-d", ip.String(), "-j", CHAIN_TPROXY)
	//c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "tcp", "-d", ip.String(), "-j", CHAIN_TPROXY)
	//c.ip6tbl.Append(TABLE_MANGLE, CHAIN_RED_FROG, "-p", "udp", "-d", ip.String(), "-j", CHAIN_TPROXY)
	return
}