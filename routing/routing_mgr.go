package routing

import (
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"net"
	"sync"
)

type RoutingMgr struct{
	mux				sync.RWMutex
	ipListV4		map[string][]net.IP
	ipListV6		map[string][]net.IP
}


func StartRoutingMgr() (ret *RoutingMgr, err error){
	logger := log.GetLogger()
	ret = &RoutingMgr{}
	ret.ipListV4 = make(map[string][]net.IP)
	ret.ipListV6 = make(map[string][]net.IP)
	logger.Info("Init routing manager successful")
	return
}

func (c *RoutingMgr) Stop(){
	logger := log.GetLogger()
	logger.Info("Stop routing manager")
	// something restore ip tables
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
	return
}
func (c *RoutingMgr)routingTableAddIPV6(ip net.IP) (err error){
	logger := log.GetLogger()
	logger.Debug("routing table add ipv6", zap.String("ip", ip.String()))
	return
}