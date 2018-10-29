package dns_proxy

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/pac"
	"github.com/weishi258/redfrog-core/routing"
	"go.uber.org/zap"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type dnsResolver struct {
	addr   string
	client *dns.Client
}

type DnsServer struct {
	routingMgr *routing.RoutingMgr
	pacMgr     *pac.PacListMgr
	server     *dns.Server

	localResolver  []*dnsResolver
	remoteResolver []*dnsResolver

	proxyClient common.ProxyClientInterface

	dnsResolverMux sync.RWMutex

	sendNum     int32
	dnsCaches   *dnsCache
	dnsCacheMux sync.RWMutex

	timeout time.Duration

	filter       *dnsFilter
	dnsFilterMux sync.RWMutex
}

type dnsCacheEntry struct {
	response *dns.Msg
	halfTtl  time.Time
	ttl      time.Time
}

type dnsCache struct {
	sync.RWMutex
	caches map[string]*dnsCacheEntry
}

func (c *DnsServer) AddDnsCache(domain string, response *dns.Msg, ttl uint32) {
	c.dnsCacheMux.RLock()
	cache := c.dnsCaches
	c.dnsCacheMux.RUnlock()

	if cache != nil {
		cache.Lock()
		defer cache.Unlock()
		cache.caches[domain] = &dnsCacheEntry{response: response, halfTtl: time.Now().Add(time.Duration(ttl>>1) * time.Second), ttl: time.Now().Add(time.Duration(ttl) * time.Second)}
	}
}

func (c *dnsCache) get(domain string) *dnsCacheEntry {
	c.RLock()
	defer c.RUnlock()
	if res, ok := c.caches[domain]; ok {
		return res
	} else {
		return nil
	}
}
func (c *dnsCache) del(domain string) {
	c.Lock()
	defer c.Unlock()
	delete(c.caches, domain)
}

func (c *dnsCache) GetDnsCache(domain string) (*dns.Msg, bool) {
	if entry := c.get(domain); entry != nil {
		log.GetLogger().Debug("Get cache hit", zap.String("domain", domain))
		now := time.Now()
		if now.Before(entry.ttl) {
			// we used halfTtl as an test to determine if we need to refresh the cache
			// it the current time + timeout > current time we will need to refresh cache even we hit cache to minimize dns lost
			return entry.response, now.After(entry.halfTtl)
		} else {
			c.del(domain)
		}
	}

	return nil, false
}

func StartDnsServer(dnsConfig config.DnsConfig, pacMgr *pac.PacListMgr, routingMgr *routing.RoutingMgr, proxyClient common.ProxyClientInterface) (ret *DnsServer, err error) {
	logger := log.GetLogger()

	ret = &DnsServer{}
	ret.proxyClient = proxyClient
	if routingMgr == nil {
		return nil, errors.New("Routing manager is nil")
	}
	ret.routingMgr = routingMgr

	if pacMgr == nil {
		return nil, errors.New("Pac list manager is nil")
	}
	ret.pacMgr = pacMgr

	ret.server = &dns.Server{Addr: dnsConfig.ListenAddr, Net: "udp", Handler: ret}
	logger.Info("Dns server starting", zap.String("addr", dnsConfig.ListenAddr))
	go func() {
		if err = ret.server.ListenAndServe(); err != nil {
			logger.Error("Dns server start failed", zap.String("error", err.Error()))
		}
	}()

	// create dns exchange client
	ret.localResolver = make([]*dnsResolver, 0)
	for _, addr := range dnsConfig.LocalResolver {
		var resolver *dnsResolver
		if strings.Index(addr, ":") >= 0 {
			resolver = &dnsResolver{addr, &dns.Client{Net: "udp"}}
		} else {
			resolver = &dnsResolver{fmt.Sprintf("%s:53", addr), &dns.Client{Net: "udp"}}
		}
		ret.localResolver = append(ret.localResolver, resolver)
		logger.Debug("DNS local resolver", zap.String("addr", resolver.addr))
	}

	ret.remoteResolver = make([]*dnsResolver, 0)
	for _, addr := range dnsConfig.ProxyResolver {
		var resolver *dnsResolver
		if strings.Index(addr, ":") >= 0 {
			resolver = &dnsResolver{addr, &dns.Client{Net: "udp"}}
		} else {
			resolver = &dnsResolver{fmt.Sprintf("%s:53", addr), &dns.Client{Net: "udp"}}
		}
		ret.remoteResolver = append(ret.remoteResolver, resolver)
		logger.Debug("DNS proxy resolver", zap.String("addr", resolver.addr))
	}

	if dnsConfig.Cache {
		logger.Info("Enable DNS cache")
		ret.dnsCaches = &dnsCache{caches: make(map[string]*dnsCacheEntry)}
	}
	ret.sendNum = int32(dnsConfig.SendNum)
	if ret.sendNum < 1 {
		ret.sendNum = 1
	}
	ret.timeout = time.Duration(dnsConfig.Timeout) * time.Second

	// lets deal with dns filter
	if dnsConfig.FilterConfig.Enable {
		if ret.filter, err = LoadFilter(dnsConfig.FilterConfig.BlackLists, dnsConfig.FilterConfig.WhiteLists); err != nil {
			logger.Error("Start DNS filter failed", zap.String("error", err.Error()))
		} else {
			logger.Info("Start DNS filter successful")
		}
	}
	//logger.Info("Set DNS send number", zap.Int("num", dnsConfig.SendNum))
	//aa := ret.(proxy_client.DNSServerInterface)
	ret.proxyClient.SetDNSProcessor(ret)
	return
}
func (c *DnsServer) Reload(dnsConfig config.DnsConfig) {
	logger := log.GetLogger()

	// reload resolver

	localResolver := make([]*dnsResolver, 0)
	for _, addr := range dnsConfig.LocalResolver {
		var resolver *dnsResolver
		if strings.Index(addr, ":") >= 0 {
			resolver = &dnsResolver{addr, &dns.Client{Net: "udp"}}
		} else {
			resolver = &dnsResolver{fmt.Sprintf("%s:53", addr), &dns.Client{Net: "udp"}}
		}
		localResolver = append(localResolver, resolver)
		logger.Info("DNS local resolver", zap.String("addr", resolver.addr))
	}

	remoteResolver := make([]*dnsResolver, 0)
	for _, addr := range dnsConfig.ProxyResolver {
		var resolver *dnsResolver
		if strings.Index(addr, ":") >= 0 {
			resolver = &dnsResolver{addr, &dns.Client{Net: "udp"}}
		} else {
			resolver = &dnsResolver{fmt.Sprintf("%s:53", addr), &dns.Client{Net: "udp"}}
		}
		remoteResolver = append(remoteResolver, resolver)
		logger.Info("DNS proxy resolver", zap.String("addr", resolver.addr))
	}
	c.dnsResolverMux.Lock()
	defer c.dnsResolverMux.Unlock()
	c.localResolver = localResolver
	c.remoteResolver = remoteResolver

	// reload DNS cache
	c.dnsCacheMux.Lock()

	if dnsConfig.Cache {
		if c.dnsCaches == nil {
			logger.Info("Enable DNS cache")
			c.dnsCaches = &dnsCache{caches: make(map[string]*dnsCacheEntry)}
		}
	} else {
		if c.dnsCaches != nil {
			c.dnsCaches = nil
			logger.Info("Disable DNS cache")
		}

	}
	c.dnsCacheMux.Unlock()

	c.dnsFilterMux.Lock()

	if dnsConfig.FilterConfig.Enable {
		if filter, err := LoadFilter(dnsConfig.FilterConfig.BlackLists, dnsConfig.FilterConfig.WhiteLists); err != nil {
			logger.Error("Load DNS filter list failed", zap.String("error", err.Error()))
		} else {
			c.filter = filter
			logger.Info("Reload DNS filter list successful")
		}
	} else {
		c.filter = nil
		logger.Info("Disable DNS filter")
	}

	c.dnsFilterMux.Unlock()

	// reload Send Num
	//sendNum := dnsConfig.SendNum
	//if sendNum < 1{
	//	sendNum = 1
	//}
	//atomic.StoreInt32(&c.sendNum, int32(sendNum))
	////logger.Info("Set DNS send number", zap.Int("num", sendNum))

	logger.Info("Reload DNS config successful")
}

func (c *DnsServer) Stop() {
	logger := log.GetLogger()

	c.proxyClient = nil
	c.routingMgr = nil
	c.pacMgr = nil
	if err := c.server.Shutdown(); err != nil {
		logger.Error("Stop DNS server failed", zap.String("error", err.Error()))
	}

	logger.Info("Dns server stopped")
}

func (c *DnsServer) getResolver(bIsRemote bool) *dnsResolver {
	c.dnsResolverMux.RLock()
	defer c.dnsResolverMux.RUnlock()
	if bIsRemote {
		length := len(c.remoteResolver)
		if length == 0 {
			return nil
		} else if length == 1 {
			return c.remoteResolver[0]
		} else {
			return c.remoteResolver[rand.Int31n(int32(length))]
		}
	} else {
		length := len(c.localResolver)
		if length == 0 {
			return nil
		} else if length == 1 {
			return c.localResolver[0]
		} else {
			return c.localResolver[rand.Int31n(int32(length))]
		}
	}
}

func (c *DnsServer) applyFilterChain(r *dns.Msg) bool {
	// TODO
	// 1. Implement DNS cache filter for fast performance
	// 2. Implement DNS block filter for ads blocking etc

	c.dnsFilterMux.RLock()
	filter := c.filter
	c.dnsFilterMux.RUnlock()

	if filter != nil {
		for _, q := range r.Question {
			if q.Qclass == dns.ClassINET {
				domain := strings.TrimSuffix(q.Name, ".")
				action := filter.CheckDomain(domain)
				if action == FILTER_ACTION_PASS {
					//log.GetLogger().Debug("Domain filter is white", zap.String("domain", domain))
					return false
				} else if action == FILTER_ACTION_BLOCK {
					//log.GetLogger().Debug("Domain filter is black", zap.String("domain", domain))
					return true
				}
			}
		}

	}

	return false
}

func (c *DnsServer) checkCache(r *dns.Msg) (*dns.Msg, bool) {
	c.dnsCacheMux.RLock()
	dnsCache := c.dnsCaches
	c.dnsCacheMux.RUnlock()
	if dnsCache != nil {
		for _, q := range r.Question {
			if q.Qclass == dns.ClassINET {
				domain := strings.TrimSuffix(q.Name, ".")
				if resDns, needRefreshCache := dnsCache.GetDnsCache(domain); resDns != nil {
					return resDns, needRefreshCache
				}
			}
		}
	}
	return nil, false
}

func (c *DnsServer) resolveProxyDNS(r *dns.Msg, domainName string, isBlock bool) (resDns *dns.Msg, err error) {
	logger := log.GetLogger()
	if resolver := c.getResolver(true); resolver != nil {
		var data []byte
		if data, err = r.Pack(); err != nil {
			err = errors.Wrap(err, "Pack DNS query for proxy failed")
			return
		}

		if resDns, err = c.proxyClient.ExchangeDNS(resolver.addr, data, c.timeout); err != nil {
			err = errors.Wrapf(err, "DNS proxy resolve failed, domain %s", domainName)
			return
		}
		// if its blocked then we dont deal with it with normal procedure
		if !isBlock {
			hasIPv4 := false
			var ttl uint32
			for _, a := range resDns.Answer {
				if a.Header().Class == dns.ClassINET {
					if a.Header().Ttl > ttl {
						ttl = a.Header().Ttl
					}
					if a.Header().Rrtype == dns.TypeA {
						hasIPv4 = true
						name := strings.TrimSuffix(a.Header().Name, ".")
						c.routingMgr.AddIp(name, a.(*dns.A).A)
						logger.Debug("ipv4 ip query", zap.String("domain", name), zap.String("ip", a.(*dns.A).A.String()), zap.Uint32("ttl", ttl))

						// ipv6 is not fully support yet, so ignore now
					} else if a.Header().Rrtype == dns.TypeAAAA {

							//shouldAddCache = true
							name := strings.TrimSuffix(a.Header().Name, ".")
							c.routingMgr.AddIp(name, a.(*dns.AAAA).AAAA)
							logger.Debug("ipv6 ip query", zap.String("domain", name), zap.String("ip", a.(*dns.AAAA).AAAA.String()), zap.Uint32("ttl", ttl))
					} else if a.Header().Rrtype == dns.TypeCNAME {
						cname := strings.TrimSuffix(a.(*dns.CNAME).Target, ".")
						c.pacMgr.AddDomain(cname, common.DOMAIN_BLACK_LIST)
						logger.Debug("Add CNAME to list", zap.String("CNAME", cname))
					}

				}
			}
			if hasIPv4 {
				c.AddDnsCache(domainName, resDns, ttl)
			}
		}
	} else {
		err = errors.New("can not get proxy dns resolver")
	}
	return
}

func (c *DnsServer) resolveLocalDNS(r *dns.Msg) (*dns.Msg, error) {
	if resolver := c.getResolver(false); resolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		if response, _, err := resolver.client.ExchangeContext(ctx, r, resolver.addr); err != nil{
			if len(r.Question) > 0 {
				return nil, errors.Wrapf(err, "Dns query for local resolver failed, domain: %s", r.Question[0].String())
			} else {
				return nil, errors.Wrap(err, "Dns query for local resolver failed")
			}
		}else{
			return response, nil
		}
	} else {
		return nil, errors.New("can not get local dns resolver")
	}
}

func (c *DnsServer) writeResponse(w dns.ResponseWriter, r *dns.Msg, resDns *dns.Msg, isBlocked bool) ([]byte, error) {
	if isBlocked {
		// well we need to block it, so replace all ip address to 0.0.0.0
		for i := 0; i < len(resDns.Answer); i++ {
			if resDns.Answer[i].Header().Class == dns.ClassINET {
				rType := resDns.Answer[i].Header().Rrtype
				if rType == dns.TypeA {
					resDns.Answer[i].(*dns.A).A = net.IPv4zero
				} else if rType == dns.TypeAAAA {
					resDns.Answer[i].(*dns.AAAA).AAAA = net.IPv6zero
				} else if rType == dns.TypeCNAME {
					resDns.Answer[i].(*dns.CNAME).Target = ""
				} else if rType == dns.TypeSOA {
					resDns.Answer[i].(*dns.SOA).Ns = ""
					resDns.Answer[i].(*dns.SOA).Mbox = ""
				}
			}
		}
	}
	// replace id with request so avoid mis-match
	resDns.Id = r.Id
	// we need to pack the response since its from gateway filter
	if w == nil {
		if data, err := resDns.Pack(); err != nil {
			//log.GetLogger().Warn("Pack DNS response failed", zap.String("error", err.Error()))
			return nil, errors.Wrap(err, "Pack DNS response failed")
		} else {
			return data, nil
		}
	}
	// well its from standard gateway
	return nil, w.WriteMsg(resDns)
}

func (c *DnsServer) ServerDNSPacket(msg *dns.Msg) ([]byte, error) {
	//r := new(dns.Msg)
	//if err := r.Unpack(data); err != nil{
	//	return nil, errors.Wrapf(err, "unpack DNS packet failed")
	//}
	return c.processDNSRequest(nil, msg)
}

func (c *DnsServer) processDNSRequest(w dns.ResponseWriter, r *dns.Msg) ([]byte, error) {
	isBlocked := c.applyFilterChain(r)
	log.GetLogger().Debug("Domain filter status", zap.Bool("block", isBlocked))
	for _, q := range r.Question {
		domainName := strings.TrimSuffix(q.Name, ".")
		// if its black then do proxy resolve
		if c.pacMgr.CheckDomain(domainName) {
			if resDns, bRefreshCache := c.checkCache(r); resDns != nil {
				if bRefreshCache {
					go c.resolveProxyDNS(r, domainName, isBlocked)
				}
				return c.writeResponse(w, r, resDns, isBlocked)
			}
			if resDns, err := c.resolveProxyDNS(r, domainName, isBlocked); err == nil {
				return c.writeResponse(w, r, resDns, isBlocked)
			} else {
				return nil, err
			}
		}
	}

	if resDns, err := c.resolveLocalDNS(r); err == nil {
		return c.writeResponse(w, r, resDns, isBlocked)
	} else {
		return nil, err
	}
}

func (c *DnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if _, err := c.processDNSRequest(w, r); err != nil{
		log.GetLogger().Error("Server local DNS failed", zap.String("error", err.Error()))
	}
}
