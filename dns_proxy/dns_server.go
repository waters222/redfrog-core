package dns_proxy

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/pac"
	"github.com/weishi258/redfrog-core/proxy_client"
	"github.com/weishi258/redfrog-core/routing"
	"go.uber.org/zap"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	DNS_TIMEOUT	=	5
)

type dnsResolver struct {
	addr		string
	client		*dns.Client
}

type DnsServer struct {
	routingMgr *routing.RoutingMgr
	pacMgr     *pac.PacListMgr
	server     *dns.Server

	localResolver 	[]*dnsResolver
	remoteResolver 	[]*dnsResolver

	proxyClient 	*proxy_client.ProxyClient
	dnsTimeout		time.Duration

	dnsResolverMux 		sync.RWMutex
}


func StartDnsServer(dnsConfig config.DnsConfig, pacMgr *pac.PacListMgr, routingMgr *routing.RoutingMgr, proxyClient *proxy_client.ProxyClient) (ret *DnsServer, err error){
	logger := log.GetLogger()

	ret = &DnsServer{}
	ret.proxyClient = proxyClient
	ret.dnsTimeout = time.Second * time.Duration(dnsConfig.DnsTimeout)
	if routingMgr == nil{
		return nil, errors.New("Routing manager is nil")
	}
	ret.routingMgr = routingMgr

	if pacMgr == nil{
		return nil, errors.New("Pac list manager is nil")
	}
	ret.pacMgr = pacMgr



	ret.server = &dns.Server{Addr: dnsConfig.ListenAddr, Net:"udp", Handler: ret}
	logger.Info("Dns server starting",  zap.String("addr", dnsConfig.ListenAddr))
	go func(){
		if err = ret.server.ListenAndServe(); err != nil{
			logger.Error("Dns server start failed", zap.String("error", err.Error()))
		}
	}()

	// create dns exchange client
	ret.localResolver = make([]*dnsResolver, 0)
	for _, addr := range dnsConfig.LocalResolver{
		if strings.Index(addr, ":") >= 0{
			ret.localResolver = append(ret.localResolver, &dnsResolver{addr, &dns.Client{Net: "udp"}})
		}else{
			ret.localResolver = append(ret.localResolver, &dnsResolver{fmt.Sprintf("%s:53", addr), &dns.Client{Net: "udp"}})
		}
	}

	ret.remoteResolver = make([]*dnsResolver, 0)
	for _, addr := range dnsConfig.ProxyResolver{
		if strings.Index(addr, ":") >= 0{
			ret.remoteResolver = append(ret.remoteResolver, &dnsResolver{addr, &dns.Client{Net: "udp"}})
		}else{
			ret.remoteResolver = append(ret.remoteResolver, &dnsResolver{fmt.Sprintf("%s:53", addr), &dns.Client{Net: "udp"}})
		}
	}

	return
}

func (c *DnsServer) Stop(){
	logger := log.GetLogger()

	if err := c.server.Shutdown(); err != nil{
		logger.Error("Stop DNS server failed", zap.String("error", err.Error()))
	}

	logger.Info("Dns server stopped")
}

func (c *DnsServer)getResolver(bIsRemote bool) *dnsResolver{
	c.dnsResolverMux.RLock()
	defer c.dnsResolverMux.RUnlock()
	if bIsRemote{
		length := len(c.remoteResolver)
		if length == 1{
			return c.remoteResolver[0]
		}else{
			return c.remoteResolver[rand.Int31n(int32(length))]
		}
	}else{
		length := len(c.localResolver)
		if length == 1{
			return c.localResolver[0]
		}else{
			return c.localResolver[rand.Int31n(int32(length))]
		}
	}
}

func (c *DnsServer) applyFilterChain(r *dns.Msg) *dns.Msg{
	// TODO
	// 1. Implement DNS cache filter for fast performance
	// 2. Implement DNS block filter for ads blocking etc
	return nil
}

func (c *DnsServer)ServeDNS(w dns.ResponseWriter, r *dns.Msg){
	logger := log.GetLogger()

	if resDns := c.applyFilterChain(r); resDns != nil{
		w.WriteMsg(resDns)
		return
	}

	isBlacked := false
	var domainName string
	for _, q := range r.Question{
		if c.pacMgr.CheckDomain(q.Name){
			isBlacked = true
			domainName = q.Name
			break
		}
	}

	if isBlacked {
		resolver := c.getResolver(true)
		data, err := r.Pack()
		if err != nil{
			logger.Error("Pack DNS query for proxy failed", zap.String("error", err.Error()))
			return
		}
		responseBytes, err := c.proxyClient.ExchangeDNS(w.RemoteAddr().String(), resolver.addr, data, c.dnsTimeout)
		if err != nil{
			logger.Error("DNS proxy resolve failed", zap.String("domain", domainName),zap.String("error", err.Error()))
			return
		}
		resDns := new(dns.Msg)
		if err = resDns.Unpack(responseBytes); err != nil{
			logger.Error("DNS unpack for proxy resolver failed", zap.String("error", err.Error()))
			return
		}

		for _, a := range resDns.Answer{
			if a.Header().Class == dns.ClassINET{
				if a.Header().Rrtype == dns.TypeA{
					c.routingMgr.AddIp(a.Header().Name, a.(*dns.A).A)
					logger.Debug("ipv4 ip query", zap.String("domain", a.Header().Name), zap.String("ip", a.(*dns.A).A.String()))
				}else if a.Header().Rrtype == dns.TypeAAAA{
					c.routingMgr.AddIp(a.Header().Name, a.(*dns.AAAA).AAAA)
					logger.Debug("ipv6 ip query", zap.String("domain", a.Header().Name), zap.String("ip", a.(*dns.AAAA).AAAA.String()))
				}else if a.Header().Rrtype == dns.TypeCNAME{
					cname := strings.TrimSuffix(a.(*dns.CNAME).Target, ".")
					c.pacMgr.AddDomain(cname)
					logger.Debug("Add CNAME to list", zap.String("CNAME", cname))
				}
			}
		}

		w.WriteMsg(resDns)

	}else{
		ctx, cancel := context.WithTimeout(context.Background(), time.Second * DNS_TIMEOUT)
		defer cancel()

		resolver := c.getResolver(false)
		if response, t, err := resolver.client.ExchangeContext(ctx, r, resolver.addr); err != nil{
			logger.Debug("Can not exchange dns query for local resolver", zap.String("addr", resolver.addr), zap.String("error", err.Error()))
		}else{
			logger.Debug("Dns query for local resolver successful", zap.String("addr", resolver.addr), zap.Duration("time", t))
			w.WriteMsg(response)
		}
	}

}

