package dns_proxy

import (
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/config"
	"go.uber.org/zap"
	"github.com/weishi258/redfrog-core/routing"
	"github.com/pkg/errors"
	"github.com/miekg/dns"
	"github.com/weishi258/redfrog-core/pac"
	"strings"
	"fmt"
	"context"
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
	routingMgr 		*routing.RoutingMgr
	proxyMgr		*pac.PacListMgr
	server			*dns.Server

	localResolver 	[]*dnsResolver
	remoteResolver 	[]*dnsResolver
}


func StartDnsServer(dnsConfig config.DnsConfig, pacMgr *pac.PacListMgr, routingMgr *routing.RoutingMgr) (ret *DnsServer, err error){
	logger := log.GetLogger()

	ret = &DnsServer{}
	if routingMgr == nil{
		return nil, errors.New("Routing manager is nil")
	}
	ret.routingMgr = routingMgr

	if pacMgr == nil{
		return nil, errors.New("Pac list manager is nil")
	}
	ret.proxyMgr = pacMgr



	ret.server = &dns.Server{Addr: dnsConfig.ListenAddr, Net:"udp", Handler: ret}
	logger.Info("Dns server started",  zap.String("addr", dnsConfig.ListenAddr))
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
	if bIsRemote{
		return c.remoteResolver[0]
	}else{
		return c.localResolver[0]
	}
}

func (c *DnsServer)ServeDNS(w dns.ResponseWriter, r *dns.Msg){
	logger := log.GetLogger()
	bInProxyList := false
	for _, q := range r.Question{
		if c.proxyMgr.CheckDomain(q.Name){
			bInProxyList = true
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second * DNS_TIMEOUT)
	defer cancel()
	if bInProxyList {
		resolver := c.getResolver(true)
		if response, t, err := resolver.client.ExchangeContext(ctx, r, resolver.addr); err != nil{
			logger.Debug("Can not exchange dns query for local resolver", zap.String("addr", resolver.addr), zap.String("error", err.Error()))
		}else{
			logger.Debug("Dns query for local resolver successful", zap.String("addr", resolver.addr), zap.Duration("time", t))
			w.WriteMsg(response)
		}
	}else{
		resolver := c.getResolver(false)
		if response, t, err := resolver.client.ExchangeContext(ctx, r, resolver.addr); err != nil{
			logger.Debug("Can not exchange dns query for remote resolver", zap.String("addr", resolver.addr), zap.String("error", err.Error()))
		}else{
			logger.Debug("Dns query for remote resolver successful", zap.String("addr", resolver.addr), zap.Duration("time", t))
			w.WriteMsg(response)
		}
	}

}

