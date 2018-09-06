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
	"net"
	"strings"
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
	if bIsRemote{
		return c.remoteResolver[0]
	}else{
		return c.localResolver[0]
	}
}

func (c *DnsServer)ServeDNS(w dns.ResponseWriter, r *dns.Msg){
	logger := log.GetLogger()
	var domainName string
	for _, q := range r.Question{
		if c.pacMgr.CheckDomain(q.Name){
			domainName = q.Name
			break
		}
	}

	if len(domainName) != 0 {
		resolver := c.getResolver(true)
		data, err := r.Pack()
		if err != nil{
			logger.Error("Pack DNS query failed", zap.String("error", err.Error()))
			return
		}
		responseBytes, err := c.proxyClient.ExchangeDNS(w.RemoteAddr().String(), resolver.addr, data, c.dnsTimeout)
		if err != nil{
			logger.Error("DNS remote resolve failed", zap.String("error", err.Error()))
			return
		}
		resDns := new(dns.Msg)
		if err = resDns.Unpack(responseBytes); err != nil{
			logger.Error("DNS unpack failed", zap.String("error", err.Error()))
			return
		}
		ips := make([]net.IP, 0)
		for _, a := range resDns.Answer{
			if a.Header().Class == dns.ClassINET{
				if a.Header().Rrtype == dns.TypeA{
					if a.Header().Name == domainName {
						ips = append(ips, a.(*dns.A).A)
						logger.Debug("ipv4 ip query", zap.String("domain", domainName), zap.String("ip", a.(*dns.A).A.String()))
					}
				}else if a.Header().Rrtype == dns.TypeAAAA{
					if a.Header().Name == domainName {
						ips = append(ips, a.(*dns.AAAA).AAAA)
						logger.Debug("ipv6 ip query", zap.String("domain", domainName), zap.String("ip", a.(*dns.AAAA).AAAA.String()))
					}
				}else if a.Header().Rrtype == dns.TypeCNAME{
					if a.Header().Name == domainName{
						cname := strings.TrimSuffix(a.(*dns.CNAME).Target, ".")
						c.pacMgr.AddDomain(cname)
						logger.Debug("Add CNAME to list", zap.String("CNAME", cname))

					}
				}
			}
		}
		// lets put it into iptables
		for _, ip := range ips{
			c.routingMgr.AddIp(domainName, ip)
		}

		w.WriteMsg(resDns)

	}else{
		ctx, cancel := context.WithTimeout(context.Background(), time.Second * DNS_TIMEOUT)
		defer cancel()

		resolver := c.getResolver(false)
		if response, t, err := resolver.client.ExchangeContext(ctx, r, resolver.addr); err != nil{
			logger.Debug("Can not exchange dns query for remote resolver", zap.String("addr", resolver.addr), zap.String("error", err.Error()))
		}else{
			logger.Debug("Dns query for remote resolver successful", zap.String("addr", resolver.addr), zap.Duration("time", t))
			w.WriteMsg(response)
		}
	}

}

