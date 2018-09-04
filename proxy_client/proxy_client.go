package proxy_client

import (
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"go.uber.org/zap"
	"net"
)

type ProxyClient struct {
	backends_				[]*proxyBackend
	tcpListener				net.Listener
	udpListener				*net.UDPConn

}

func StartProxyClient(config config.ShadowsocksConfig) (*ProxyClient, error){
	logger := log.GetLogger()

	ret := &ProxyClient{}
	ret.backends_ = make([]*proxyBackend, 0)
	for _, backendConfig := range config.Servers{
		if backend, err := CreateProxyBackend(backendConfig, config.TcpTimeout, config.UdpTimeout); err != nil{
			err = errors.Wrap(err, "Create proxy backend failed")
			return nil, err
		}else{
			logger.Info("Proxy backend create successful", zap.String("addr", backendConfig.RemoteServer))
			ret.backends_ = append(ret.backends_, backend)
		}
	}

	isIPv6, err := network.CheckIPFamily(config.ListenAddr)
	if err != nil{
		err = errors.Wrap(err, "Check addr ip family failed")
		return nil, err
	}
	if ret.tcpListener, err = network.ListenTransparentTCP(config.ListenAddr, isIPv6); err != nil{
		err = errors.Wrap(err, "TCP listen failed")
		return nil, err
	}

	if ret.udpListener, err = network.ListenTransparentUDP(config.ListenAddr, isIPv6); err != nil{
		err = errors.Wrap(err, "UDP listen failed")
		return nil, err
	}

	logger.Info("ProxyClient start successful", zap.String("addr", config.ListenAddr))
	return ret, nil
}


func (c *ProxyClient)Stop(){
	logger := log.GetLogger()
	if err := c.tcpListener.Close(); err != nil{
		logger.Error("Close TCP listener failed", zap.String("error", err.Error()))
	}
	if err := c.udpListener.Close(); err != nil{
		logger.Error("Close UDP listener failed", zap.String("error", err.Error()))
	}
	c.backends_ = nil

}