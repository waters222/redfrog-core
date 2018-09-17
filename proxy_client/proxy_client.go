package proxy_client

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"go.uber.org/zap"
	"math/rand"
	"net"
	"time"
)

type ProxyClient struct {
	backends_				[]*proxyBackend
	tcpListener				net.Listener
	udpListener				*net.UDPConn

	udpBuffer_    			*common.LeakyBuffer
	udpOOBBuffer_ 			*common.LeakyBuffer
	addr					string

}

func StartProxyClient(config config.ShadowsocksConfig, listenAddr string) (*ProxyClient, error){
	logger := log.GetLogger()

	ret := &ProxyClient{}
	ret.addr = listenAddr
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

	isIPv6, err := network.CheckIPFamily(listenAddr)
	if err != nil{
		err = errors.Wrap(err, "Check addr ip family failed")
		return nil, err
	}
	if ret.tcpListener, err = network.ListenTransparentTCP(listenAddr, isIPv6); err != nil{
		err = errors.Wrap(err, "TCP listen failed")
		return nil, err
	}
	go ret.startListenTCP()



	ret.udpBuffer_ = common.NewLeakyBuffer(common.UDP_BUFFER_POOL_SIZE, common.UDP_BUFFER_SIZE)
	ret.udpOOBBuffer_ = common.NewLeakyBuffer(common.UDP_OOB_POOL_SIZE, common.UDP_OOB_BUFFER_SIZE)

	if ret.udpListener, err = network.ListenTransparentUDP(listenAddr, isIPv6); err != nil{
		ret.tcpListener.Close()
		err = errors.Wrap(err, "UDP listen failed")
		return nil, err
	}
	go ret.startListenUDP()


	logger.Info("ProxyClient start successful", zap.String("addr", listenAddr))
	return ret, nil
}

func (c *ProxyClient)getBackendProxy(isUDP bool) *proxyBackend{
	length := len(c.backends_)
	if length > 0 {
		if !isUDP{
			if length == 1{
				return c.backends_[0]
			}else{
				return c.backends_[rand.Int31n(int32(length))]
				//return c.backends_[0]
			}
		}else{
			// need to fix this, need an global nat table
			return c.backends_[0]
		}

	}
	return nil
}

func (c *ProxyClient)startListenTCP(){
	logger := log.GetLogger()
	logger.Info("TCP start listening", zap.String("addr", c.addr))
	for{
		if conn, err := c.tcpListener.Accept(); err != nil{
			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection"{
				logger.Debug("Accept tcp conn failed", zap.String("error", err.Error()))
			}
		}else{
			go c.handleTCP(conn)
		}
	}
	logger.Info("TCP stop listening", zap.String("addr", c.addr))
}

func (c *ProxyClient)handleTCP(conn net.Conn){
	logger := log.GetLogger()

	defer conn.Close()

	if backendProxy := c.getBackendProxy(false); backendProxy == nil{
		logger.Error("Can not get backend proxy")
	}else{

		if outboundSize, inboundSize, err := backendProxy.RelayTCPData(conn); err != nil{
			if ee, ok := err.(net.Error); ok && ee.Timeout(){
				// do nothing for timeout
			}else{
				logger.Error("Relay TCP failed", zap.String("error", err.Error()))
			}
		}else{
			logger.Debug("Relay TCP successful", zap.Int64("outbound", outboundSize), zap.Int64("inbound", inboundSize))
		}
	}
}



func (c *ProxyClient)startListenUDP(){
	logger := log.GetLogger()
	logger.Info("UDP start listening", zap.String("addr", c.addr))
	for{
		buffer := c.udpBuffer_.Get()
		oob := c.udpOOBBuffer_.Get()
		if dataLen, oobLen, _, srcAddr, err := c.udpListener.ReadMsgUDP(buffer.Bytes(), oob.Bytes()); err != nil{
			c.udpBuffer_.Put(buffer)
			c.udpOOBBuffer_.Put(oob)

			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection"{
				logger.Debug("Read from udp failed", zap.String("error", err.Error()))
			}
		}else{

			if dstAddr, err := network.ExtractOrigDstFromUDP(oobLen, oob.Bytes()); err != nil{
				logger.Error("Failed to extract original dst from udp", zap.String("error", err.Error()))
			}else{
				go c.handleUDP(buffer, srcAddr, dstAddr, dataLen)
			}
			c.udpOOBBuffer_.Put(oob)
		}

	}
	logger.Info("UDP stop listening", zap.String("addr", c.addr))
}
func (c *ProxyClient)handleUDP(buffer *bytes.Buffer, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, dataLen int){
	logger := log.GetLogger()
	defer c.udpBuffer_.Put(buffer)

	if backendProxy := c.getBackendProxy(true); backendProxy == nil{
		logger.Error("Can not get backend proxy")
	}else if err := backendProxy.RelayUDPData(srcAddr, dstAddr, c.udpBuffer_, buffer, dataLen); err != nil {
		logger.Error("Relay UDP failed", zap.String("error", err.Error()))
	}


}
func (c * ProxyClient)ExchangeDNS(srcAddr string, dstAddr string, data []byte, dnsTimeout time.Duration) (response []byte, err error) {
	if backendProxy := c.getBackendProxy(true); backendProxy == nil{
		err = errors.New("Can not get backend proxy")
	}else if response, err = backendProxy.RelayDNS(srcAddr, dstAddr, data, c.udpBuffer_, dnsTimeout); err != nil {
		err = errors.Wrap(err, "Relay DNS query from proxy failed")
	}
	return
}

func (c *ProxyClient)Stop(){
	logger := log.GetLogger()
	if err := c.tcpListener.Close(); err != nil{
		logger.Error("Close TCP listener failed", zap.String("error", err.Error()))
	}
	if err := c.udpListener.Close(); err != nil{
		logger.Error("Close UDP listener failed", zap.String("error", err.Error()))
	}
	for _, backend := range c.backends_{
		backend.Stop()
	}
	logger.Info("ProxyClient stopped")

}