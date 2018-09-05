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
)

type ProxyClient struct {
	backends_				[]*proxyBackend
	tcpListener				net.Listener
	udpListener				*net.UDPConn

	udpBuffer_    			*common.LeakyBuffer
	udpOOBBuffer_ 			*common.LeakyBuffer

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
	go ret.startListenTCP()



	ret.udpBuffer_ = common.NewLeakyBuffer(common.UDP_BUFFER_POOL_SIZE, common.UDP_BUFFER_SIZE)
	ret.udpOOBBuffer_ = common.NewLeakyBuffer(common.UDP_OOB_POOL_SIZE, common.UDP_OOB_BUFFER_SIZE)

	if ret.udpListener, err = network.ListenTransparentUDP(config.ListenAddr, isIPv6); err != nil{
		err = errors.Wrap(err, "UDP listen failed")
		return nil, err
	}
	go ret.startListenUDP()


	logger.Info("ProxyClient start successful", zap.String("addr", config.ListenAddr))
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
	logger.Info("TCP start listening")
	for{
		if conn, err := c.tcpListener.Accept(); err != nil{
			logger.Warn("Accept tcp conn failed", zap.String("error", err.Error()))
		}else{
			if backendProxy := c.getBackendProxy(false); backendProxy == nil{
				logger.Error("Can not get backend proxy")
				conn.Close()
			}else{
				go func(){
					if outboundSize, inboundSize, err := backendProxy.RelayTCPData(conn); err != nil{
						logger.Error("Relay TCP failed", zap.String("error", err.Error()))
					}else{
						logger.Debug("Relay TCP successful", zap.Int64("outbound", outboundSize), zap.Int64("inbound", inboundSize))
					}
				}()
			}
		}
	}
	logger.Info("TCP stop listening")
}

func (c *ProxyClient)handleUDP(buffer *bytes.Buffer, oob *bytes.Buffer, srcAddr *net.UDPAddr, dataLen int, oobLen int){
	logger := log.GetLogger()
	defer c.udpBuffer_.Put(buffer)

	if dstAddr, err := network.ExtractOrigDstFromUDP(oobLen, oob.Bytes()); err != nil{
		c.udpOOBBuffer_.Put(oob)
		logger.Error("Failed to extract original dst from udp", zap.String("error", err.Error()))
	}else{
		c.udpOOBBuffer_.Put(oob)
		if backendProxy := c.getBackendProxy(true); backendProxy == nil{
			logger.Error("Can not get backend proxy")
		}else if err = backendProxy.RelayUDPData(srcAddr, dstAddr, c.udpBuffer_, buffer, dataLen); err != nil{
			logger.Error("Relay UDP failed", zap.String("error", err.Error()))
		}
	}


}

func (c *ProxyClient)startListenUDP(){
	logger := log.GetLogger()
	logger.Info("UDP start listening")
	for{
		buffer := c.udpBuffer_.Get()
		oob := c.udpOOBBuffer_.Get()
		if dataLen, oobLen, _, srcAddr, err := c.udpListener.ReadMsgUDP(buffer.Bytes(), oob.Bytes()); err != nil{
			logger.Error("Read from udp failed", zap.String("error", err.Error()))
			// release buffer
			c.udpBuffer_.Put(buffer)
			c.udpOOBBuffer_.Put(oob)
		}else{
			go c.handleUDP(buffer, oob, srcAddr, dataLen, oobLen)
		}

	}
	logger.Info("UDP stop listening")
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
	logger.Info("ProxyClient stopped")

}