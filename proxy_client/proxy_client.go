package proxy_client

import (
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

//const(
//	DNS_ADDR_MOCK_TIMEOUT = 60
//)

//type DnsSyncResolver struct {
//	dnsIdQueue     chan uint16
//	dnsQueryMap    map[uint16]chan<- *dns.Msg
//	dnsQueryMapMux sync.RWMutex
//}

type ProxyClient struct {
	backends_  []*proxyBackend
	backendMux sync.RWMutex

	tcpListener net.Listener
	udpListener *net.UDPConn

	udpBuffer_    *common.LeakyBuffer
	udpOOBBuffer_ *common.LeakyBuffer
	addr          string

	udpBackend_ *udpBackend
	udpNatMap_  *udpNatMap

	dnsServer      common.DNSServerInterface
	dnsMockTimeout int

	dnsSyncResolver common.DnsSyncResolver
}

// udp relay
type relayDataRes struct {
	outboundSize int64
	Err          error
}

type udpProxyEntry struct {
	sync.Mutex
	dstUdp_   net.PacketConn
	dstTcp_   net.Conn
	dstKcp_   *smux.Stream
	header_   []byte
	proxyAddr *net.UDPAddr
	timeout   time.Duration
}

func createProxyEntry(isUDPOverTcp bool, dstP net.PacketConn, dstT net.Conn, dstK *smux.Stream, dstAddr *net.UDPAddr, proxyAddr *net.UDPAddr, timeout time.Duration) (*udpProxyEntry, error) {
	addr, err := network.ConvertShadowSocksAddr(dstAddr.String(), isUDPOverTcp)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(addr))
	copy(buf, addr)
	return &udpProxyEntry{dstUdp_: dstP, dstTcp_: dstT, dstKcp_: dstK, header_: buf, proxyAddr: proxyAddr, timeout: timeout}, nil
}

func createUDPProxyEntry(dst net.PacketConn, dstAddr *net.UDPAddr, proxyAddr *net.UDPAddr, timeout time.Duration) (*udpProxyEntry, error) {
	return createProxyEntry(false, dst, nil, nil, dstAddr, proxyAddr, timeout)
}

func createUDPOverTCPProxyEntry(dst net.Conn, dstAddr *net.UDPAddr, proxyAddr *net.UDPAddr, timeout time.Duration) (*udpProxyEntry, error) {
	return createProxyEntry(true, nil, dst, nil, dstAddr, proxyAddr, timeout)
}

func createUDPOverKCPProxyEntry(dst *smux.Stream, dstAddr *net.UDPAddr, proxyAddr *net.UDPAddr, timeout time.Duration) (*udpProxyEntry, error) {
	return createProxyEntry(true, nil, nil, dst, dstAddr, proxyAddr, timeout)
}

type udpNatMap struct {
	sync.RWMutex
	entries map[string]*udpProxyEntry
}

func (c *udpNatMap) Add(key string, entry *udpProxyEntry) {
	c.entries[key] = entry
}
func (c *udpNatMap) Del(key string) {
	delete(c.entries, key)
}
func (c *udpNatMap) Get(key string) *udpProxyEntry {
	if entry, ok := c.entries[key]; ok {
		return entry
	} else {
		return nil
	}
}

func StartProxyClient(dnsMockTimeout int, config config.ShadowsocksConfig, listenAddr string) (*ProxyClient, error) {
	logger := log.GetLogger()

	ret := &ProxyClient{}
	ret.addr = listenAddr

	if err := ret.StartBackend(config); err != nil {
		return nil, err
	}

	isIPv6, err := network.CheckIPFamily(listenAddr)
	if err != nil {
		err = errors.Wrap(err, "Check addr ip family failed")
		return nil, err
	}
	if ret.tcpListener, err = network.ListenTransparentTCP(listenAddr, isIPv6); err != nil {
		err = errors.Wrap(err, "TCP listen failed")
		return nil, err
	}
	go ret.startListenTCP()

	ret.udpBuffer_ = common.NewLeakyBuffer(common.UDP_BUFFER_POOL_SIZE, common.UDP_BUFFER_SIZE)
	ret.udpOOBBuffer_ = common.NewLeakyBuffer(common.UDP_OOB_POOL_SIZE, common.UDP_OOB_BUFFER_SIZE)

	if ret.udpListener, err = network.ListenTransparentUDP(listenAddr, isIPv6); err != nil {
		ret.tcpListener.Close()
		err = errors.Wrap(err, "UDP listen failed")
		return nil, err
	}
	ret.udpBackend_ = NewUDPBackend()
	ret.dnsMockTimeout = dnsMockTimeout
	ret.udpNatMap_ = &udpNatMap{entries: make(map[string]*udpProxyEntry)}

	// for dns proxy
	//ret.dnsSyncResolver.dnsQueryMap = make(map[uint16]chan<- *dns.Msg)
	//ret.dnsSyncResolver.dnsIdQueue = make(chan uint16, math.MaxUint16)
	//for i := 1; i < math.MaxUint16; i++ {
	//	ret.dnsSyncResolver.dnsIdQueue <- uint16(i)
	//}
	ret.dnsSyncResolver.Start()

	go ret.startListenUDP()

	logger.Info("ProxyClient start successful", zap.String("addr", listenAddr))
	return ret, nil
}

func (c *ProxyClient) StartBackend(serverConfig config.ShadowsocksConfig) (err error) {
	logger := log.GetLogger()
	c.backendMux.Lock()
	defer c.backendMux.Unlock()

	c.backends_ = make([]*proxyBackend, 0)

	for _, backendConfig := range serverConfig.Servers {
		if backendConfig.Enable {
			var backend *proxyBackend
			if backend, err = CreateProxyBackend(backendConfig); err != nil {
				logger.Error("Proxy backend create failed", zap.String("addr", backendConfig.RemoteServer))
				err = errors.Wrap(err, "Create proxy backend failed")
				return
			} else {
				c.backends_ = append(c.backends_, backend)
				logger.Info("Proxy backend create successful", zap.String("addr", backendConfig.RemoteServer))
			}
		}
	}

	if len(c.backends_) == 0 {
		err = errors.New("No backend created !!!")
	}
	return
}

func (c *ProxyClient) ReloadBackend(dnsMockTimeout int, serverConfig config.ShadowsocksConfig) (err error) {
	logger := log.GetLogger()
	newBackends := make([]*proxyBackend, 0)

	c.backendMux.Lock()
	defer c.backendMux.Unlock()
	c.dnsMockTimeout = dnsMockTimeout
	for _, backend := range c.backends_ {
		shouldClosed := true
		for _, backendConfig := range serverConfig.Servers {
			if backend.remoteServerConfig.RemoteServer == backendConfig.RemoteServer {
				// we have a match
				if backend.remoteServerConfig.Equal(&backendConfig) {
					logger.Debug("Should not close backend", zap.String("server", backendConfig.RemoteServer))
					shouldClosed = false
				}
				break
			}
		}
		if shouldClosed {
			logger.Debug("Closing backend", zap.String("server", backend.remoteServerConfig.RemoteServer))
			backend.Stop()
		} else {
			newBackends = append(newBackends, backend)
		}
	}

	for _, backendConfig := range serverConfig.Servers {
		if backendConfig.Enable {
			shouldStart := true
			for _, backend := range newBackends {
				if backendConfig.RemoteServer == backend.remoteServerConfig.RemoteServer {
					shouldStart = false
					break
				}
			}
			if shouldStart {
				if backend, err := CreateProxyBackend(backendConfig); err != nil {
					logger.Error("Proxy backend create failed", zap.String("addr", backendConfig.RemoteServer))
				} else {
					newBackends = append(newBackends, backend)
					logger.Info("Proxy backend create successful", zap.String("addr", backendConfig.RemoteServer))
				}
			}
		}

	}

	c.backends_ = newBackends

	if len(c.backends_) == 0 {
		err = errors.New("No backend created !!!")
	}
	return
}

func (c *ProxyClient) getBackendProxy() *proxyBackend {
	c.backendMux.RLock()
	defer c.backendMux.RUnlock()
	length := len(c.backends_)
	if length == 1 {
		return c.backends_[0]
	} else {
		return c.backends_[rand.Int31n(int32(length))]
	}
	return nil
}

func (c *ProxyClient) getBackendProxyByAddr(addr string) *proxyBackend {
	c.backendMux.RLock()
	defer c.backendMux.RUnlock()
	for _, backend := range c.backends_ {
		if backend.udpAddr.String() == addr {
			return backend
		}
	}
	return nil
}

func (c *ProxyClient) startListenTCP() {
	logger := log.GetLogger()
	logger.Info("TCP start listening", zap.String("addr", c.addr))
	for {
		if conn, err := c.tcpListener.Accept(); err != nil {
			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection" {
				logger.Debug("Accept tcp conn failed", zap.String("error", err.Error()))
			}
		} else {
			go c.handleTCP(conn)
		}
	}
	logger.Info("TCP stop listening", zap.String("addr", c.addr))
}

func (c *ProxyClient) handleTCP(conn net.Conn) {
	logger := log.GetLogger()

	defer conn.Close()

	if backendProxy := c.getBackendProxy(); backendProxy == nil {
		logger.Error("Can not get backend proxy")
	} else {

		if outboundSize, inboundSize, err := backendProxy.RelayTCPData(conn); err != nil {
			if ee, ok := err.(net.Error); ok && ee.Timeout() {
				// do nothing for timeout
			} else {
				logger.Error("Relay TCP failed", zap.String("error", err.Error()))
			}
		} else {
			logger.Debug("Relay TCP successful", zap.Int64("outbound", outboundSize), zap.Int64("inbound", inboundSize))
		}
	}
}

func (c *ProxyClient) startListenUDP() {
	logger := log.GetLogger()
	logger.Info("UDP start listening", zap.String("addr", c.addr))
	for {
		buffer := c.udpBuffer_.Get()
		oob := c.udpOOBBuffer_.Get()
		//logger.Debug("start intercept udp")
		if dataLen, oobLen, _, srcAddr, err := c.udpListener.ReadMsgUDP(buffer, oob); err != nil {
			c.udpBuffer_.Put(buffer)
			c.udpOOBBuffer_.Put(oob)

			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection" {
				logger.Debug("Read from udp failed", zap.String("error", err.Error()))
			}
		} else {
			//logger.Debug("got one udp")
			if dstAddr, err := network.ExtractOrigDstFromUDP(oobLen, oob); err != nil {
				logger.Error("Failed to extract original dst from udp", zap.String("error", err.Error()))
			} else {
				go c.HandleUDP(buffer, srcAddr, dstAddr, dataLen)

			}
			c.udpOOBBuffer_.Put(oob)
		}

	}
	logger.Info("UDP stop listening", zap.String("addr", c.addr))
}

func (c *ProxyClient) GetUDPBuffer() []byte {
	return c.udpBuffer_.Get()
}
func (c *ProxyClient) PutUDPBuffer(buffer []byte) {
	c.udpBuffer_.Put(buffer)
}

func (c *ProxyClient) HandleUDP(buffer []byte, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, dataLen int) {
	logger := log.GetLogger()
	defer c.udpBuffer_.Put(buffer)
	//logger.Debug("HandleUDP", zap.String("src", srcAddr.String()), zap.String("dst", dstAddr.String()))
	if dstAddr.Port == 53 {
		msg := new(dns.Msg)
		if err := msg.Unpack(buffer[:dataLen]); err != nil {
			if len(msg.Question) > 0 {
				logger.Info("unpack DNS packet failed",
					zap.String("src", srcAddr.String()),
					zap.String("DNS server", dstAddr.String()),
					zap.String("domain", msg.Question[0].Name),
					zap.Int("udp size", dataLen), zap.String("error", err.Error()))
			} else {
				logger.Info("unpack DNS packet failed",
					zap.String("src", srcAddr.String()),
					zap.String("DNS server", dstAddr.String()),
					zap.Int("udp size", dataLen), zap.String("error", err.Error()))
			}
			x := new(dns.Msg)
			x.SetRcodeFormatError(msg)
			if responseByte, _ := x.Pack(); len(responseByte) > 0 {
				c.udpBackend_.WriteBackUDPPayload(c, srcAddr, dstAddr, responseByte, time.Duration(c.dnsMockTimeout)*time.Second)
			}
			return
		}
		if err := c.relayDNS(srcAddr, dstAddr, msg); err != nil {
			logger.Info("Relay DNS failed", zap.String("error", err.Error()))
			return
		}
		logger.Debug("Relay DNS successful", zap.String("srcAddr", srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
	} else {
		if err := c.RelayUDPData(srcAddr, dstAddr, buffer, dataLen); err != nil {
			logger.Info("Relay UDP failed", zap.String("error", err.Error()))
		}
	}
}

func (c *ProxyClient) relayDNS(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, msg *dns.Msg) error {
	if c.dnsServer == nil {
		return errors.New("No backend DNS server")
	}
	response, err := c.dnsServer.ServerDNSPacket(msg)
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("response dns packet is empty")
	}
	c.udpBackend_.WriteBackUDPPayload(c, srcAddr, dstAddr, response, time.Duration(c.dnsMockTimeout)*time.Second)
	return nil

}

func (c *ProxyClient) Stop() {
	logger := log.GetLogger()
	c.dnsServer = nil

	if err := c.tcpListener.Close(); err != nil {
		logger.Error("Close TCP listener failed", zap.String("error", err.Error()))
	}
	if err := c.udpListener.Close(); err != nil {
		logger.Error("Close UDP listener failed", zap.String("error", err.Error()))
	}
	for _, backend := range c.backends_ {
		backend.Stop()
	}
	c.dnsSyncResolver.Stop()

	c.udpNatMap_.Lock()
	defer c.udpNatMap_.Unlock()

	for _, entry := range c.udpNatMap_.entries {
		if err := entry.dstUdp_.Close(); err != nil {
			logger.Error("Close UDP proxy failed", zap.String("error", err.Error()))
		}
	}

	c.udpBackend_.stop()

	logger.Info("ProxyClient stopped")

}

func (c *ProxyClient) relayUDPData(udpKey string, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, data []byte, dataLen int) error {
	logger := log.GetLogger()
	if dataLen > common.UDP_BUFFER_SIZE {
		return errors.New(fmt.Sprintf("udp packet too big, so ignore: %d", dataLen))
	}
	c.udpNatMap_.Lock()
	udpProxy := c.udpNatMap_.Get(udpKey)
	if udpProxy == nil {
		backendProxy := c.getBackendProxy()
		if backendProxy == nil {
			c.udpNatMap_.Unlock()
			return errors.New("Can not get backend proxy")
		}
		var err error
		if udpProxy, err = backendProxy.GetUDPRelayEntry(dstAddr); err != nil {
			c.udpNatMap_.Unlock()
			return errors.Wrap(err, "UDP proxy listen local failed ")
		}
		c.udpNatMap_.Add(udpKey, udpProxy)
		udpProxy.Lock()
		c.udpNatMap_.Unlock()
		if udpProxy.dstUdp_ != nil {
			udpProxy.Unlock()
			// now lets run copy from dst
			go func() {
				// copy udp from remote
				defer func() {
					if srcAddr == nil {
						logger.Debug("dns relay entry quit", zap.String("src", udpProxy.dstUdp_.LocalAddr().String()), zap.String("dst", dstAddr.String()))
					} else {
						logger.Debug("udp relay entry quit", zap.String("src", srcAddr.String()), zap.String("dst", dstAddr.String()))
					}
					c.udpNatMap_.Lock()
					c.udpNatMap_.Del(udpKey)
					c.udpNatMap_.Unlock()
					udpProxy.dstUdp_.Close()

				}()

				buffer := c.udpBuffer_.Get()
				defer c.udpBuffer_.Put(buffer)
				var n int
				for {
					buffer = buffer[:cap(buffer)]
					n, _, err = udpProxy.dstUdp_.ReadFrom(buffer)
					udpProxy.dstUdp_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
					if err != nil {
						// do not print timeout
						if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
							logger.Error("Read udp from remote dst failed", zap.String("error", err.Error()))
						}
						return
					}
					//logger.Debug("Read from remote", zap.Int("size", n))
					// now lets write back
					headerLen := len(udpProxy.header_)
					writeBuffer := make([]byte, n-headerLen)
					copy(writeBuffer, buffer[headerLen:n])
					if n > headerLen {
						if srcAddr == nil {
							// its dns so deal accordingly
							c.dnsSyncResolver.ProcessDnsResponse(logger, writeBuffer)
							//c.processDNSResponse(writeBuffer)
						} else {
							// regular udp proxy
							c.udpBackend_.WriteBackUDPPayload(c, srcAddr, dstAddr, writeBuffer, udpProxy.timeout)
						}
					} else {
						logger.Info("UDP read from remote too small, so not write back", zap.Int("n", n), zap.Int("headerLen", headerLen))
					}

				}

			}()
		} else {
			if udpProxy.dstKcp_ != nil {
				udpProxy.dstKcp_.SetWriteDeadline(time.Now().Add(udpProxy.timeout))
				_, err = udpProxy.dstKcp_.Write(udpProxy.header_)
			} else {
				udpProxy.dstTcp_.SetWriteDeadline(time.Now().Add(udpProxy.timeout))
				_, err = udpProxy.dstTcp_.Write(udpProxy.header_)
			}
			udpProxy.Unlock()
			if err != nil {
				if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
					logger.Info("write udp over tcp failed", zap.String("error", err.Error()))
				} else {
					logger.Info("write udp over tcp with timeout", zap.Duration("timeout", udpProxy.timeout))
				}
				// close the connection
				c.udpNatMap_.Lock()
				c.udpNatMap_.Del(udpKey)
				c.udpNatMap_.Unlock()
				if udpProxy.dstKcp_ != nil {
					udpProxy.dstKcp_.Close()
				} else {
					udpProxy.dstTcp_.Close()
				}
				return err
			}

			go func() {
				defer func() {
					if srcAddr == nil {
						if udpProxy.dstKcp_ != nil {
							logger.Debug("dns relay entry quit", zap.String("dst", dstAddr.String()))
						} else {
							logger.Debug("dns relay entry quit", zap.String("dst", dstAddr.String()))
						}

					} else {
						logger.Debug("udp relay entry quit", zap.String("src", srcAddr.String()), zap.String("dst", dstAddr.String()))
					}
					c.udpNatMap_.Lock()
					c.udpNatMap_.Del(udpKey)
					c.udpNatMap_.Unlock()
					if udpProxy.dstKcp_ != nil {
						udpProxy.dstKcp_.Close()
					} else {
						udpProxy.dstTcp_.Close()
					}
				}()

				buffer := c.udpBuffer_.Get()
				defer c.udpBuffer_.Put(buffer)
				var n int
				for {
					buffer = buffer[:cap(buffer)]
					if udpProxy.dstKcp_ != nil {
						n, err = common.ReadUdpOverTcp(udpProxy.dstKcp_, buffer)
						udpProxy.dstKcp_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
					} else {
						n, err = common.ReadUdpOverTcp(udpProxy.dstTcp_, buffer)
						udpProxy.dstTcp_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
					}
					if err != nil {
						if err != io.EOF {
							if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
								logger.Error("Read udp over tcp from remote dst failed", zap.String("error", err.Error()))
							}
						}
						return
					}
					if n > 0 {
						writeBuffer := make([]byte, n)
						copy(writeBuffer, buffer[:n])
						if srcAddr == nil {
							// its dns so deal accordingly
							c.dnsSyncResolver.ProcessDnsResponse(logger, writeBuffer)
						} else {
							// regular udp proxy
							c.udpBackend_.WriteBackUDPPayload(c, srcAddr, dstAddr, writeBuffer, udpProxy.timeout)
						}
					}
				}
			}()
		}

	} else {
		c.udpNatMap_.Unlock()
	}

	headerLen := len(udpProxy.header_)
	totalLen := headerLen + dataLen
	// we ignore udp packet which too big, which is 4096 bytes, well enough beyond any MTU
	if totalLen > c.udpBuffer_.GetBufferSize() {
		return errors.New(fmt.Sprintf("udp packet too big: %d > %d", totalLen, common.UDP_BUFFER_SIZE))
	}
	if udpProxy.dstUdp_ != nil {
		// get leaky buffer
		newBuffer := c.udpBuffer_.Get()
		defer c.udpBuffer_.Put(newBuffer)
		copy(newBuffer, udpProxy.header_)
		copy(newBuffer[headerLen:], data[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dstUdp_.WriteTo(newBuffer[:totalLen], udpProxy.proxyAddr); err != nil {
			return err
		}
		udpProxy.dstUdp_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
	} else {
		var err error
		udpProxy.Lock()
		defer udpProxy.Unlock()
		if udpProxy.dstKcp_ != nil {
			udpProxy.dstKcp_.SetWriteDeadline(time.Now().Add(udpProxy.timeout))
			_, err = common.WriteUdpOverTcp(udpProxy.dstKcp_, data[:dataLen])
		} else {
			udpProxy.dstTcp_.SetWriteDeadline(time.Now().Add(udpProxy.timeout))
			_, err = common.WriteUdpOverTcp(udpProxy.dstTcp_, data[:dataLen])
		}

		if err != nil {
			if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
				logger.Info("write udp over tcp failed", zap.String("error", err.Error()))
			} else {
				logger.Info("write udp over tcp with timeout", zap.Duration("timeout", udpProxy.timeout))
			}
			// close the connection
			if udpProxy.dstKcp_ != nil {
				udpProxy.dstKcp_.SetReadDeadline(time.Now())
			} else {
				udpProxy.dstTcp_.SetReadDeadline(time.Now())
			}
			return err
		}
		if udpProxy.dstKcp_ != nil {
			udpProxy.dstKcp_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
		} else {
			udpProxy.dstTcp_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
		}

	}
	return nil
}
func (c *ProxyClient) RelayUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, data []byte, dataLen int) error {
	return c.relayUDPData(computeUDPKey(srcAddr, dstAddr), srcAddr, dstAddr, data, dataLen)
}

// using relay udp data to exchange dns

func (c *ProxyClient) SetDNSProcessor(server common.DNSServerInterface) {
	c.dnsServer = server
}

//func (c *ProxyClient) processDNSResponse(data []byte) {
//	logger := log.GetLogger()
//	dnsId := binary.BigEndian.Uint16(data)
//	// now we unpack
//	resDns := new(dns.Msg)
//	if err := resDns.Unpack(data); err != nil {
//		logger.Info("DNS unpack for proxy resolver failed", zap.String("error", err.Error()))
//		return
//	}
//
//	c.dnsSyncResolver.dnsQueryMapMux.Lock()
//	// if id is exists then send signal for notification and delete this entry
//	if sig, ok := c.dnsSyncResolver.dnsQueryMap[dnsId]; ok {
//		delete(c.dnsSyncResolver.dnsQueryMap, dnsId)
//		c.dnsSyncResolver.dnsQueryMapMux.Unlock()
//		// put id back for re-use
//		c.dnsSyncResolver.dnsIdQueue <- dnsId
//		sig <- resDns
//	} else {
//		c.dnsSyncResolver.dnsQueryMapMux.Unlock()
//	}
//}

func (c *ProxyClient) ExchangeDNS(dnsAddr string, data []byte, timeout time.Duration) (response *dns.Msg, err error) {
	dstAddr, err := net.ResolveUDPAddr("udp", dnsAddr)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("resolve dns server addr failed: %s", dnsAddr))
	}

	//logger := log.GetLogger()
	dnsId := c.dnsSyncResolver.GetDnsId()
	//dnsId := <-c.dnsSyncResolver.dnsIdQueue
	// replace original id with new id
	binary.BigEndian.PutUint16(data, dnsId)

	err = c.relayUDPData(computeDnsKey(dnsAddr), nil, dstAddr, data, len(data))
	if err != nil {
		// recycle id
		c.dnsSyncResolver.PutDnsId(dnsId)
		return nil, err
	}
	return c.dnsSyncResolver.WaitResponse(dnsId, timeout)
	//sig := make(chan *dns.Msg)
	//c.dnsSyncResolver.dnsQueryMapMux.Lock()
	//c.dnsSyncResolver.dnsQueryMap[dnsId] = sig
	//c.dnsSyncResolver.dnsQueryMapMux.Unlock()
	//
	//// set timeout for dns query
	//timeoutTimer := time.NewTimer(timeout)
	//select {
	//case dnsResponse := <-sig:
	//	if dnsResponse == nil {
	//		return nil, errors.New("dns sig channel close")
	//	} else {
	//		return dnsResponse, nil
	//	}
	//
	//case <-timeoutTimer.C:
	//	// remove from map and recycle id after timeout triggered
	//	c.dnsSyncResolver.dnsQueryMapMux.Lock()
	//	defer c.dnsSyncResolver.dnsQueryMapMux.Unlock()
	//	delete(c.dnsSyncResolver.dnsQueryMap, dnsId)
	//	c.dnsSyncResolver.dnsIdQueue <- dnsId
	//	return nil, errors.New(fmt.Sprintf("read dns from remote proxy timeout: %s, dnsID: %d", timeout.String(), dnsId))
	//}

}
