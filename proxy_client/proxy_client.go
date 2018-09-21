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
	"sync"
	"time"
)

type ProxyClient struct {
	backends_   []*proxyBackend
	backendMux sync.RWMutex


	tcpListener net.Listener
	udpListener *net.UDPConn

	udpBuffer_    *common.LeakyBuffer
	udpOOBBuffer_ *common.LeakyBuffer
	addr          string

	//udpTimeout_    time.Duration
	udpOrigDstMap_ *udpOrigDstMap
	udpNatMap_     *udpNatMap
	//dnsNatMap_     *dnsNatMap


}

//type dnsNatMap struct {
//	sync.RWMutex
//	entries map[string]*dnsNapMapEntry
//}
//type dnsNapMapEntry struct {
//	conn      net.PacketConn
//	proxyAddr *net.UDPAddr
//	sync.Mutex
//}
//
//func (c *dnsNatMap) Get(key string) *dnsNapMapEntry {
//	c.RLock()
//	defer c.RUnlock()
//	ret, ok := c.entries[key]
//	if ok {
//		return ret
//	} else {
//		return nil
//	}
//}
//
//func (c *dnsNatMap) Add(key string, entry *dnsNapMapEntry) {
//	c.Lock()
//	defer c.Unlock()
//	c.entries[key] = entry
//}

//func createDNSProxyEntry(dst net.PacketConn, proxyAddr *net.UDPAddr) *dnsNapMapEntry {
//
//	return &dnsNapMapEntry{dst, proxyAddr}
//}

//func (c *dnsNatMap) Del(key string) {
//	c.Lock()
//	defer c.Unlock()
//	delete(c.entries, key)
//}

// udp relay
type relayDataRes struct {
	outboundSize int64
	Err          error
}

type udpProxyEntry struct {
	dst_      net.PacketConn
	header_   []byte
	proxyAddr *net.UDPAddr
	timeout   time.Duration
}

func createUDPProxyEntry(dst net.PacketConn, dstAddr *net.UDPAddr, proxyAddr *net.UDPAddr, timeout time.Duration) (*udpProxyEntry, error) {
	addr, err := network.ConvertShadowSocksAddr(dstAddr.String())
	if err != nil {
		return nil, err
	}
	return &udpProxyEntry{dst, addr, proxyAddr, timeout}, nil
}

type udpOrigDstMap struct {
	sync.RWMutex
	channels map[string]chan dstMapChannel
}

func (c *udpOrigDstMap) Send(key string, ch dstMapChannel) bool {
	c.RLock()
	defer c.RUnlock()
	if channel, ok := c.channels[key]; ok {
		channel <- ch
		return true
	} else {
		return false
	}
}

func (c *udpOrigDstMap) Add(key string, channel chan dstMapChannel) {
	c.Lock()
	defer c.Unlock()
	c.channels[key] = channel
}
func (c *udpOrigDstMap) Del(key string) {
	c.Lock()
	defer c.Unlock()
	delete(c.channels, key)
}

type dstMapChannel struct {
	srcAddr *net.UDPAddr
	payload []byte
}

type udpNatMap struct {
	sync.RWMutex
	entries map[string]*udpProxyEntry
}

func (c *udpNatMap) Add(key string, entry *udpProxyEntry) {
	c.Lock()
	defer c.Unlock()
	c.entries[key] = entry
}
func (c *udpNatMap) Del(key string) {
	c.Lock()
	defer c.Unlock()
	delete(c.entries, key)
}
func (c *udpNatMap) Get(key string) *udpProxyEntry {
	c.RLock()
	defer c.RUnlock()
	if entry, ok := c.entries[key]; ok {
		return entry
	} else {
		return nil
	}
}

func StartProxyClient(config config.ShadowsocksConfig, listenAddr string) (*ProxyClient, error) {
	logger := log.GetLogger()

	ret := &ProxyClient{}
	ret.addr = listenAddr

	if err := ret.StartBackend(config); err != nil{
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
	ret.udpOrigDstMap_ = &udpOrigDstMap{channels: make(map[string]chan dstMapChannel)}
	ret.udpNatMap_ = &udpNatMap{entries: make(map[string]*udpProxyEntry)}
	//ret.dnsNatMap_ = &dnsNatMap{entries: make(map[string]*dnsNapMapEntry)}
	go ret.startListenUDP()

	logger.Info("ProxyClient start successful", zap.String("addr", listenAddr))
	return ret, nil
}

func (c *ProxyClient)StartBackend(serverConfig config.ShadowsocksConfig) (err error){
	logger := log.GetLogger()
	c.backendMux.Lock()
	defer c.backendMux.Unlock()

	c.backends_ = make([]*proxyBackend, 0)

	for _, backendConfig := range serverConfig.Servers {
		if backendConfig.Enable{
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

	if len(c.backends_) == 0{
		err = errors.New("No backend created !!!")
	}
	return
}

func (c *ProxyClient)ReloadBackend(serverConfig config.ShadowsocksConfig) (err error){
	logger := log.GetLogger()
	newBackends := make([]*proxyBackend, 0)

	c.backendMux.Lock()
	defer c.backendMux.Unlock()

	for _, backend := range c.backends_{
		shouldClosed := true
		for _, backendConfig := range serverConfig.Servers {
			if backend.remoteServerConfig.RemoteServer == backendConfig.RemoteServer{
				// we have a match
				if backend.remoteServerConfig.Equal(&backendConfig){
					logger.Debug("Should not close backend", zap.String("server", backendConfig.RemoteServer))
					shouldClosed = false
				}
				break
			}
		}
		if shouldClosed{
			logger.Debug("Closing backend", zap.String("server", backend.remoteServerConfig.RemoteServer))
			backend.Stop()
		}else{
			newBackends = append(newBackends, backend)
		}
	}

	for _, backendConfig := range serverConfig.Servers {
		if backendConfig.Enable{
			shouldStart := true
			for _, backend := range newBackends{
				if backendConfig.RemoteServer == backend.remoteServerConfig.RemoteServer{
					shouldStart = false
					break
				}
			}
			if shouldStart{
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

	if len(c.backends_) == 0{
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
		if dataLen, oobLen, _, srcAddr, err := c.udpListener.ReadMsgUDP(buffer.Bytes(), oob.Bytes()); err != nil {
			c.udpBuffer_.Put(buffer)
			c.udpOOBBuffer_.Put(oob)

			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection" {
				logger.Debug("Read from udp failed", zap.String("error", err.Error()))
			}
		} else {

			if dstAddr, err := network.ExtractOrigDstFromUDP(oobLen, oob.Bytes()); err != nil {
				logger.Error("Failed to extract original dst from udp", zap.String("error", err.Error()))
			} else {
				go c.handleUDP(buffer, srcAddr, dstAddr, dataLen)
			}
			c.udpOOBBuffer_.Put(oob)
		}

	}
	logger.Info("UDP stop listening", zap.String("addr", c.addr))
}
func (c *ProxyClient) handleUDP(buffer *bytes.Buffer, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, dataLen int) {
	logger := log.GetLogger()
	defer c.udpBuffer_.Put(buffer)
	if err := c.RelayUDPData(srcAddr, dstAddr, c.udpBuffer_, buffer, dataLen); err != nil {
		logger.Error("Relay UDP failed", zap.String("error", err.Error()))
	}
}

//func (c * ProxyClient)ExchangeDNS(srcAddr string, dstAddr string, data []byte, dnsTimeout time.Duration) (response []byte, err error) {
//	if backendProxy := c.getBackendProxy(true); backendProxy == nil{
//		err = errors.New("Can not get backend proxy")
//	}else if response, err = backendProxy.RelayDNS(srcAddr, dstAddr, data, c.udpBuffer_, dnsTimeout); err != nil {
//		err = errors.Wrap(err, "Relay DNS query from proxy failed")
//	}
//	return
//}

func (c *ProxyClient) Stop() {
	logger := log.GetLogger()
	if err := c.tcpListener.Close(); err != nil {
		logger.Error("Close TCP listener failed", zap.String("error", err.Error()))
	}
	if err := c.udpListener.Close(); err != nil {
		logger.Error("Close UDP listener failed", zap.String("error", err.Error()))
	}
	for _, backend := range c.backends_ {
		backend.Stop()
	}

	c.udpOrigDstMap_.Lock()
	defer c.udpOrigDstMap_.Unlock()
	for _, channel := range c.udpOrigDstMap_.channels {
		channel <- dstMapChannel{}
	}

	c.udpNatMap_.Lock()
	defer c.udpNatMap_.Unlock()

	for _, entry := range c.udpNatMap_.entries {
		if err := entry.dst_.Close(); err != nil {
			logger.Error("Close UDP proxy failed", zap.String("error", err.Error()))
		}
	}

	//c.dnsNatMap_.Lock()
	//defer c.dnsNatMap_.Unlock()
	//
	//for _, entry := range c.dnsNatMap_.entries {
	//	if err := entry.conn.Close(); err != nil {
	//		logger.Error("Close DNS proxy failed", zap.String("error", err.Error()))
	//	}
	//}

	logger.Info("ProxyClient stopped")

}

func (c *ProxyClient) writeBackUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, payload []byte, udpTimeout time.Duration) {
	logger := log.GetLogger()
	chanKey := dstAddr.String()

	signal := dstMapChannel{srcAddr, payload}
	if !c.udpOrigDstMap_.Send(chanKey, signal) {
		if srcConn, err := network.DialTransparentUDP(dstAddr); err != nil {
			logger.Error("UDP proxy listen using transparent failed", zap.String("error", err.Error()))
		} else {
			dstChannel := make(chan dstMapChannel)
			c.udpOrigDstMap_.Add(chanKey, dstChannel)
			go func() {
				defer srcConn.Close()
				defer c.udpOrigDstMap_.Del(chanKey)
				timer := time.NewTimer(udpTimeout)
				timeout := time.Now()
				for {
					select {
					case ch := <-dstChannel:
						if len(ch.payload) > 0 {
							if _, err := srcConn.WriteTo(ch.payload, ch.srcAddr); err != nil {
								logger.Error("UDP orig dst handler write failed", zap.String("error", err.Error()))
							} else {
								logger.Debug("UDP orig dst write back", zap.String("srcAddr", ch.srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
								timeout = timeout.Add(udpTimeout)
							}
						} else {
							return
						}

					case <-timer.C:
						diff := timeout.Sub(time.Now())
						if diff >= 0 {
							timer.Reset(diff)
						} else {
							logger.Debug("UDP orig dst handler timeout", zap.String("dstAddr", dstAddr.String()))
							return
						}
					}
				}

			}()
			c.udpOrigDstMap_.Send(chanKey, signal)
		}
	}
	//logger.Debug("Send to dst map channel", zap.String("srcAddr", srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
	//dstChannel <- dstMapChannel{srcAddr, payload}
}

func (c *ProxyClient) RelayUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, leakyBuffer *common.LeakyBuffer, data *bytes.Buffer, dataLen int) error {
	logger := log.GetLogger()

	udpKey := computeUDPKey(srcAddr, dstAddr)

	udpProxy := c.udpNatMap_.Get(udpKey)

	//logger.Debug("UDP relay ",zap.String("srcAddr", srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
	if udpProxy == nil {

		backendProxy := c.getBackendProxy()
		if backendProxy == nil {
			return errors.New("Can not get backend proxy")
		}
		var err error
		if udpProxy, err = backendProxy.GetUDPRelayEntry(dstAddr); err != nil {
			return errors.Wrap(err, "UDP proxy listen local failed ")
		}

		// now lets run copy from dst
		go func() {
			// copy udp from remote
			c.udpNatMap_.Add(udpKey, udpProxy)
			defer udpProxy.dst_.Close()
			defer c.udpNatMap_.Del(udpKey)
			buffer := leakyBuffer.Get()
			defer leakyBuffer.Put(buffer)

			udpProxy.dst_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
			n, _, err := udpProxy.dst_.ReadFrom(buffer.Bytes())
			if err != nil {
				// do not print timeout
				if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
					logger.Debug("Read udp from remote dst failed", zap.String("error", err.Error()))
				}
			} else {
				//logger.Debug("Read from remote", zap.Int("size", n))
				// now lets write back
				headerLen := len(udpProxy.header_)
				if n > headerLen {
					c.writeBackUDPData(srcAddr, dstAddr, buffer.Bytes()[headerLen:n], udpProxy.timeout)
				} else {
					logger.Info("UDP read from remote too small, so not write back", zap.Int("n", n), zap.Int("headerLen", headerLen))
				}
			}
		}()
	}

	// compose udp socks5 header
	udpProxy.dst_.SetReadDeadline(time.Now().Add(udpProxy.timeout))

	headerLen := len(udpProxy.header_)
	totalLen := headerLen + dataLen

	if totalLen > leakyBuffer.GetBufferSize() {
		// too big for our leakybuffer
		writeData := make([]byte, totalLen)
		copy(writeData[:headerLen], udpProxy.header_)
		copy(writeData[headerLen:totalLen], data.Bytes()[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dst_.WriteTo(writeData, udpProxy.proxyAddr); err != nil {
			return err
		}

	} else {
		// get leaky buffer
		newBuffer := leakyBuffer.Get()
		defer leakyBuffer.Put(newBuffer)
		copy(newBuffer.Bytes(), udpProxy.header_)
		copy(newBuffer.Bytes()[headerLen:], data.Bytes()[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dst_.WriteTo(newBuffer.Bytes()[:totalLen], udpProxy.proxyAddr); err != nil {
			return err
		}
	}

	return nil
}

func (c *ProxyClient) ExchangeDNS(srcAddr string, dnsAddr string, data []byte, dnsTimeout time.Duration, times int32) (response []byte, err error) {
	//logger := log.GetLogger()

	addrBytes, err := network.ConvertShadowSocksAddr(dnsAddr)
	if err != nil {
		err = errors.Wrap(err, "DNS convert to shadowsocks addr failed")
		return
	}

	dataLen := len(data)
	addrLen := len(addrBytes)
	totalLen := addrLen + dataLen

	buffer := c.udpBuffer_.Get()
	defer c.udpBuffer_.Put(buffer)

	copy(buffer.Bytes(), addrBytes)
	copy(buffer.Bytes()[addrLen:], data)

	//dnsEntry := c.dnsNatMap_.Get(srcAddr)
	//if dnsEntry == nil {
	//	if backendProxy := c.getBackendProxy(); backendProxy == nil {
	//		err = errors.New("Can not get backend proxy")
	//		return
	//	} else {
	//		if dnsEntry, err = backendProxy.GetDNSRelayEntry(); err != nil {
	//			err = errors.Wrap(err, "UDP proxy listen local failed ")
	//			return
	//		}
	//	}
	//	c.dnsNatMap_.Add(srcAddr, dnsEntry)
	//}
	//
	//dnsEntry.Lock()
	//defer dnsEntry.Unlock()
	//defer dnsEntry.conn.Close()
	//defer c.dnsNatMap_.Del(srcAddr)


	if backendProxy := c.getBackendProxy(); backendProxy == nil {
		err = errors.New("Can not get backend proxy")
		return
	} else {
		var conn net.PacketConn
		conn, err = net.ListenPacket("udp", "")
		if err != nil {
			err = errors.Wrap(err, "DNS proxy listen local failed")
			return
		}
		conn = backendProxy.cipher_.PacketConn(conn)
		defer conn.Close()
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err = conn.WriteTo(buffer.Bytes()[:totalLen], backendProxy.udpAddr); err != nil {
			err = errors.Wrap(err, "Write to DNS proxy failed")
			return
		}

		conn.SetReadDeadline(time.Now().Add(dnsTimeout))
		if n, _, err := conn.ReadFrom(buffer.Bytes()); err != nil{
			return nil, err
		}else{
			if n <= addrLen {
				err = errors.New("Read query from DNS proxy empty")
				return nil, err
			}
			response = make([]byte, n)
			copy(response, buffer.Bytes()[addrLen:n])
		}
	}

	return

}
