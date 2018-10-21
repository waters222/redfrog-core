package proxy_client

import (
	"github.com/miekg/dns"
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


//const(
//	DNS_ADDR_MOCK_TIMEOUT = 60
//)

type ProxyClient struct {
	backends_   []*proxyBackend
	backendMux sync.RWMutex


	tcpListener net.Listener
	udpListener *net.UDPConn

	udpBuffer_    *common.LeakyBuffer
	udpOOBBuffer_ *common.LeakyBuffer
	addr          string

	udpBackend_    *udpBackend
	udpNatMap_     *udpNatMap

	dnsServer		common.DNSServerInterface
	dnsMockTimeout  int
}


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
	buf := make([]byte, len(addr))
	copy(buf, addr)
	return &udpProxyEntry{dst, buf, proxyAddr, timeout}, nil
}


type udpNatMap struct {
	sync.RWMutex
	entries map[string]*udpProxyEntry
}

func (c *udpNatMap) Add(key string, entry *udpProxyEntry) {
	//c.Lock()
	//defer c.Unlock()
	c.entries[key] = entry
}
func (c *udpNatMap) Del(key string) {
	//c.Lock()
	//defer c.Unlock()
	delete(c.entries, key)
}
func (c *udpNatMap) Get(key string) *udpProxyEntry {
	//c.RLock()
	//defer c.RUnlock()
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
	ret.udpBackend_ = NewUDPBackend()
	ret.dnsMockTimeout = dnsMockTimeout
	ret.udpNatMap_ = &udpNatMap{entries: make(map[string]*udpProxyEntry)}
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

func (c *ProxyClient)ReloadBackend(dnsMockTimeout int, serverConfig config.ShadowsocksConfig) (err error){
	logger := log.GetLogger()
	newBackends := make([]*proxyBackend, 0)

	c.backendMux.Lock()
	defer c.backendMux.Unlock()
	c.dnsMockTimeout = dnsMockTimeout
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

func (c *ProxyClient) getBackendProxyByAddr(addr string) *proxyBackend {
	c.backendMux.RLock()
	defer c.backendMux.RUnlock()
	for _, backend :=range c.backends_{
		if backend.udpAddr.String() == addr{
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

func (c *ProxyClient) GetUDPBuffer() []byte{
	return c.udpBuffer_.Get()
}
func (c *ProxyClient) PutUDPBuffer(buffer []byte){
	c.udpBuffer_.Put(buffer)
}

func (c *ProxyClient) HandleUDP(buffer []byte, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, dataLen int) {
	logger := log.GetLogger()
	defer c.udpBuffer_.Put(buffer)
	//logger.Debug("HandleUDP", zap.String("src", srcAddr.String()), zap.String("dst", dstAddr.String()))
	if dstAddr.Port == 53{
		msg := new(dns.Msg)
		if err := msg.Unpack(buffer[:dataLen]); err != nil{
			logger.Error("unpack DNS packet failed", zap.String("src", srcAddr.String()), zap.String("DNS server", dstAddr.String()), zap.Int("udp size", dataLen),zap.String("error", err.Error()))
			return
		}
		if err := c.relayDNS(srcAddr, dstAddr, msg); err != nil {
			logger.Info("Relay DNS failed", zap.String("error", err.Error()))
			return
		}
		logger.Debug("Relay DNS successful", zap.String("srcAddr", srcAddr.String()),zap.String("dstAddr", dstAddr.String()))
	}else{
		if err := c.RelayUDPData(srcAddr, dstAddr, buffer, dataLen); err != nil {
			logger.Info("Relay UDP failed", zap.String("error", err.Error()))
		}
	}
}

func (c *ProxyClient) relayDNS(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, msg *dns.Msg) error {
	if c.dnsServer == nil{
		return errors.New("No backend DNS server")
	}
	response, err := c.dnsServer.ServerDNSPacket(msg)
	if err != nil{
		return err
	}
	if response == nil{
		return errors.New("response dns packet is empty")
	}
	c.udpBackend_.WriteBackUDPPayload(c, srcAddr, dstAddr, response, time.Duration(c.dnsMockTimeout) * time.Second)
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

	c.udpBackend_.stop()

	c.udpNatMap_.Lock()
	defer c.udpNatMap_.Unlock()

	for _, entry := range c.udpNatMap_.entries {
		if err := entry.dst_.Close(); err != nil {
			logger.Error("Close UDP proxy failed", zap.String("error", err.Error()))
		}
	}


	logger.Info("ProxyClient stopped")

}


//func (c *ProxyClient) doWriteBackUDPData(srcConn *net.UDPConn, chanKey string, udpTimeout time.Duration, sendChannel chan dstMapChannel, dstAddr *net.UDPAddr){
//	logger := log.GetLogger()
//	defer func(){
//		logger.Debug("UDP bind close", zap.String("addr", dstAddr.String()))
//		c.udpOrigDstMap_.Lock()
//		defer c.udpOrigDstMap_.Unlock()
//		srcConn.Close()
//		c.udpOrigDstMap_.Del(chanKey)
//	}()
//	timer := time.NewTimer(udpTimeout)
//	timeout := time.Now()
//	for {
//		select {
//		case ch := <-sendChannel:
//			if len(ch.payload) > 0 {
//				if _, err := srcConn.WriteTo(ch.payload, ch.srcAddr); err != nil {
//					logger.Error("UDP orig dst handler write failed", zap.String("error", err.Error()))
//					return
//				} else {
//					logger.Debug("UDP orig dst write back", zap.String("srcAddr", ch.srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
//					timeout = timeout.Add(udpTimeout)
//				}
//			}
//
//		case <-timer.C:
//			diff := timeout.Sub(time.Now())
//			if diff >= 0 {
//				timer.Reset(diff)
//			} else {
//				logger.Debug("UDP orig dst handler timeout", zap.String("dstAddr", dstAddr.String()), zap.Duration("timeout", udpTimeout))
//				return
//			}
//		}
//	}
//}
//
//func (c *ProxyClient) writeBackUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, payload []byte, udpTimeout time.Duration) {
//	logger := log.GetLogger()
//	chanKey := dstAddr.String()
//
//	signal := dstMapChannel{srcAddr, payload}
//	c.udpOrigDstMap_.Lock()
//	defer c.udpOrigDstMap_.Unlock()
//	sendChannel := c.udpOrigDstMap_.Get(chanKey)
//	if sendChannel == nil{
//		if srcConn, err := network.DialTransparentUDP(dstAddr); err != nil {
//			logger.Error("UDP proxy listen using transparent failed", zap.String("src", srcAddr.String()), zap.String("dst", dstAddr.String()), zap.String("error", err.Error()))
//			return
//		} else {
//			sendChannel = make(chan dstMapChannel, common.CHANNEL_QUEUE_LENGTH)
//			c.udpOrigDstMap_.Add(chanKey, sendChannel)
//			go c.doWriteBackUDPData(srcConn, chanKey, udpTimeout, sendChannel, dstAddr)
//		}
//	}
//	sendChannel <- signal
//}

func (c *ProxyClient) RelayUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, data []byte, dataLen int) error {
	logger := log.GetLogger()

	udpKey := computeUDPKey(srcAddr, dstAddr)

	c.udpNatMap_.Lock()
	defer c.udpNatMap_.Unlock()

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

		c.udpNatMap_.Add(udpKey, udpProxy)

		// now lets run copy from dst
		go func() {
			// copy udp from remote
			defer func(){
				c.udpNatMap_.Lock()
				defer c.udpNatMap_.Unlock()
				udpProxy.dst_.Close()
				c.udpNatMap_.Del(udpKey)
			}()

			buffer := c.udpBuffer_.Get()
			defer c.udpBuffer_.Put(buffer)

			for{
				udpProxy.dst_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
				if n, _, err := udpProxy.dst_.ReadFrom(buffer); err != nil{
					// do not print timeout
					if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
						logger.Error("Read udp from remote dst failed", zap.String("error", err.Error()))
					}
					return
				}else{
					//logger.Debug("Read from remote", zap.Int("size", n))
					// now lets write back
					headerLen := len(udpProxy.header_)
					if n > headerLen {
						c.udpBackend_.WriteBackUDPPayload(c, srcAddr, dstAddr, buffer[headerLen:n], udpProxy.timeout)
					} else {
						logger.Info("UDP read from remote too small, so not write back", zap.Int("n", n), zap.Int("headerLen", headerLen))
					}
				}
			}

		}()
	}

	// compose udp socks5 header


	headerLen := len(udpProxy.header_)
	totalLen := headerLen + dataLen

	if totalLen > c.udpBuffer_.GetBufferSize() {
		// too big for our leakybuffer
		writeData := make([]byte, totalLen)
		copy(writeData[:headerLen], udpProxy.header_)
		copy(writeData[headerLen:totalLen], data[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dst_.WriteTo(writeData, udpProxy.proxyAddr); err != nil {
			return err
		}

	} else {
		// get leaky buffer
		newBuffer := c.udpBuffer_.Get()
		defer c.udpBuffer_.Put(newBuffer)
		copy(newBuffer, udpProxy.header_)
		copy(newBuffer[headerLen:], data[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dst_.WriteTo(newBuffer[:totalLen], udpProxy.proxyAddr); err != nil {
			return err
		}
	}
	udpProxy.dst_.SetReadDeadline(time.Now().Add(udpProxy.timeout))
	return nil
}

//
//type dnsClientsMap struct {
//	sync.RWMutex
//	clients    map[string]*dnsClientEntry
//}
//
//
//type dnsClientEntry struct {
//	sync.RWMutex
//	localConn	net.PacketConn
//	dnsIdMap	map[uint32] *dnsIDMapEntry
//}
//
//type dnsIDMapEntry struct {
//
//}

// using relay udp data to exchange dns


func (c *ProxyClient)SetDNSProcessor(server common.DNSServerInterface){
	c.dnsServer = server
}


func (c *ProxyClient) ExchangeDNS(dnsAddr string, data []byte, timeout time.Duration) (response *dns.Msg, err error) {

	if backendProxy := c.getBackendProxy(); backendProxy == nil {
		err = errors.New("Can not get backend proxy")
		return
	} else {

		var addrBytes []byte
		addrBytes, err = network.ConvertShadowSocksAddr(dnsAddr)
		if err != nil {
			err = errors.Wrap(err, "DNS addr convert to shadowsocks addr failed")
			return
		}

		dataLen := len(data)
		addrLen := len(addrBytes)
		totalLen := addrLen + dataLen

		buffer := c.udpBuffer_.Get()
		defer c.udpBuffer_.Put(buffer)

		copy(buffer, addrBytes)
		copy(buffer[addrLen:], data)

		return backendProxy.ResolveDNS(addrLen, buffer[:totalLen], timeout)
		//
		//var conn net.PacketConn
		//conn, err = net.ListenPacket("udp", "")
		//if err != nil {
		//	err = errors.Wrap(err, "DNS proxy listen local failed")
		//	return
		//}
		//conn = backendProxy.cipher_.PacketConn(conn)
		//defer conn.Close()
		//// set timeout for each send
		//// write to remote shadowsocks server
		//if _, err = conn.WriteTo(buffer.Bytes()[:totalLen], backendProxy.udpAddr); err != nil {
		//	err = errors.Wrap(err, "Write to DNS proxy failed")
		//	return
		//}
		//
		//conn.SetReadDeadline(time.Now().Add(backendProxy.GetUDPTimeout()))
		//if n, _, err := conn.ReadFrom(buffer.Bytes()); err != nil{
		//	return nil, err
		//}else{
		//	if n <= addrLen {
		//		err = errors.New("Read query from DNS proxy empty")
		//		return nil, err
		//	}
		//	response = make([]byte, n)
		//	copy(response, buffer.Bytes()[addrLen:n])
		//}
	}

}
