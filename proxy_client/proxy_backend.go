package proxy_client

import (
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/weishi258/go-shadowsocks2/core"
	"github.com/weishi258/go-shadowsocks2/socks"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
	"io"
	"math"
	"net"
	"sync"
	"time"
)



type proxyBackend struct {
	cipher_ core.Cipher
	tcpAddr net.TCPAddr
	udpAddr *net.UDPAddr
	remoteServerConfig config.RemoteServerConfig

	networkType_ string
	tcpTimeout_  time.Duration
	udpTimeout_  time.Duration
	kcpBackend   *KCPBackend

	dnsResolver *dnsProxyResolver

}

const (
	RELAY_TCP_RETRY = "Kcp relay tcp failed when write header"
)


func computeUDPKey(src *net.UDPAddr, dst *net.UDPAddr) string {
	return fmt.Sprintf("%s->%s", src.String(), dst.String())
}

func CreateProxyBackend(remoteServerConfig config.RemoteServerConfig) (ret *proxyBackend, err error) {

	ret = &proxyBackend{}
	ret.remoteServerConfig = remoteServerConfig
	ret.tcpTimeout_ = time.Second * time.Duration(remoteServerConfig.TcpTimeout)
	ret.udpTimeout_ = time.Second * time.Duration(remoteServerConfig.UdpTimeout)

	var isIPv6 bool
	if isIPv6, err = network.CheckIPFamily(remoteServerConfig.RemoteServer); err != nil {
		err = errors.Wrap(err, fmt.Sprintf("Invalid IP format: %s", remoteServerConfig.RemoteServer))
		return
	}
	if isIPv6 {
		ret.networkType_ = "tcp6"
	} else {
		ret.networkType_ = "tcp4"
	}
	if ip, port, ee := network.ParseAddr(remoteServerConfig.RemoteServer, isIPv6); ee != nil {
		err = errors.Wrap(ee, "Parse IPv4 failed")
		return
	} else {
		ret.tcpAddr = net.TCPAddr{IP: ip, Port: port}
		ret.udpAddr = &net.UDPAddr{IP: ip, Port: port}
	}

	if ret.cipher_, err = core.PickCipher(remoteServerConfig.Crypt, []byte{}, remoteServerConfig.Password); err != nil {
		err = errors.Wrap(err, "Generate cipher failed")
		return
	}


	if ret.dnsResolver, err = StartDnsResolver(ret.cipher_); err != nil{
		err = errors.Wrap(err, "Dns conn listening failed")
		return
	}
	if remoteServerConfig.Kcptun.Enable {
		if ret.kcpBackend, err = StartKCPBackend(remoteServerConfig.Kcptun, remoteServerConfig.Crypt, remoteServerConfig.Password); err != nil {
			err = errors.Wrap(err, "Create KCP backend failed")
		}
	}

	return
}

func (c *proxyBackend) GetUDPTimeout() time.Duration {
	return c.udpTimeout_
}

func (c *proxyBackend) Stop() {
	logger := log.GetLogger()

	if err := c.dnsResolver.Stop(); err != nil{
		logger.Error("Proxy close dns resolver failed", zap.String("error", err.Error()))
	}

	if c.kcpBackend != nil {
		c.kcpBackend.Stop()
	}
	logger.Info("Proxy backend stopped", zap.String("addr", c.tcpAddr.String()))
}

func (c *proxyBackend) createTCPConn() (conn net.Conn, err error) {

	conn, err = net.DialTCP(c.networkType_, nil, &c.tcpAddr)
	if err != nil {
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)

	conn = c.cipher_.StreamConn(conn)

	return

}

func (c *proxyBackend) relayKCPData(srcConn net.Conn, kcpConn *smux.Stream, header []byte) (inboundSize int64, outboundSize int64, err error) {
	defer kcpConn.Close()

	srcConn.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))
	kcpConn.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))

	if _, err = kcpConn.Write(header); err != nil {
		log.GetLogger().Error(RELAY_TCP_RETRY, zap.String("err", err.Error()))
		err = errors.New(RELAY_TCP_RETRY)
		return
	}

	ch := make(chan relayDataRes)

	go func() {
		res := relayDataRes{}
		res.outboundSize, res.Err = io.Copy(srcConn, kcpConn)
		srcConn.SetDeadline(time.Now())
		kcpConn.Close()
		ch <- res
	}()

	inboundSize, err = io.Copy(kcpConn, srcConn)
	srcConn.SetDeadline(time.Now())
	kcpConn.Close()
	rs := <-ch

	if err == nil {
		err = rs.Err
	}

	outboundSize = rs.outboundSize

	return
}

func (c *proxyBackend) RelayTCPData(src net.Conn) (inboundSize int64, outboundSize int64, err error) {

	var originDst []byte
	if originDst, err = network.ConvertShadowSocksAddr(src.LocalAddr().String()); err != nil {
		err = errors.Wrap(err, "Parse origin dst failed")
		return
	}

	// try relay data through KCP is enabled and working
	if c.kcpBackend != nil {
		// try to get an KCP steam connection, if not fall back to default proxy mode
		var kcpConn *smux.Stream
		if kcpConn, err = c.kcpBackend.GetKcpConn(); err == nil {
			if inboundSize, outboundSize, err = c.relayKCPData(src, kcpConn, originDst); err != nil {
				if err.Error() != RELAY_TCP_RETRY {
					log.GetLogger().Debug("Relay Kcp finished", zap.Int64("inbound", inboundSize), zap.Int64("outbound", outboundSize), zap.String("error", err.Error()))
					return
				}
			} else {
				log.GetLogger().Debug("Relay Kcp finished", zap.Int64("inbound", inboundSize), zap.Int64("outbound", outboundSize))
				return
			}
		}
	}

	var dst net.Conn
	if dst, err = c.createTCPConn(); err != nil {
		err = errors.Wrap(err, "Create remote conn failed")
		return
	}
	defer dst.Close()

	// set deadline timeout
	dst.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))
	src.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))

	if _, err = dst.Write(originDst); err != nil {
		err = errors.Wrap(err, "Write to remote server failed")
		return
	}
	ch := make(chan relayDataRes)

	go func() {
		res := relayDataRes{}
		res.outboundSize, res.Err = io.Copy(dst, src)
		dst.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		src.SetDeadline(time.Now()) // wake up the other goroutine blocking on left
		ch <- res
	}()

	inboundSize, err = io.Copy(src, dst)
	dst.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	src.SetDeadline(time.Now()) // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}

	outboundSize = rs.outboundSize
	return
}


func (c *proxyBackend) GetUDPRelayEntry(dstAddr *net.UDPAddr) (entry *udpProxyEntry, err error) {
	var conn net.PacketConn
	conn, err = net.ListenPacket("udp", "")
	if err != nil {
		err = errors.Wrap(err, "UDP proxy listen local failed")
		return
	}
	conn = c.cipher_.PacketConn(conn)

	if entry, err = createUDPProxyEntry(conn, dstAddr, c.udpAddr, c.udpTimeout_); err != nil {
		conn.Close()
		err = errors.Wrap(err, "Create udp proxy entry failed")
	}
	return
}




func (c *proxyBackend)ResolveDNS(headerLen int, payload []byte, timeout time.Duration) (*dns.Msg, error){
	// we use half of udp timeout for dns timeout
	return c.dnsResolver.resolveDNS(headerLen,  payload, timeout, c.udpAddr)
}




type dnsProxyResolver struct {
	dnsConn        net.PacketConn
	dnsIdQueue     chan uint16

	dnsQueryMap    map[uint16]chan<-*dns.Msg
	dnsQueryMapMux sync.RWMutex
	buffer    	   *common.LeakyBuffer

}
func StartDnsResolver(cipher core.Cipher) (ret *dnsProxyResolver, err error){
	ret = &dnsProxyResolver{}
	if ret.dnsConn, err = net.ListenPacket("udp4", ""); err != nil{
		err = errors.Wrap(err, "Dns conn listening failed")
		return
	}
	ret.dnsConn = cipher.PacketConn(ret.dnsConn)

	ret.dnsIdQueue = make(chan uint16, math.MaxUint16)
	for i:=1; i < math.MaxUint16; i++{
		ret.dnsIdQueue <- uint16(i)
	}

	ret.dnsQueryMap = make(map[uint16]chan<-*dns.Msg)
	ret.buffer = common.NewLeakyBuffer(common.DNS_BUFFER_POOL_SIZE, common.DNS_BUFFER_SIZE)
	go ret.processResponse()
	return
}

func (c *dnsProxyResolver) Stop() error{
	return c.dnsConn.Close()
}

func (c *dnsProxyResolver)processResponse(){
	logger := log.GetLogger()
	// set read timeout to forever
	c.dnsConn.SetReadDeadline(time.Time{})
	for{
		buffer := c.buffer.Get()
		if dataLen, _, err := c.dnsConn.ReadFrom(buffer); err != nil{
			c.buffer.Put(buffer)
			logger.Error("Dns resolver read failed", zap.String("error", err.Error()))
			return
		}else{
			go c.processDns(buffer, dataLen)
		}
	}
}

func (c *dnsProxyResolver)processDns(buffer []byte, dataLen int){
	logger := log.GetLogger()
	defer c.buffer.Put(buffer)
	// lets process response
	// get header length
	data := buffer[:dataLen]
	//logger.Debug("read dns response", zap.Int("length", dataLen))

	dstAddrBytes := socks.SplitAddr(data)
	if dstAddrBytes == nil{
		logger.Error("extract shadowsocks proxy header failed")
		return
	}
	headerLen := len(dstAddrBytes)
	//logger.Debug("extract dns response", zap.Int("header length", headerLen))
	// extract raw response
	data = data[headerLen:]
	// extract dnsId
	dnsId := binary.BigEndian.Uint16(data)

	// now we unpack
	resDns := new(dns.Msg)
	if err := resDns.Unpack(data); err != nil {
		logger.Error("DNS unpack for proxy resolver failed", zap.String("error", err.Error()))
		return
	}

	c.dnsQueryMapMux.Lock()
	// if id is exists then send signal for notification and delete this entry
	if sig, ok := c.dnsQueryMap[dnsId]; ok{
		delete(c.dnsQueryMap, dnsId)
		c.dnsQueryMapMux.Unlock()
		// put id back for re-use
		c.dnsIdQueue <- dnsId
		sig <- resDns
	}else{
		c.dnsQueryMapMux.Unlock()
	}
}

func (c *dnsProxyResolver) resolveDNS(headerLen int, payload []byte, timeout time.Duration, addr *net.UDPAddr) (*dns.Msg, error){

	// get un-used id from queue
	dnsId := <- c.dnsIdQueue
	// replace original id with new id
	binary.BigEndian.PutUint16(payload[headerLen:], dnsId)
	if _, err := c.dnsConn.WriteTo(payload, addr); err != nil{
		c.dnsIdQueue <- dnsId
		return nil, errors.Wrap(err, "Write to remote dns proxy failed")
	}else{
		// successful write so map it for later resolve response
		sig := make(chan*dns.Msg)
		c.dnsQueryMapMux.Lock()
		c.dnsQueryMap[dnsId] = sig
		c.dnsQueryMapMux.Unlock()

		// set timeout for dns query
		timeout := time.NewTimer(timeout)
		select{
			case dnsResponse := <- sig:
				return dnsResponse, nil
			case <- timeout.C:
				// remove from map and recycle id after timeout triggered
				c.dnsQueryMapMux.Lock()
				defer c.dnsQueryMapMux.Unlock()
				delete(c.dnsQueryMap, dnsId)
				c.dnsIdQueue <- dnsId
				return nil, errors.New("read dns from remote proxy timeout")
		}
	}
}

