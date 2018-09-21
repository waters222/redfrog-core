package proxy_client

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
	"io"
	"net"
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
}

const (
	RELAY_TCP_RETRY = "Kcp relay tcp failed when write header"
)

// dns

//func (c *udpProxyEntry) copyFromRemote() error{
//	logger := log.GetLogger()
//	buffer := make([]byte, common.UDP_BUFFER_SIZE)
//	for {
//		c.dst_.SetReadDeadline(time.Now().Add(c.timeout))
//		n, _, err := c.dst_.ReadFrom(buffer)
//
//		if err != nil{
//			return err
//		}
//		logger.Debug("Read from remote", zap.Int("size", n))
//		// should check header
//		if n > len(c.header_) {
//			logger.Debug("Write back to origin", zap.String("addr", c.srcAddr_.String()))
//			if _, err = c.src_.WriteTo(buffer[len(c.header_):n], c.srcAddr_); err != nil{
//				return err
//			}
//		}else{
//			return errors.New(fmt.Sprintf("UDP Read too few bytes: %d", n))
//		}
//	}
//}

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

//func (c* p/*roxyBackend) writeBackUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, payload []byte){
//	logger := log.GetLogger()
//	chanKey := dstAddr.String()
//
//	signal := dstMapChannel{srcAddr, payload}
//	if !c.udpOrigDstMap_.Send(chanKey, signal) {
//		if srcConn, err := network.DialTransparentUDP(dstAddr); err != nil{
//			logger.Error("UDP proxy listen using transparent failed", zap.String("error", err.Error()))
//		}else{
//			dstChannel := make(chan dstMapChannel)
//			c.udpOrigDstMap_.Add(chanKey, dstChannel)
//			go func(){
//				defer srcConn.Close()
//				defer c.udpOrigDstMap_.Del(chanKey)
//				timer := time.NewTimer(c.udpTimeout_)
//				timeout := time.Now()
//				for{
//					select {
//					case ch := <- dstChannel:
//						if len(ch.payload) > 0{
//							if _, err := srcConn.WriteTo(ch.payload, ch.srcAddr); err != nil{
//								logger.Error("UDP orig dst handler write failed", zap.String("error", err.Error()))
//							}else{
//								logger.Debug("UDP orig dst write back", zap.String("srcAddr", ch.srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
//								timeout = timeout.Add(c.udpTimeout_)
//							}
//						}else{
//							return
//						}
//
//					case <- timer.C:
//						diff := timeout.Sub(time.Now())
//						if diff >= 0{
//							timer.Reset(diff)
//						}else{
//							logger.Debug("UDP orig dst handler timeout", zap.String("dstAddr", dstAddr.String()))
//							return
//						}
//					}
//				}
//
//			}()
//			c.udpOrigDstMap_.Send(chanKey, signal)
//		}
//	}
//	//logger.Debug("Send to dst map channel", zap.String("srcAddr", srcAddr.String()), zap.String("dstAddr", dstAddr.String()))
//	//dstChannel <- dstMapChannel{srcAddr, payload}
//}*/

//func (c *proxyBackend) GetDNSRelayEntry() (entry *dnsNapMapEntry, err error) {
//	var conn net.PacketConn
//	conn, err = net.ListenPacket("udp", "")
//	if err != nil {
//		err = errors.Wrap(err, "UDP proxy listen local failed")
//		return
//	}
//	conn = c.cipher_.PacketConn(conn)
//	entry = createDNSProxyEntry(conn, c.udpAddr)
//	return
//
//}

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
