package impl

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"io"
	"net"
	"sync"
	"time"
)

type ProxyServer struct {
	tcpListener_   net.Listener
	udpListener_   net.PacketConn
	tcpTimeout_    time.Duration
	udpTimeout_    time.Duration
	dnsTimeout_    time.Duration
	cipher         core.Cipher
	listenAddr     string
	udpLeakyBuffer *common.LeakyBuffer
	udpNatMap_     *udpNatMap
	kcpServer      *KCPServer
}

type res struct {
	OutboundSize int64
	Err          error
}

type udpNatMapEntry struct {
	conn   *net.UDPConn
	header []byte
}

type udpNatMap struct {
	sync.RWMutex
	entries map[string]*udpNatMapEntry
}

func NewNatMap() *udpNatMap {
	ret := &udpNatMap{}
	ret.entries = make(map[string]*udpNatMapEntry)

	return ret
}

func (c *udpNatMap) Get(key string) *udpNatMapEntry {
	if entry, ok := c.entries[key]; ok {
		return entry
	} else {
		return nil
	}
}

func (c *udpNatMap) Del(key string) {
	delete(c.entries, key)
}

func (c *udpNatMap) Add(key string, conn *net.UDPConn, header []byte) (ret *udpNatMapEntry) {
	buf := make([]byte, len(header))
	copy(buf, header)
	ret = &udpNatMapEntry{conn: conn, header: buf}
	c.entries[key] = ret
	return
}

func StartProxyServer(config config.ServerConfig) (ret *ProxyServer, err error) {

	ret = &ProxyServer{}

	ret.tcpTimeout_ = time.Second * time.Duration(config.TcpTimeout)
	ret.udpTimeout_ = time.Second * time.Duration(config.UdpTimeout)
	ret.listenAddr = config.ListenAddr
	ret.udpLeakyBuffer = common.NewLeakyBuffer(common.UDP_BUFFER_POOL_SIZE*4, common.UDP_BUFFER_SIZE)

	ret.udpNatMap_ = NewNatMap()

	if ret.cipher, err = core.PickCipher(config.Crypt, []byte{}, config.Password); err != nil {
		err = errors.Wrap(err, "Pick cipher failed")
		return
	}
	if err = ret.startTcpListener(); err != nil {
		err = errors.Wrap(err, "TCP listener start failed")
		return
	}
	if err = ret.startUDPListener(); err != nil {
		ret.tcpListener_.Close()
		err = errors.Wrap(err, "UDP listener start failed")
		return
	}
	//
	if config.Kcptun.Enable {
		if ret.kcpServer, err = StartKCPServer(config.Kcptun, config.Crypt, config.Password, ret.udpLeakyBuffer, config.TcpTimeout, config.UdpTimeout); err != nil {
			ret.tcpListener_.Close()
			ret.udpListener_.Close()
			err = errors.Wrap(err, "Start KCP server failed")
		}
	}

	return
}

func (c *ProxyServer) Stop() {
	logger := log.GetLogger()

	if err := c.tcpListener_.Close(); err != nil {
		logger.Error("ProxyServer stop tcp failed", zap.String("listenAddr", c.listenAddr), zap.String("error", err.Error()))
	}
	if err := c.udpListener_.Close(); err != nil {
		logger.Error("ProxyServer stop udp failed", zap.String("listenAddr", c.listenAddr), zap.String("error", err.Error()))
	}

	if c.kcpServer != nil {
		c.kcpServer.Stop()
	}
	logger.Info("ProxyServer stopped", zap.String("listenAddr", c.listenAddr))

}

func (c *ProxyServer) startTcpListener() (err error) {
	logger := log.GetLogger()

	if c.tcpListener_, err = net.Listen("tcp4", c.listenAddr); err != nil {
		err = errors.Wrap(err, "TCP listen failed")
		return
	}
	logger.Info("TCP Listener started", zap.String("listenAddr", c.listenAddr))
	go c.startTCPAccept()
	return
}

func (c *ProxyServer) startTCPAccept() {
	logger := log.GetLogger()
	for {
		if conn, err := c.tcpListener_.Accept(); err != nil {
			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection" {
				logger.Debug("Tcp accept failed", zap.String("error", err.Error()))
			}
		} else {
			go c.handleTCP(conn)
		}
	}
	logger.Info("TCP listen stopped", zap.String("listenAddr", c.listenAddr))
}

func (c *ProxyServer) handleUDPOverTCP(conn net.Conn, dstAddrBytes socks.Addr) {
	logger := log.GetLogger()
	dstAddr, err := net.ResolveUDPAddr("udp", common.AddrToString(dstAddrBytes))
	if err != nil {
		logger.Error("tcp resolve udp address failed", zap.String("error", err.Error()))
		return
	}
	remoteConn, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		logger.Error("tcp UDP dial remote address failed", zap.String("addr", dstAddr.String()), zap.String("error", err.Error()))
		return
	}
	go func() {
		copyBuffer := c.udpLeakyBuffer.Get()
		defer func() {
			logger.Debug("udp over tcp endpoint exit", zap.String("dst", dstAddr.String()))
			defer remoteConn.Close()
			conn.SetReadDeadline(time.Now())
			c.udpLeakyBuffer.Put(copyBuffer)
		}()
		for {
			copyBuffer = copyBuffer[:cap(copyBuffer)]
			dataLen, _, err := remoteConn.ReadFrom(copyBuffer)
			if err != nil {
				if err != io.EOF {
					if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
						logger.Error("tcp udp read from remote failed", zap.String("error", err.Error()))
					}
				}

				return
			}
			if _, err = common.WriteUdpOverTcp(conn, copyBuffer[:dataLen]); err != nil {
				logger.Error("tcp udp write back failed", zap.String("error", err.Error()))
				return
			}
			remoteConn.SetReadDeadline(time.Now().Add(c.udpTimeout_))
		}

	}()

	buffer := c.udpLeakyBuffer.Get()
	defer c.udpLeakyBuffer.Put(buffer)
	var packetSize int
	defer remoteConn.SetReadDeadline(time.Now())
	for err == nil {
		buffer = buffer[:cap(buffer)]
		if packetSize, err = common.ReadUdpOverTcp(conn, buffer); err != nil {
			if err != io.EOF {
				if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
					logger.Error("read UDP over TCP failed", zap.String("addr", dstAddr.String()), zap.Int("packetSize", packetSize), zap.String("error", err.Error()))
				}
				return
			}
		}
		if _, err = remoteConn.Write(buffer[:packetSize]); err != nil {
			logger.Error("tcp write udp to remote failed", zap.String("addr", dstAddr.String()), zap.String("error", err.Error()))
			return
		}
		remoteConn.SetReadDeadline(time.Now().Add(c.udpTimeout_))
	}

}

func (c *ProxyServer) handleTCP(conn net.Conn) {
	logger := log.GetLogger()
	defer conn.Close()

	conn.(*net.TCPConn).SetKeepAlive(true)
	conn = c.cipher.StreamConn(conn)
	//conn.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))

	isUDP, dstAddr, err := common.ReadShadowsocksHeader(conn)
	if err != nil {
		logger.Error("TCP read dst addr failed", zap.String("error", err.Error()))
		return
	}
	if isUDP {
		c.handleUDPOverTCP(conn, dstAddr)
	} else {
		remoteConn, err := net.Dial("tcp", dstAddr.String())
		if err != nil {
			logger.Info("TCP dial dst failed", zap.String("error", err.Error()))
			return
		}
		//logger.Debug("tcp dial remote", zap.String("addr", dstAddr.String()))
		defer remoteConn.Close()
		//remoteConn.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))
		remoteConn.(*net.TCPConn).SetKeepAlive(true)

		// starting relay data
		ch := make(chan res)

		go func() {
			outboundSize, err := io.Copy(remoteConn, conn)
			remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
			conn.SetDeadline(time.Now())       // wake up the other goroutine blocking on left
			ch <- res{outboundSize, err}
		}()

		inboundSize, err := io.Copy(conn, remoteConn)
		remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		conn.SetDeadline(time.Now())       // wake up the other goroutine blocking on left
		rs := <-ch

		if err == nil {
			err = rs.Err
		}

		if err != nil {
			if ee, ok := err.(net.Error); ok && ee.Timeout() {
				logger.Debug("TCP relay successful", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
			} else {
				logger.Error("TCP relay failed", zap.String("error", err.Error()))
			}
		} else {
			logger.Debug("TCP relay successful", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
		}
	}

}

func (c *ProxyServer) startUDPListener() (err error) {
	logger := log.GetLogger()

	if c.udpListener_, err = net.ListenPacket("udp4", c.listenAddr); err != nil {
		err = errors.Wrap(err, "UDP listen failed")
		return
	}
	c.udpListener_ = c.cipher.PacketConn(c.udpListener_)

	logger.Info("UDP Listener started", zap.String("listenAddr", c.listenAddr))

	go c.startUDPAccept()

	return
}
func (c *ProxyServer) startUDPAccept() {
	logger := log.GetLogger()
	for {
		buffer := c.udpLeakyBuffer.Get()
		if dataLen, srcAddr, err := c.udpListener_.ReadFrom(buffer); err != nil {
			c.udpLeakyBuffer.Put(buffer)
			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection" {
				logger.Info("UDP Read failed", zap.String("error", err.Error()))
			}

		} else {
			logger.Debug("Read udp ", zap.String("srcAddr", srcAddr.String()))
			go c.handleUDP(buffer, dataLen, srcAddr)
		}
	}
	logger.Info("UDP listener stopped", zap.String("listenAddr", c.listenAddr))
}

func (c *ProxyServer) handleUDP(buffer []byte, dataLen int, srcAddr net.Addr) {
	logger := log.GetLogger()

	defer c.udpLeakyBuffer.Put(buffer)

	dstAddrBytes := socks.SplitAddr(buffer[:dataLen])
	if dstAddrBytes == nil {
		logger.Error("UDP dst addr is nil")
		return
	}

	dstAddr, err := net.ResolveUDPAddr("udp", dstAddrBytes.String())
	if err != nil {
		logger.Error("UDP resolve dst addr failed", zap.String("error", err.Error()))
		return
	}

	logger.Debug("Handle UDP ", zap.String("src", srcAddr.String()), zap.String("dst", dstAddr.String()))
	keyStr := fmt.Sprintf("%s->%s", srcAddr.String(), dstAddr.String())

	c.udpNatMap_.Lock()
	defer c.udpNatMap_.Unlock()

	remoteConnEntry := c.udpNatMap_.Get(keyStr)
	if remoteConnEntry == nil {
		remoteConn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			logger.Error("UDP open dial failed", zap.String("error", err.Error()))
			return
		}
		remoteConnEntry = c.udpNatMap_.Add(keyStr, remoteConn, dstAddrBytes)
		go c.copyFromRemote(remoteConnEntry, keyStr, dstAddr, srcAddr)
	}
	if _, err = remoteConnEntry.conn.WriteTo(buffer[len(dstAddrBytes):dataLen], dstAddr); err != nil {
		// something failed, so delete this entry
		c.udpNatMap_.Del(keyStr)
		logger.Error("UPD write to remote failed", zap.String("error", err.Error()))
	} else {
		remoteConnEntry.conn.SetReadDeadline(time.Now().Add(c.udpTimeout_))
		logger.Debug("UDP write to remote successful", zap.String("dst", dstAddr.String()))
	}

}

func (c *ProxyServer) copyFromRemote(entry *udpNatMapEntry, keyStr string, dstAddr *net.UDPAddr, srcAddr net.Addr) {
	logger := log.GetLogger()

	defer c.udpNatMap_.Unlock()
	defer entry.conn.Close()
	defer c.udpNatMap_.Del(keyStr)
	defer c.udpNatMap_.Lock()

	remoteBuffer := c.udpLeakyBuffer.Get()
	defer c.udpLeakyBuffer.Put(remoteBuffer)

	for {
		// let dns query fast expire
		remoteBuffer = remoteBuffer[:cap(remoteBuffer)]
		if dataLen, _, err := entry.conn.ReadFrom(remoteBuffer); err != nil {
			if ee, ok := err.(net.Error); !ok || !ee.Timeout() {
				logger.Error("UDP read from remote failed", zap.String("error", err.Error()))

			}
			return
		} else {
			// lets write back
			headerLen := len(entry.header)
			totalLen := dataLen + headerLen
			if totalLen > common.UDP_BUFFER_SIZE {
				writeBuffer := make([]byte, totalLen)
				copy(writeBuffer, entry.header)
				copy(writeBuffer[headerLen:], remoteBuffer[:dataLen])
				if _, err = c.udpListener_.WriteTo(writeBuffer, srcAddr); err != nil {
					logger.Error("UDP write back failed", zap.String("error", err.Error()))
					return
				}
			} else {
				writeBuffer := c.udpLeakyBuffer.Get()
				copy(writeBuffer, entry.header)
				copy(writeBuffer[headerLen:], remoteBuffer[:dataLen])
				if _, err = c.udpListener_.WriteTo(writeBuffer[:totalLen], srcAddr); err != nil {
					c.udpLeakyBuffer.Put(writeBuffer)
					logger.Error("UDP write back failed", zap.String("error", err.Error()))
					return
				} else {
					c.udpLeakyBuffer.Put(writeBuffer)
				}
			}
			logger.Debug("UDP write back to successful", zap.String("addr", srcAddr.String()))
		}
		entry.conn.SetReadDeadline(time.Now().Add(c.udpTimeout_))

	}
}
