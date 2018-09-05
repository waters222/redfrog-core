package main

import (
	"bytes"
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
	tcpListener_			net.Listener
	udpListener_			net.PacketConn
	tcpTimeout_				time.Duration
	udpTimeout_				time.Duration
	cipher					core.Cipher
	port					int
	udpLeakyBuffer			*common.LeakyBuffer
	udpNatMap_				*udpNatMap
}

type res struct {
	OutboundSize   int64
	Err error
}

type udpNatMapEntry struct {
	conn			*net.UDPConn
	header			[]byte
}

type udpNatMap struct {
	sync.RWMutex
	entries		map[string]*udpNatMapEntry
}
func NewNatMap() *udpNatMap{
	ret := &udpNatMap{}
	ret.entries = make(map[string]*udpNatMapEntry)

	return ret
}

func (c *udpNatMap)Get(key string) *udpNatMapEntry {
	c.RLock()
	defer c.RUnlock()
	if entry, ok := c.entries[key]; ok {
		return entry
	}else{
		return nil
	}
}

func (c *udpNatMap)Del(key string)  {
	c.Lock()
	defer c.Unlock()
	delete(c.entries, key)
}


func (c *udpNatMap)Add(key string, conn *net.UDPConn, header []byte){
	c.Lock()
	defer c.Unlock()
	c.entries[key] = &udpNatMapEntry{conn, header}
}


func StartProxyServer(config config.ServerConfig) (ret *ProxyServer, err error) {
	ret = &ProxyServer{}

	ret.tcpTimeout_ = time.Second * time.Duration( config.TcpTimeout)
	ret.udpTimeout_ = time.Second * time.Duration(config.UdpTimeout)
	ret.port = config.ListenPort
	ret.udpLeakyBuffer = common.NewLeakyBuffer(common.UDP_BUFFER_POOL_SIZE * 4, common.UDP_BUFFER_SIZE)

	ret.udpNatMap_ = NewNatMap()

	if ret.cipher, err = core.PickCipher(config.Crypt, []byte{}, config.Password); err != nil{
		err = errors.Wrap(err, "Pick cipher failed")
		return
	}
	if err = ret.startTcpListener(); err != nil{
		err = errors.Wrap(err, "TCP listener start failed")
		return
	}
	if err = ret.startUDPListener(); err != nil{
		ret.tcpListener_.Close()
		err = errors.Wrap(err, "UDP listener start failed")
		return
	}


	return ret, nil
}



func (c *ProxyServer)Stop(){
	logger := log.GetLogger()


	if err := c.tcpListener_.Close(); err != nil{
		logger.Error("ProxyServer stop tcp failed", zap.Int("port", c.port), zap.String("error", err.Error()))
	}
	if err := c.udpListener_.Close(); err != nil{
		logger.Error("ProxyServer stop udp failed", zap.Int("port", c.port), zap.String("error", err.Error()))
	}

	logger.Info("ProxyServer stopped", zap.Int("port", c.port))


}

func (c *ProxyServer)startTcpListener() (err error){
	logger := log.GetLogger()

	if c.tcpListener_, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d",c.port)); err != nil{
		err = errors.Wrap(err, "TCP listen failed")
		return
	}
	logger.Info("TCP Listener started", zap.Int("port", c.port))
	go c.startTCPAccept()
	return
}

func (c *ProxyServer)startTCPAccept(){
	logger := log.GetLogger()
	for{
		if conn, err := c.tcpListener_.Accept(); err != nil{
			if err.(*net.OpError).Err.Error() != "use of closed network connection"{
				logger.Error("Tcp accept failed", zap.String("error", err.Error()))
			}else{
				return
			}
		}else{
			go c.handleTCP(conn)
		}
	}
	logger.Info("TCP listen stopped", zap.Int("port", c.port))
}

func (c *ProxyServer)handleTCP(conn net.Conn){
	logger := log.GetLogger()
	defer conn.Close()

	conn.(*net.TCPConn).SetKeepAlive(true)
	conn = c.cipher.StreamConn(conn)
	conn.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))

	dstAddr, err := socks.ReadAddr(conn)
	if err != nil{
		logger.Error("TCP read dst addr failed", zap.String("error", err.Error()))
		return
	}
	remoteConn, err := net.Dial("tcp", dstAddr.String())
	if err != nil{
		logger.Info("TCP dial dst failed", zap.String("error", err.Error()))
		return
	}
	//logger.Debug("tcp dial remote", zap.String("addr", dstAddr.String()))
	defer remoteConn.Close()
	remoteConn.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))
	remoteConn.(*net.TCPConn).SetKeepAlive(true)

	// starting relay data
	ch := make(chan res)

	go func() {
		outboundSize, err := io.Copy(remoteConn, conn)
		remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		conn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{outboundSize, err}
	}()

	inboundSize, err := io.Copy(conn, remoteConn)
	remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	conn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}

	if err != nil {
		if ee, ok := err.(net.Error); ok && ee.Timeout() {
			return // ignore i/o timeout
		}else{
			logger.Error("TCP relay failed", zap.String("error", err.Error()))
		}

	}else{
		logger.Debug("TCP relay successful", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
	}
}

func (c *ProxyServer)startUDPListener() (err error){
	logger := log.GetLogger()

	if c.udpListener_, err = net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d",c.port)); err != nil{
		err = errors.Wrap(err, "UDP listen failed")
		return
	}
	c.udpListener_ = c.cipher.PacketConn(c.udpListener_)

	logger.Info("UDP Listener started", zap.Int("port", c.port))

	go c.startUDPListener()

	return
}
func (c *ProxyServer)startUDPAccept(){
	logger := log.GetLogger()
	for{
		buffer := c.udpLeakyBuffer.Get()
		if dataLen, srcAddr, err := c.udpListener_.ReadFrom(buffer.Bytes()); err != nil{
			c.udpLeakyBuffer.Put(buffer)
			if err.(*net.OpError).Err.Error() != "use of closed network connection"{
				logger.Error("Read from udp failed", zap.String("error", err.Error()))
			}else{
				return
			}

		}else{
			go c.handleUDP(buffer, dataLen, srcAddr)
		}
	}
	logger.Info("UDP listener stopped", zap.Int("port", c.port))
}

func (c *ProxyServer) handleUDP(buffer *bytes.Buffer, dataLen int, srcAddr net.Addr) {
	logger := log.GetLogger()

	defer c.udpLeakyBuffer.Put(buffer)

	dstAddrBytes := socks.SplitAddr(buffer.Bytes()[:dataLen])
	if dstAddrBytes == nil{
		logger.Error("UDP dst addr is nil")
		return
	}

	dstAddr, err := net.ResolveUDPAddr("udp", dstAddrBytes.String())
	if err != nil{
		logger.Error("UDP resolve dst addr failed", zap.String("error", err.Error()))
		return
	}
	remoteConnEntry := c.udpNatMap_.Get(dstAddr.String())

	if remoteConnEntry == nil{
		remoteConn, err := net.DialUDP("udp", nil, dstAddr)
		if err != nil{
			logger.Error("UDP open dial failed", zap.String("error", err.Error()))
			return
		}
		c.udpNatMap_.Add(dstAddr.String(), remoteConn, dstAddrBytes)
		go c.copyFromRemote(remoteConn, dstAddr, dstAddrBytes)
	}

	remoteConnEntry.conn.SetReadDeadline(time.Now().Add(c.udpTimeout_))
	_, err = remoteConnEntry.conn.WriteTo(buffer.Bytes()[len(dstAddrBytes):dataLen], dstAddr)
	if err != nil {
		logger.Error("UDP write to remote failed", zap.String("error", err.Error()))
	}
}

func (c *ProxyServer)copyFromRemote(remoteConn *net.UDPConn, dstAddr *net.UDPAddr, dstAddrBytes []byte){
	logger := log.GetLogger()

	remoteBuffer := c.udpLeakyBuffer.Get()
	defer c.udpLeakyBuffer.Put(remoteBuffer)
	defer remoteConn.Close()
	defer c.udpNatMap_.Del(dstAddr.String())

	for{
		remoteConn.SetReadDeadline(time.Now().Add(c.udpTimeout_))
		dataLen, _, err := remoteConn.ReadFrom(remoteBuffer.Bytes())
		if err != nil{
			logger.Debug("UDP read from remote failed", zap.String("error", err.Error()))
			return
		}
		// lets write back
		headerLen := len(dstAddrBytes)
		totalLen := dataLen + headerLen
		if totalLen > common.UDP_BUFFER_SIZE{
			writeBuffer := make([]byte, totalLen)
			copy(writeBuffer, dstAddrBytes)
			copy(writeBuffer[headerLen:], remoteBuffer.Bytes()[:dataLen])
			if _, err = c.udpListener_.WriteTo(writeBuffer, dstAddr); err != nil{
				logger.Error("Write back failed", zap.String("error", err.Error()))
				return
			}
		}else{
			writeBuffer := c.udpLeakyBuffer.Get()
			copy(writeBuffer.Bytes(), dstAddrBytes)
			copy(writeBuffer.Bytes()[headerLen:], remoteBuffer.Bytes()[:dataLen])
			if _, err = c.udpListener_.WriteTo(writeBuffer.Bytes(), dstAddr); err != nil{
				logger.Error("Write back failed", zap.String("error", err.Error()))
				return
			}
		}
	}
}
