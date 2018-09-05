package proxy_client

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"go.uber.org/zap"
	"io"
	"net"
	"sync"
	"time"
)

type proxyBackend struct{
	cipher_      	core.Cipher
	addr_        	net.TCPAddr
	networkType_ 	string
	tcpTimeout_  	time.Duration
	udpTimeout_  	time.Duration
	udpNatMap_		*udpNatMap
}

type relayDataRes struct {
	N   int64
	Err error
}


type udpProxyEntry struct{
	src_    	net.PacketConn
	dst_     	net.PacketConn
	srcAddr_	*net.UDPAddr
	header_		[]byte
	timeout		time.Duration

}
func createUDPProxyEntry(src net.PacketConn, dst net.PacketConn, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, timeout time.Duration) (*udpProxyEntry, error) {
	addr, err := network.ConvertShadowSocksAddr(dstAddr.String())
	if err != nil{
		return nil, err
	}
	return &udpProxyEntry{src, dst, srcAddr, addr, timeout}, nil
}

func (c *udpProxyEntry) copyFromRemote() error{
	buffer := make([]byte, common.UDP_BUFFER_SIZE)
	for {
		c.dst_.SetReadDeadline(time.Now().Add(c.timeout))
		n, _, err := c.dst_.ReadFrom(buffer)

		if err != nil{
			return err
		}
		// should check header

		if _, err = c.src_.WriteTo(buffer[len(c.header_):n], c.srcAddr_); err != nil{
			return err
		}

	}
}

type udpNatMap struct{
	sync.RWMutex
	entries		map[string]*udpProxyEntry
}

func (c *udpNatMap) Add(key string, entry *udpProxyEntry){
	c.Lock()
	defer c.Unlock()
	c.entries[key] = entry
}
func (c *udpNatMap) Del(key string){
	c.Lock()
	defer c.Unlock()
	delete(c.entries, key)
}
func (c *udpNatMap) Get(key string) *udpProxyEntry{
	c.RLock()
	defer c.RUnlock()
	if entry, ok := c.entries[key]; ok {
		return entry
	}else{
		return nil
	}
}

func computeUDPKey(src *net.UDPAddr, dst *net.UDPAddr) string{
	return fmt.Sprintf("%s->%s", src.String(), dst.String())
}


func CreateProxyBackend(config config.RemoteServerConfig, tcpTimeout int, udpTimeout int) (ret *proxyBackend, err error){

	ret = &proxyBackend{}
	ret.tcpTimeout_ = time.Second * time.Duration(tcpTimeout)
	ret.udpTimeout_ = time.Second * time.Duration(udpTimeout)

	var isIPv6 bool
	if isIPv6, err = network.CheckIPFamily(config.RemoteServer); err != nil{
		err = errors.Wrap(err, fmt.Sprintf("Invalid IP format: %s", config.RemoteServer))
		return
	}
	if isIPv6 {
		ret.networkType_ = "tcp4"
	}else{
		ret.networkType_ = "tcp6"
	}
	if ip, port, ee := network.ParseAddr(config.RemoteServer, isIPv6); ee != nil{
		err = errors.Wrap(ee, "Parse IPv4 failed")
		return
	}else{
		ret.addr_ = net.TCPAddr{IP: ip, Port: port}
	}


	if ret.cipher_, err = core.PickCipher(config.Crypt, []byte{}, config.Password); err != nil{
		err = errors.Wrap(err, "Generate cipher failed")
		return
	}

	ret.udpNatMap_ = &udpNatMap{entries: make(map[string]*udpProxyEntry)}

	return
}

func (c *proxyBackend) createTCPConn() (conn net.Conn, err error){

	conn, err = net.DialTCP(c.networkType_, nil, &c.addr_)
	if err != nil{
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)

	conn = c.cipher_.StreamConn(conn)

	return

}

func (c *proxyBackend) RelayTCPData(src net.Conn) (int64, int64, error){
	defer src.Close()

	originDst, err := network.ConvertShadowSocksAddr(src.LocalAddr().String())
	if err != nil{
		return 0, 0, errors.Wrap(err, "Parse origin dst failed")
	}

	dst, err := c.createTCPConn()
	if err != nil{
		return 0, 0, errors.Wrap(err,"Create remote conn failed")
	}
	defer dst.Close()

	// set deadline timeout
	dst.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))
	src.SetWriteDeadline(time.Now().Add(c.tcpTimeout_))

	if _, err = dst.Write(originDst); err != nil{
		return 0, 0, errors.Wrap(err, "Write to remote server failed")
	}

	ch := make(chan relayDataRes)

	go func() {
		n, err := io.Copy(dst, src)
		dst.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		src.SetDeadline(time.Now()) // wake up the other goroutine blocking on left
		ch <- relayDataRes{n, err}
	}()

	n, err := io.Copy(src, dst)
	dst.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	src.SetDeadline(time.Now()) // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}

	return n, rs.N, err
}

func (c *proxyBackend) RelayUDPData(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, leakyBuffer *common.LeakyBuffer, data *bytes.Buffer, dataLen int) error{
	logger := log.GetLogger()

	udpKey := computeUDPKey(srcAddr, dstAddr)

	udpProxy := c.udpNatMap_.Get(udpKey)

	if udpProxy == nil{
		dstConn, err := net.ListenPacket("udp", "")
		if err != nil{
			return errors.Wrap(err, "UDP proxy listen local failed")
		}
		dstConn = c.cipher_.PacketConn(dstConn)

		srcConn, err := network.DialTransparentUDP(srcAddr)
		if err != nil{
			dstConn.Close()
			return errors.Wrap(err, "UDP proxy listen using transparent failed")
		}
		if udpProxy, err = createUDPProxyEntry(srcConn, dstConn, srcAddr, dstAddr, c.udpTimeout_); err != nil{
			dstConn.Close()
			srcConn.Close()
			return errors.Wrap(err,"Create udp proxy entry failed")
		}

		// now lets run copy from dst
		go func(){
			c.udpNatMap_.Add(udpKey, udpProxy)
			if err := udpProxy.copyFromRemote(); err != nil{
				logger.Debug("Proxy UDP from dst to local stopped", zap.String("error", err.Error()))
			}
			c.udpNatMap_.Del(udpKey)

			udpProxy.src_.Close()
			udpProxy.dst_.Close()
		}()
	}

	// compose udp socks5 header
	udpProxy.dst_.SetReadDeadline(time.Now().Add(c.udpTimeout_))

	headerLen := len(udpProxy.header_)
	totalLen := headerLen + dataLen

	if totalLen > leakyBuffer.GetBufferSize(){
		// too big for our leakybuffer
		writeData := make([]byte, totalLen)
		copy(writeData, udpProxy.header_)
		copy(writeData[headerLen:], data.Bytes()[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dst_.WriteTo(writeData, dstAddr); err != nil{
			return err
		}

	}else{
		// get leaky buffer
		newBuffer := leakyBuffer.Get()
		defer leakyBuffer.Put(newBuffer)

		copy(newBuffer.Bytes(), udpProxy.header_)
		copy(newBuffer.Bytes()[headerLen:], data.Bytes()[:dataLen])
		// set timeout for each send
		// write to remote shadowsocks server
		if _, err := udpProxy.dst_.WriteTo(newBuffer.Bytes(), dstAddr); err != nil{
			return err
		}
	}


	return nil
}