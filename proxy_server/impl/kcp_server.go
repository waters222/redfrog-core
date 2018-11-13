package impl

import (
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/weishi258/kcp-go-ng"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/kcp_helper"
	"github.com/weishi258/redfrog-core/log"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
	"io"
	"net"
	"time"
)

type KCPServer struct {
	config         config.KcptunConfig
	cipher         kcp.AheadCipher
	listener       *kcp.Listener
	tcpTimeout     time.Duration
	udpTimeout     time.Duration
	udpLeakyBuffer *common.LeakyBuffer
}

func StartKCPServer(config config.KcptunConfig, crypt string, password string, udpLeakyBuffer *common.LeakyBuffer, tcpTimeoutValue int, udpTimeoutValue int) (ret *KCPServer, err error) {
	logger := log.GetLogger()
	ret = &KCPServer{}
	ret.config = config
	ret.config.Nodelay, ret.config.Interval, ret.config.Resend, ret.config.NoCongestion = kcp_helper.GetModeSetting(ret.config.Mode,
		ret.config.Nodelay,
		ret.config.Interval,
		ret.config.Resend,
		ret.config.NoCongestion)
	ret.tcpTimeout = time.Second * time.Duration(tcpTimeoutValue)
	ret.udpTimeout = time.Second * time.Duration(udpTimeoutValue)
	ret.udpLeakyBuffer = udpLeakyBuffer

	if ret.cipher, err = kcp_helper.GetCipher(crypt, password); err != nil {
		err = errors.Wrap(err, "Create Kcp cipher failed")
		return
	}

	if ret.listener, err = kcp.ListenWithOptionsAhead(ret.config.ListenAddr, config.ThreadCount, ret.cipher, ret.config.Datashard, ret.config.Parityshard); err != nil {
		err = errors.Wrap(err, "Kcp Listen failed")
		return
	}
	//if err = ret.listener.SetDSCP(ret.config.Dscp); err != nil {
	//	logger.Warn("Set DSCP failed", zap.String("error", err.Error()))
	//}
	if err = ret.listener.SetReadBuffer(ret.config.Sockbuf); err != nil {
		ret.listener.Close()
		err = errors.Wrap(err, "Kcp set ReadBuffer failed")
		return
	}
	if err = ret.listener.SetWriteBuffer(ret.config.Sockbuf); err != nil {
		ret.listener.Close()
		err = errors.Wrap(err, "Kcp set WriteBuffer failed")
		return
	}

	go ret.startAccept()
	logger.Info("Kcp server started at addr", zap.String("addr", ret.config.ListenAddr))
	return
}

func (c *KCPServer) Stop() {
	logger := log.GetLogger()
	if err := c.listener.Close(); err != nil {
		logger.Error("Kcp stop failed", zap.String("error", err.Error()))
	}
	logger.Info("Kcp server stopped")
}

func (c *KCPServer) startAccept() {
	logger := log.GetLogger()
	for {
		if conn, err := c.listener.AcceptKCP(); err != nil {
			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection" {
				logger.Info("Kcp accept failed", zap.String("error", err.Error()))
			}
		} else {
			conn.SetStreamMode(true)
			conn.SetWriteDelay(true)
			conn.SetNoDelay(c.config.Nodelay, c.config.Interval, c.config.Resend, c.config.NoCongestion)
			conn.SetMtu(c.config.Mtu)
			conn.SetWindowSize(c.config.Sndwnd, c.config.Rcvwnd)
			conn.SetACKNoDelay(c.config.Acknodelay)

			if c.config.Nocomp {
				go c.handleConnection(conn)
			} else {
				go c.handleConnection(kcp_helper.NewCompStream(conn))
			}
		}
	}
}
func (c *KCPServer) handleConnection(conn io.ReadWriteCloser) {
	logger := log.GetLogger()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = c.config.Sockbuf
	smuxConfig.KeepAliveInterval = time.Duration(c.config.KeepAliveInterval) * time.Second
	smuxConfig.KeepAliveTimeout = time.Duration(c.config.KeepAliveTimeout) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		logger.Error("Kcp server mux failed", zap.String("error", err.Error()))
		return
	}
	defer mux.Close()
	for {
		if kcpConn, err := mux.AcceptStream(); err != nil {
			logger.Debug("Kcp server accept stream stopped", zap.String("error", err.Error()))
			return
		} else {
			go c.handleRelay(kcpConn)
		}
	}
}

func (c *KCPServer) handleUDPOverTCP(conn *smux.Stream, dstAddrBytes socks.Addr) {
	logger := log.GetLogger()
	dstAddr, err := net.ResolveUDPAddr("udp", common.AddrToString(dstAddrBytes))
	if err != nil {
		logger.Error("kcp resolve udp address failed", zap.String("error", err.Error()))
		return
	}
	remoteConn, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		logger.Error("kcp UDP dial remote address failed", zap.String("addr", dstAddr.String()), zap.String("error", err.Error()))
		return
	}

	go func() {
		copyBuffer := c.udpLeakyBuffer.Get()
		defer func() {
			logger.Debug("udp over kcp endpoint exit", zap.String("dst", dstAddr.String()))
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
						logger.Error("kcp UDP read from remote failed", zap.String("error", err.Error()))
					}
				}
				return
			}
			if _, err = common.WriteUdpOverTcp(conn, copyBuffer[:dataLen]); err != nil {
				logger.Error("kcp UDP write back failed", zap.String("error", err.Error()))
				return
			}
			remoteConn.SetReadDeadline(time.Now().Add(c.udpTimeout))
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
					logger.Error("Read UDP over kcp failed", zap.String("addr", dstAddr.String()), zap.Int("packetSize", packetSize), zap.String("error", err.Error()))
				}
			}
			return
		}
		if packetSize > 0 {
			if _, err = remoteConn.Write(buffer[:packetSize]); err != nil {
				logger.Error("kcp write udp to remote failed", zap.String("addr", dstAddr.String()), zap.String("error", err.Error()))
				return
			}
		}

		remoteConn.SetReadDeadline(time.Now().Add(c.udpTimeout))
	}

}

func (c *KCPServer) handleRelay(kcpConn *smux.Stream) {
	logger := log.GetLogger()

	defer kcpConn.Close()

	isUDP, dstAddr, err := common.ReadShadowsocksHeader(kcpConn)
	if err != nil {
		logger.Error("Kcp read dst addr failed", zap.String("error", err.Error()))
		return
	}
	if isUDP {
		c.handleUDPOverTCP(kcpConn, dstAddr)
	} else {

		remoteConn, err := net.Dial("tcp", dstAddr.String())
		if err != nil {
			logger.Info("Kcp dial dst failed", zap.String("error", err.Error()))
			return
		}
		//logger.Debug("tcp dial remote", zap.String("addr", dstAddr.String()))
		defer remoteConn.Close()
		remoteConn.SetWriteDeadline(time.Now().Add(c.tcpTimeout))
		remoteConn.(*net.TCPConn).SetKeepAlive(true)

		// starting relay data
		ch := make(chan res)

		go func() {
			outboundSize, err := io.Copy(remoteConn, kcpConn)
			remoteConn.SetDeadline(time.Now())
			kcpConn.SetDeadline(time.Now())

			//remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
			//kcpConn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
			ch <- res{outboundSize, err}
		}()

		inboundSize, err := io.Copy(kcpConn, remoteConn)
		remoteConn.SetDeadline(time.Now())
		kcpConn.SetDeadline(time.Now())

		//remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		//kcpConn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		rs := <-ch

		if err == nil {
			err = rs.Err
		}
		if err != nil {
			logger.Debug("Kcp relay finished", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize), zap.String("error", err.Error()))
		} else {
			logger.Debug("Kcp relay finished", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
		}
	}

}
