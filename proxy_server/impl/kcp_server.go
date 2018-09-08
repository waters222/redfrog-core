package impl

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/kcp_helper"
	"github.com/weishi258/redfrog-core/log"
	"github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
	"io"
	"net"
	"time"
)

type KCPServer struct {
	config 			config.KcptunConfig
	cipher			kcp.BlockCrypt
	listener		*kcp.Listener
	timeout			time.Duration

}

func StartKCPServer(config config.KcptunConfig, crypt string, password string, timeoutValue int) (ret *KCPServer, err error){
	logger := log.GetLogger()
	ret = &KCPServer{}
	ret.config = config
	ret.config.Nodelay, ret.config.Interval, ret.config.Resend, ret.config.NoCongestion = kcp_helper.GetModeSetting(ret.config.Mode,
		ret.config.Nodelay,
		ret.config.Interval,
		ret.config.Resend,
		ret.config.NoCongestion)
	ret.timeout = time.Second * time.Duration(timeoutValue)

	if ret.cipher, err  = kcp_helper.GetCipher(crypt, password); err != nil{
		err = errors.Wrap(err, "Create Kcp cipher failed")
		return
	}


	if ret.listener, err = kcp.ListenWithOptions(fmt.Sprintf("0.0.0.0:%d", ret.config.ListenPort), ret.cipher, ret.config.Datashard, ret.config.Parityshard); err != nil{
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
	logger.Info("Kcp server started at port", zap.Int("addr", ret.config.ListenPort))
	return
}


func (c *KCPServer)Stop(){
	logger := log.GetLogger()
	if err := c.listener.Close(); err != nil{
		logger.Error("Kcp stop failed", zap.String("error", err.Error()))
	}
	logger.Info("Kcp server stopped")
}

func (c *KCPServer)startAccept(){
	logger := log.GetLogger()
	for{
		if conn, err := c.listener.AcceptKCP(); err != nil{
			if ee, ok := err.(*net.OpError); ok && ee != nil && ee.Err.Error() != "use of closed network connection"{
				logger.Info("Kcp accept failed", zap.String("error", err.Error()))
			}
		}else{
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
func (c *KCPServer) handleConnection(conn io.ReadWriteCloser){
	logger := log.GetLogger()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = c.config.Sockbuf
	smuxConfig.KeepAliveInterval = time.Duration(c.config.KeepAlive) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		logger.Error("Kcp server mux failed", zap.String("error", err.Error()))
		return
	}
	defer mux.Close()
	for {
		if kcpConn, err := mux.AcceptStream(); err != nil{
			if err.Error() != "broken pipe"{
				logger.Error("Kcp server accept stream failed", zap.String("error", err.Error()))
			}
			return
		}else{
			go c.handleRelay(kcpConn)
		}
	}
}
func (c *KCPServer)handleRelay(kcpConn *smux.Stream) {
	logger := log.GetLogger()

	defer kcpConn.Close()

	dstAddr, err := socks.ReadAddr(kcpConn)
	if err != nil{
		logger.Error("Kcp read dst addr failed", zap.String("error", err.Error()))
		return
	}

	remoteConn, err := net.Dial("tcp", dstAddr.String())
	if err != nil{
		logger.Info("Kcp dial dst failed", zap.String("error", err.Error()))
		return
	}
	//logger.Debug("tcp dial remote", zap.String("addr", dstAddr.String()))
	defer remoteConn.Close()
	remoteConn.SetWriteDeadline(time.Now().Add(c.timeout))
	remoteConn.(*net.TCPConn).SetKeepAlive(true)

	// starting relay data
	ch := make(chan res)

	go func() {
		outboundSize, err := io.Copy(remoteConn, kcpConn)
		remoteConn.SetDeadline(time.Now())
		kcpConn.Close()
		//remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		//kcpConn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{outboundSize, err}
	}()

	inboundSize, err := io.Copy(kcpConn, remoteConn)
	remoteConn.SetDeadline(time.Now())
	kcpConn.Close()
	//remoteConn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	//kcpConn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	if err != nil {
		if ee, ok := err.(net.Error); ok && ee.Timeout() {
			logger.Debug("Kcp relay successful", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
		}else if err.Error() == "broken pipe"{
			logger.Debug("Kcp relay successful", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
		}else{
			logger.Error("Kcp relay failed", zap.String("error", err.Error()))
		}
	}else{
		logger.Debug("Kcp relay successful", zap.Int64("inboundSize", inboundSize), zap.Int64("outboundSize", rs.OutboundSize))
	}
}
