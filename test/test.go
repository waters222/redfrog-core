package main

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"go.uber.org/zap"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//const (
//	SOL_IP = 0
//	IP_TRANSPARENT = 19
//)

var CONN_DEADLINE int


var Version string
var BuildTime string

var sigChan chan os.Signal

func main(){

	sigChan = make(chan os.Signal, 5)
	done := make(chan bool)

	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGKILL,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGINT)

	rand.Seed(time.Now().UnixNano())

	var printVer bool
	var logLevel string
	var mode string
	var addr string
	var msg 	string
	var repeatTime int
	var err error

	// parse parameters

	flag.BoolVar(&printVer, "version", false, "print server version")
	flag.StringVar(&mode, "m", "", "mode: client/server")
	flag.StringVar(&addr, "addr", "", "addr")
	flag.StringVar(&msg, "msg", "hello world", "send msg")
	flag.IntVar(&repeatTime, "r", 0, "repeat time in second")
	flag.IntVar(&CONN_DEADLINE, "timeout", 10, "timeout")
	flag.StringVar(&logLevel, "l", "info", "log level")
	flag.Parse()

	logger := log.InitLogger(logLevel, false)

	defer func(){
		if err != nil{
			logger.Error("Encounter critical error!", zap.String("error", err.Error()))
			os.Exit(1)
		}else{
			os.Exit(0)
		}
	}()

	// init logger

	var tcpListen net.Listener
	var udpListen *net.UDPConn

	var ticker *time.Ticker
	if mode == "client" {
		if repeatTime > 0{
			ticker = time.NewTicker(time.Second * time.Duration(repeatTime))
			logger.Info("Running client repeat mode", zap.Int("seconds", repeatTime), zap.Int("timeout", CONN_DEADLINE))
			go func(){
				for  range ticker.C{
					runClient(addr, msg)
				}
			}()
		}else{
			runClient(addr, msg)
			return
		}

	}else if mode == "server"{
		logger.Info("Running as server mode", zap.String("addr", addr), zap.Int("timeout", CONN_DEADLINE))
		if tcpListen, err = listenTcp(addr); err != nil{
			logger.Error("Listen TCP failed", zap.String("error", err.Error()))
			return
		}
		logger.Info("TCP listen successful")
		defer func() {
			tcpListen.Close()
			logger.Info("TCP listen closed")
		}()
		if udpListen, err = listenUdp(addr); err != nil{
			logger.Error("Listen UDP failed", zap.String("error", err.Error()))
			return
		}

		logger.Info("UDP listen successful")
		defer func() {
			udpListen.Close()
			logger.Info("TCP listen closed")
		}()

	}else{
		err = errors.New(fmt.Sprintf("Unknow mode type: %s", mode))
		return
	}




	logger.Info("RedFrog Test is started")
	go func() {
		sig := <-sigChan

		logger.Debug("RedFrog caught signal for exit",
			zap.Any("signal", sig))
		done <- true

		if ticker != nil{
			ticker.Stop()
		}
	}()
	<-done
}
func runClient(addr string, msg string){
	logger := log.GetLogger()
	var err error
	logger.Info("Running as client mode", zap.String("addr", addr))
	if err = writeTcp(addr, msg); err != nil{
		logger.Error("TCP Client failed", zap.String("error", err.Error()))
	}
	if err = writeUdp(addr, msg); err != nil{
		logger.Error("UDP Client failed", zap.String("error", err.Error()))
	}
}
func writeTcp(addr string, msg string) (err error){
	logger := log.GetLogger()

	var conn net.Conn
	dial := net.Dialer{Timeout: time.Second * time.Duration(CONN_DEADLINE)}
	if conn, err = dial.Dial("tcp", addr); err != nil{
		return
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(CONN_DEADLINE))); err != nil{
		return
	}

	var n int
	writeBuffer := []byte(msg)
	if n, err = conn.Write(writeBuffer); err != nil{
		return
	}
	if n < len(msg){
		err = errors.New("Write tcp less")
		return
	}

	lineBuffer := make([]byte, 4096)
	var readLen int
	if readLen, err = conn.Read(lineBuffer); err != nil{
		return
	}
	if !checkEqual(lineBuffer, writeBuffer, readLen){
		err = errors.New(fmt.Sprintf("TCP response is not equal: %s != %s", lineBuffer, writeBuffer))
		return
	}
	logger.Info("Tcp client test successful")

	return
}
func writeUdp(addr string, msg string) (err error){

	logger := log.GetLogger()

	var udpAddr *net.UDPAddr
	if udpAddr, err = net.ResolveUDPAddr("udp", addr); err != nil{
		return
	}
	var conn *net.UDPConn
	if conn, err = net.DialUDP("udp", nil, udpAddr); err != nil{
		return
	}
	defer conn.Close()
	//
	if err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(CONN_DEADLINE))); err != nil{
		return
	}

	writeBuffer := []byte(msg)
	var writeLen int
	if writeLen, err = conn.Write(writeBuffer); err != nil{
		logger.Error("UDP write failed", zap.String("error", err.Error()))
		return err
	}

	readBuffer := make([]byte, writeLen)
	var readLen int
	if n, remoteAddr, err := conn.ReadFromUDP(readBuffer); err != nil{
		logger.Error("Get udp response from server failed",zap.String("err", err.Error()))
		return err
	}else{
		logger.Error("Get udp response from server successful",zap.String("addr", remoteAddr.String()))
		readLen = n
	}
	if !checkEqual(readBuffer, writeBuffer, readLen){
		err = errors.New(fmt.Sprintf("UDP response is not equal: %s != %s", readBuffer, writeBuffer))
		return
	}
	logger.Info("UDP client test successful")
	return
}


func listenTcp(addr string) (ln net.Listener, err error){
	logger := log.GetLogger()

	if ln, err = network.ListenTransparentTCP(addr, false); err != nil{
		return
	}

	go func(){
		logger.Info("Listen TCP successful", zap.String("addr", addr))
		for{
			if conn, err := ln.Accept(); err != nil{
				logger.Debug("Accept tcp conn failed", zap.String("error", err.Error()))
			}else{
				go handleTcpConn(conn)
			}

		}
	}()

	return
}

func handleTcpConn(conn net.Conn){
	logger := log.GetLogger()
	defer conn.Close()


	if err := conn.SetDeadline(time.Now().Add(time.Second * time.Duration(CONN_DEADLINE))); err != nil{
		logger.Error("Set tcp conn deadline failed", zap.String("error", err.Error()))
		return
	}
	lineBuffer := make([]byte, 4096)
	var readLen int
	var err error
	if readLen, err = conn.Read(lineBuffer); err != nil{
		logger.Error("TCP read failed", zap.String("error", err.Error()))
		return
	}

	if n, err := conn.Write(lineBuffer[:readLen]); err != nil{
		logger.Error("Handle TCP failed", zap.String("remoteAddr", conn.RemoteAddr().String()), zap.String("localAddr", conn.(*net.TCPConn).LocalAddr().String()), zap.String("error", err.Error()))
	}else if n < readLen{
		logger.Error("Handle TCP failed, Write tcp less then expected", zap.String("remoteAddr", conn.RemoteAddr().String()), zap.String("localAddr", conn.(*net.TCPConn).LocalAddr().String()), zap.Int("n", n), zap.Int("expected", len(lineBuffer)))
	}else{
		logger.Info("Handle tcp successful", zap.String("remoteAddr", conn.RemoteAddr().String()), zap.String("localAddr", conn.(*net.TCPConn).LocalAddr().String()), zap.ByteString("msg", lineBuffer[:readLen]))
	}
}

func listenUdp(addr string) (ln *net.UDPConn, err error){
	logger := log.GetLogger()

	if ln, err = network.ListenTransparentUDP(addr, false); err != nil{
		return
	}
	go func(){
		logger.Info("Listen UDP successful", zap.String("addr", addr))
		for{
			udpBuffer := make([]byte, 4096)
			oob := make([]byte, 2048)
			if dataLen, src, dst, err := network.ReadFromTransparentUDP(ln, udpBuffer, oob); err != nil{
				logger.Debug("Read udp failed", zap.String("error", err.Error()))
			}else{
				go handleUdp(src, dst, udpBuffer[:dataLen])
			}
		}
	}()
	return
}

func handleUdp(src *net.UDPAddr, dst *net.UDPAddr, data []byte){
	logger := log.GetLogger()

	conn, err := network.DialTransparentUDP(dst, false)
	if err != nil{
		logger.Error("Can not create udp conn", zap.String("error", err.Error()))
		return
	}
	defer conn.Close()

	if _, err = conn.WriteToUDP(data, src); err != nil{
		logger.Error("Handle UDP failed", zap.String("src", src.String()), zap.String("dst", dst.String()), zap.String("error",err.Error()))
	}else{
		logger.Info("Handle UDP successful", zap.String("srcAddr", src.String()), zap.String("dstAddr", dst.String()), zap.ByteString("msg", data))
	}

}


func checkEqual(a []byte, b []byte, length int) bool{
	if (a == nil) != (b == nil) {
		return false;
	}
	if len(a) < length || len(b) < length{
		return false
	}

	for i := 0; i < length; i++{
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
