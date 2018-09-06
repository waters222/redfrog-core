package main

import (
	"flag"
	"fmt"
	. "github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/dns_proxy"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/pac"
	"github.com/weishi258/redfrog-core/proxy_client"
	"github.com/weishi258/redfrog-core/routing"
	"go.uber.org/zap"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"
)

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
	var configFile string
	var logLevel string
	var bProduction bool

	var err error

	// parse parameters

	flag.BoolVar(&printVer, "version", false, "print server version")
	flag.StringVar(&configFile, "c", "server_config.json", "server config file")
	flag.StringVar(&logLevel, "l", "info", "log level")
	flag.BoolVar(&bProduction, "production", false, "is production mode")
	flag.Parse()

	defer func(){
		if err != nil{
			os.Exit(1)
		}else{
			os.Exit(0)
		}
	}()

	// init logger
	logger := log.InitLogger(logLevel, bProduction)

	// print version
	if printVer{
		logger.Info("RedFrog",
			zap.String("Version", Version),
			zap.String("BuildTime", BuildTime))
		os.Exit(0)
	}

	defer func(){
		logger.Sync()
		logger.Info("RedFrog is stopped")
		if err != nil{
			os.Exit(1)
		}else{
			os.Exit(0)
		}
	}()

	// parse config
	var config Config
	if config, err = ParseClientConfig(configFile); err != nil{
		logger.Error("Read config file failed", zap.String("file", configFile), zap.String("error", err.Error()))
		return
	}else{
		logger.Info("Read config file successful", zap.String("file", configFile))
	}


	// init routing mgr
	var routingMgr *routing.RoutingMgr
	if routingMgr, err = routing.StartRoutingMgr(config.ListenPort, config.PacketMask); err != nil{
		logger.Error("Init routing manager failed", zap.String("error", err.Error()))
		return
	}
	defer routingMgr.Stop()


	// init pac list
	var pacListMgr *pac.PacListMgr
	if pacListMgr, err = pac.StartPacListMgr(routingMgr); err != nil{
		logger.Error("Start pac list manager failed", zap.String("error", err.Error()))
	}
	defer pacListMgr.Stop()
	pacListMgr.ReadPacList(config.Shadowsocks.PacList)


	var proxyClient* proxy_client.ProxyClient
	if proxyClient, err = proxy_client.StartProxyClient(config.Shadowsocks, fmt.Sprintf("0.0.0.0:%d", config.ListenPort)); err != nil{
		logger.Error("Start proxy client failed", zap.String("error", err.Error()))
		return
	}
	defer proxyClient.Stop()

	// Start Dns Server

	var dnsServer *dns_proxy.DnsServer
	if dnsServer, err = dns_proxy.StartDnsServer(config.Dns, pacListMgr, routingMgr, proxyClient); err != nil{
		logger.Error("Start dns_proxy server failed", zap.String("error", err.Error()))
		return
	}
	defer dnsServer.Stop()



	logger.Info("RefFrog is up and running")
	go func() {
		sig := <-sigChan

		logger.Debug("RefFrog caught signal for exit",
			zap.Any("signal", sig))
		done <- true
	}()
	<-done

}