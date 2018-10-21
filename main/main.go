package main

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	. "github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/dns_proxy"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/pac"
	"github.com/weishi258/redfrog-core/proxy_client"
	"github.com/weishi258/redfrog-core/routing"
	"go.uber.org/zap"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const DNS_MOCK_TIMEOUT_MUTIPLIER = 10

var Version string
var BuildTime string

var serviceStopSignal chan bool
var appRunStatus chan bool
var sigChan chan os.Signal

func main() {

	rand.Seed(time.Now().UnixNano())

	var printVer bool
	var configFile string
	var logLevel string
	var bProduction bool
	var workingDir string
	var logFile string
	var err error

	// parse parameters

	flag.BoolVar(&printVer, "version", false, "print server version")
	flag.StringVar(&configFile, "c", "server_config.json", "server config file")
	flag.StringVar(&logLevel, "l", "info", "log level")
	flag.BoolVar(&bProduction, "production", false, "is production mode")
	flag.StringVar(&workingDir, "d", "./", "working directory")
	flag.StringVar(&logFile, "log", "", "log output file path")
	flag.Parse()

	defer func() {
		if err != nil {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}()

	// init logger
	logger := log.InitLogger(logFile, logLevel, bProduction)

	// print version
	if printVer {
		logger.Info("RedFrog",
			zap.String("Version", Version),
			zap.String("BuildTime", BuildTime))
		os.Exit(0)
	}

	defer func() {
		logger.Sync()
		logger.Info("RedFrog is exit")
		if err != nil {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}()
	SetWorkingDir(workingDir)

	serviceStopSignal = make(chan bool)
	appRunStatus = make(chan bool)
	sigChan = make(chan os.Signal, 1)

	signal.Notify(sigChan,
		syscall.SIGTERM,
		syscall.SIGINT)

	go StartService(configFile)

	runStatus := <-appRunStatus
	if !runStatus {
		os.Exit(1)
	}

	sig := <-sigChan
	logger.Info("RefFrog caught signal for exit", zap.Any("signal", sig))
	serviceStopSignal <- true
	<-appRunStatus
	return

}
func StartService(configFile string) {
	logger := log.GetLogger()
	status := false
	defer func() {
		appRunStatus <- status
	}()
	// parse config
	var err error
	var config Config
	if config, err = ParseClientConfig(configFile); err != nil {
		logger.Error("Read config file failed", zap.String("file", configFile), zap.String("error", err.Error()))
		return
	} else {
		logger.Info("Read config file successful", zap.String("file", configFile))
	}

	if err = addTProxyRoutingIPv4(config.PacketMask, strconv.Itoa(config.RoutingTable)); err != nil {
		logger.Error("Add TProxy ipv4 route failed", zap.String("error", err.Error()))
		return
	}
	if err = addTProxyRoutingIPv6(config.PacketMask, strconv.Itoa(config.RoutingTable)); err != nil {
		logger.Error("Add TProxy ipv6 route failed", zap.String("error", err.Error()))
		return
	}
	// init routing mgr
	var routingMgr *routing.RoutingMgr
	if routingMgr, err = routing.StartRoutingMgr(config.ListenPort, config.PacketMask, config.IgnoreIP, config.Interface, config.IPSet); err != nil {
		logger.Error("Init routing manager failed", zap.String("error", err.Error()))
		return
	}
	defer routingMgr.Stop()

	// init pac list
	var pacListMgr *pac.PacListMgr
	if pacListMgr, err = pac.StartPacListMgr(routingMgr); err != nil {
		logger.Error("Start pac list manager failed", zap.String("error", err.Error()))
	}
	defer pacListMgr.Stop()
	pacListMgr.ReadPacList(config.PacList)

	var proxyClient *proxy_client.ProxyClient
	if proxyClient, err = proxy_client.StartProxyClient(config.Dns.Timeout*DNS_MOCK_TIMEOUT_MUTIPLIER, config.Shadowsocks, fmt.Sprintf("0.0.0.0:%d", config.ListenPort)); err != nil {
		logger.Error("Start proxy client failed", zap.String("error", err.Error()))
		return
	}
	defer proxyClient.Stop()

	// Start Dns Server

	var dnsServer *dns_proxy.DnsServer
	if dnsServer, err = dns_proxy.StartDnsServer(config.Dns, pacListMgr, routingMgr, proxyClient); err != nil {
		logger.Error("Start dns_proxy server failed", zap.String("error", err.Error()))
		return
	}
	defer dnsServer.Stop()

	status = true

	logger.Info("RefFrog service is up and running")

	appRunStatus <- true

	// reading reload signal
	reloadSignal := make(chan os.Signal, 1)
	signal.Notify(reloadSignal,
		syscall.SIGHUP)
	for {
		select {
		case <-reloadSignal:
			logger.Info("Reload configs")

			var newConfig Config
			if newConfig, err = ParseClientConfig(configFile); err != nil {
				logger.Error("Read config file failed", zap.String("file", configFile), zap.String("error", err.Error()))
				continue
			}
			logger.Info("Read config file successful", zap.String("file", configFile))
			pacListMgr.ReloadPacList(newConfig.PacList)

			dnsServer.Reload(newConfig.Dns)

			if err = proxyClient.ReloadBackend(config.Dns.Timeout*DNS_MOCK_TIMEOUT_MUTIPLIER, newConfig.Shadowsocks); err != nil {
				logger.Error("Reload backend failed", zap.String("error", err.Error()))
			} else {
				logger.Info("Reload backend successful")
			}

			//pacListMgr.ReadPacList()
		case <-serviceStopSignal:
			logger.Info("RedFrog service is stopped")
			return
		}
	}

}

func addTProxyRoutingIPv4(mark string, table string) (err error) {
	cmd := exec.Command("ip", "rule", "list", "fwmark", mark, "lookup", table)
	var response []byte
	if response, err = cmd.Output(); err != nil {
		err = errors.Wrap(err, "list ipv4 rule failed")
		return
	}
	if len(response) == 0 {
		// need to add new
		cmd = exec.Command("ip", "rule", "add", "fwmark", mark, "lookup", table)
		if err = cmd.Run(); err != nil {
			err = errors.Wrap(err, "add ipv4 routing rule failed")
			return
		}
	}

	cmd = exec.Command("ip", "route", "list", "0.0.0.0/0", "dev", "lo", "table", table)
	if response, err = cmd.Output(); err != nil {
		err = errors.Wrap(err, "list ipv4 routing route failed")
		return
	}
	if len(response) == 0 {
		// need to add new
		cmd = exec.Command("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", table)
		if err = cmd.Run(); err != nil {
			err = errors.Wrap(err, "add ipv4 routing route failed")
			return
		}
	}

	return
}

func addTProxyRoutingIPv6(mark string, table string) (err error) {
	cmd := exec.Command("ip", "-6", "rule", "list", "fwmark", mark, "lookup", table)
	var response []byte
	if response, err = cmd.Output(); err != nil {
		err = errors.Wrap(err, "list ipv6 rule failed")
		return
	}
	if len(response) == 0 {
		// need to add new
		cmd = exec.Command("ip", "-6", "rule", "add", "fwmark", mark, "lookup", table)
		if err = cmd.Run(); err != nil {
			err = errors.Wrap(err, "add ipv6 routing rule failed")
			return
		}
	}

	cmd = exec.Command("ip", "-6", "route", "list", "::/128", "dev", "lo", "table", table)
	if response, err = cmd.Output(); err != nil {
		err = errors.Wrap(err, "list ipv6 routing route failed")
		return
	}
	if len(response) == 0 {
		// need to add new
		cmd = exec.Command("ip", "-6", "route", "replace", "local", "::/128", "dev", "lo", "table", table)
		if err = cmd.Run(); err != nil {
			err = errors.Wrap(err, "add ipv6 routing route failed")
			return
		}
	}

	return
}
