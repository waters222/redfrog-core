package main

import (
	"flag"
	"fmt"
	. "github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/proxy_server/impl"
	"go.uber.org/zap"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var Version string
var RevInfo string
var BuildTime string

const (
	appName = "RedFrog Server"
)

func main() {

	rand.Seed(time.Now().UnixNano())

	var printVer bool
	var configFile string
	var logLevel string
	var bJson bool
	var logFile string
	var err error

	// parse parameters

	flag.BoolVar(&printVer, "version", false, "print server version")
	flag.StringVar(&configFile, "c", "server_config.json", "server config file")
	flag.StringVar(&logLevel, "l", "info", "log level")
	flag.BoolVar(&bJson, "json", false, "log output json format")
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

	logger := log.InitLogger(logFile, logLevel, bJson)

	// print version
	if printVer {
		if Version != "" {
			logger.Info(appName,
				zap.String("Version", Version),
				zap.String("Rev", RevInfo),
				zap.String("BuildTime", BuildTime))
		} else {
			logger.Info(appName,
				zap.String("Rev", RevInfo),
				zap.String("BuildTime", BuildTime))
		}

		os.Exit(0)
	}

	defer func() {
		logger.Sync()
		logger.Info(fmt.Sprintf("%s is stopped", appName))
		if err != nil {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}()

	// parse config
	var config ServerSwarmConfig
	if config, err = ParseServerConfig(configFile); err != nil {
		logger.Error("Read config file failed", zap.String("file", configFile), zap.String("error", err.Error()))
		return
	} else {
		logger.Info("Read config file successful", zap.String("file", configFile))
	}
	logger.Info("Server config total", zap.Int("count", len(config.Servers)))
	servers := make([]*impl.ProxyServer, 0)
	for _, configEntry := range config.Servers {
		if server, err := impl.StartProxyServer(configEntry); err != nil {
			logger.Error("Start proxy server failed", zap.String("error", err.Error()))
		} else {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		return
	}
	defer func() {
		for _, server := range servers {
			server.Stop()
		}
	}()

	logger.Info(fmt.Sprintf("%s is up and running", appName))

	sigChan := make(chan os.Signal, 1)
	done := make(chan bool)

	signal.Notify(sigChan,
		syscall.SIGTERM,
		syscall.SIGINT)

	go func() {
		sig := <-sigChan

		logger.Info(fmt.Sprintf("%s caught signal for exit", appName),
			zap.Any("signal", sig))
		done <- true
	}()
	<-done

}
