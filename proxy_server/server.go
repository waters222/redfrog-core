package main

import (
	"flag"
	. "github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
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
		logger.Info("RedFrog Server",
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
	var config ServerConfig
	if config, err = ParseServerConfig(configFile); err != nil{
		logger.Error("Read config file failed", zap.String("file", configFile), zap.String("error", err.Error()))
		return
	}else{
		logger.Info("Read config file successful", zap.String("file", configFile))
	}


	logger.Info("RefFrog server is up and running")
	go func() {
		sig := <-sigChan

		logger.Debug("RefFrog server caught signal for exit",
			zap.Any("signal", sig))
		done <- true
	}()
	<-done
}