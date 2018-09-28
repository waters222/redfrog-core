package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)


func main() {
	var err error
	sigChan := make(chan os.Signal, 5)
	done := make(chan bool)

	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGKILL,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGINT)

	rand.Seed(time.Now().UnixNano())

	var mode string
	var logLevel string
	var runningTime int
	var repeatInterval int
	var port int
	var portRange int
	var dnsFile string
	var dnsCount int
	flag.StringVar(&mode, "m", "", "mode: all/proxy/dns")
	flag.StringVar(&logLevel, "l", "info", "log level")
	flag.StringVar(&dnsFile, "d", "info", "dns file")
	flag.IntVar(&runningTime,"time",  10,"running time in seconds")
	flag.IntVar(&repeatInterval, "r", 5, "repeat interval in second")
	flag.IntVar(&port, "port", 9191, "min port value")
	flag.IntVar(&portRange, "portRange", 100, "port range")
	flag.IntVar(&dnsCount, "dnsCount", 100, "dns concurrency")

	flag.Parse()

	logger := log.InitLogger(logLevel, false)



	defer func() {
		if err != nil {
			logger.Error("Exit 1", zap.String("error", err.Error()))
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}()
	if port <= 1024{
		err = errors.New(fmt.Sprintf("port is less then 1024: %d", port))
		return
	}
	errorChan := make(chan error, dnsCount + portRange)


	if mode == "all"{
		if err = startDns(errorChan, dnsFile, dnsCount, repeatInterval); err != nil{
			return
		}
		if err = startProxy(errorChan, port, portRange, repeatInterval); err != nil{
			return
		}
	}else if mode == "proxy"{
		if err = startProxy(errorChan, port, portRange, repeatInterval); err != nil{
			return
		}
	}else if mode == "dns"{
		if err = startDns(errorChan, dnsFile, dnsCount, repeatInterval); err != nil{
			return
		}
	}else{
		err = errors.New(fmt.Sprintf("Unknow mode: %s", mode))
		return
	}
	logger.Info("Running test", zap.Int("duration in seconds", runningTime), zap.Int("repeat interval", repeatInterval), zap.String("mode", mode))
	timer := time.After(time.Duration(runningTime) * time.Second)

	go func(){
		select{
		case sig := <-sigChan:
			logger.Debug("Batch test exit for for signal", zap.Any("signal", sig))
			done <- true
			return
		case err = <-errorChan:
			done <- true
			return
		case <- timer:
			logger.Info("Running finished")
			done <- true
			return

		}
	}()
	<- done
}
func readDnsFile(dnsFile string) (ret []string, err error){
	file, err := os.Open(dnsFile) // For read access.
	if err != nil {
		err = errors.Wrapf(err, "Open dns file %s failed", dnsFile)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		err = errors.Wrapf(err, "Read dns file %s failed", dnsFile)
		return
	}
	stubs := bytes.Split(data,[]byte{'\n'})

	ret = make([]string, 0)
	for _, stub := range stubs{
		if len(stub) > 0{
			ret = append(ret, string(stub[:]))
		}
	}
	if len(ret) == 0{
		err = errors.New("empty dns file")
	}
	return
}

func startProxy(errorChan chan<-error, port int, portRange int, repeatInterval int) error{
	cmd := exec.Command("dig", "+short", "test-server")
	if addr, err := cmd.Output(); err != nil{
		err = errors.Wrap(err, "retrieve remote server failed")
		return err
	}else{
		remoteAddr := string(addr[:])
		for i := 0; i < portRange; i++{
			go runProxy(errorChan, remoteAddr, port + i, repeatInterval)
		}
	}
	return nil
}
func runProxy(errorChan chan<-error, addr string, port int,  repeatInterval int){
	cmd := exec.Command("./test", "-m", "client", "-timeout", strconv.Itoa(repeatInterval), "-addr",  fmt.Sprintf("%s:%d", addr, port))
	if err :=cmd.Run(); err != nil{
		errorChan <- err
	}
}

func startDns(errorChan chan<-error, dnsFile string, dnsCount int, repeatInterval int) error{
	domains, err := readDnsFile(dnsFile)
	if err != nil{
		return err
	}
	for i := 0; i < dnsCount; i++{
		go runDns(errorChan, domains, repeatInterval, i)
	}

	return nil
}
func runDns(errorChan chan<-error, domains []string, repeatInterval int, idx int){
	logger := log.GetLogger()
	logger.Info("Start dns query", zap.Int("idx", idx))
	length := int32(len(domains))
	//rndIdx := rand.Int31n(length)
	//domain := domains[rndIdx]
	//cmd := exec.Command("dig", "+short", domain)
	//if output, err := cmd.Output(); err != nil{
	//	logger.Error("dns query failed", zap.String("domain", domain), zap.String("error", err.Error()))
	//	//errorChan <- err
	//	return
	//}else{
	//	logger.Info("dns response ", zap.String("domain", domain),zap.ByteString("response", output))
	//}

	ticker := time.Tick(time.Duration(repeatInterval) * time.Second)

	for{
		select {
			case <- ticker:
				rndIdx := rand.Int31n(length)
				domain := domains[rndIdx]
				cmd := exec.Command("dig", "+short", domain, "@192.168.0.2")
				logger.Debug("Dns query", zap.String("domain", domain))
				if output, err := cmd.Output(); err != nil{
					logger.Error("dns query failed", zap.String("domain", domain), zap.String("error", err.Error()))
					//errorChan <- err
					return
				}else{
					logger.Debug("dns response ", zap.String("domain", domain),zap.ByteString("response", output))
				}

		}

	}

}