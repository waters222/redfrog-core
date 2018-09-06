package pac

import (
	"sync"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"os"
	"github.com/pkg/errors"
	"bufio"
	"regexp"
	"fmt"
	"time"
	"github.com/weishi258/redfrog-core/common"
	"bytes"
	"github.com/weishi258/redfrog-core/routing"
	"strings"
)

const MONITOR_INTERVAL = 5


const (
	regex_pacVersion_ 	= "^\\[(.*)\\]$"
	regex_commentRegex_ = "^!(.*)$"
	regex_whiteRegex_	= "^@@([^ ]+)$"
	regex_http_https_	= "^\\|https?://([^ /]+)(/.*)?$"
	regex_domain_0_		= "^\\|\\|([^ /]+)(/.*)?$"
	regex_domain_1_		= "^\\.([^ /]+)(/.*)?$"
	regex_domain_2_		= "([^\\*\\.]*\\*\\.)([^ /]+)(/.*)?$"
	regex_ip_			= "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/?(.*)$"
	regex_domain_last_	= "^([^ /\\*\\|]+)(/.*)?$"
	regex_domain_regex_	= "^/(.+)/$"
)

type PacList struct{
	Domains			map[string]bool
	IPs				map[string]bool
	lastModified	time.Time
}
type ProxyList struct{
	// for proxy_client
	proxyDomains		map[string]bool
	proxyIPs			map[string]bool
	mux      			sync.RWMutex
}
type PacListMgr struct{
	// for reading paclist and compare
	pacLists 			map[string]*PacList
	pacListsMux      	sync.Mutex
	ticker	 			*time.Ticker

	proxyList			ProxyList

	// routing table
	routingMgr			*routing.RoutingMgr

}


func (c *PacListMgr)startMonitorPacList(){
	logger := log.GetLogger()

	go func(){
		for{
			select {
				case <- c.ticker.C:
					bPacListHasChanged := false
					func(){
						c.pacListsMux.Lock()
						defer c.pacListsMux.Unlock()

						for path, pacList := range c.pacLists{
							if lastModified, err := os.Stat(path); err != nil{
								logger.Error("Get file stat failed", zap.String("file", path), zap.String("error", err.Error()))
							}else{
								if pacList.lastModified.Before(lastModified.ModTime()){
									logger.Info("Pac list file has modified since last time, so re-evaluation", zap.String("file", path))
									pacList.lastModified = lastModified.ModTime()
									// lets do re-loading

									if newPacList, err := parsePacList(path); err == nil{
										if !pacList.equal(newPacList){
											// its not equal so using the new domains
											pacList.Domains = newPacList.Domains
											pacList.IPs = newPacList.IPs
											// set changed flag to true
											bPacListHasChanged = true
											logger.Info("Pac file content has changed", zap.String("file", path))
										}
									}
								}
							}
						}
					}()

					if bPacListHasChanged{
						//
						c.composeProxyList()
					}
			}
		}
	}()
	logger.Info("Start pac list files monitor")
}
func (c *PacListMgr)stopMonitorPackList(){
	logger := log.GetLogger()
	c.ticker.Stop()
	logger.Info("Stop pac list files monitor")
}

func (c* PacListMgr)composeProxyList(){
	logger := log.GetLogger()

	proxyDomains := make(map[string]bool)
	proxyIPs := make(map[string]bool)

	func(){
		c.pacListsMux.Lock()
		defer c.pacListsMux.Unlock()
		for _, pacList := range c.pacLists{
			for domain, flag := range pacList.Domains{
				proxyDomains[domain] = flag
			}
			for ip, flag := range pacList.IPs{
				proxyIPs[ip] = flag
			}
		}
	}()


	c.proxyList.mux.Lock()
	defer c.proxyList.mux.Unlock()
	c.proxyList.proxyDomains = proxyDomains
	c.proxyList.proxyIPs = proxyIPs



	logger.Info("Composing new proxy_client list finished, start to populate routing table")
	// now lets re-populate routing table
	c.routingMgr.ReloadPacList(proxyDomains, proxyIPs)
}

func StartPacListMgr(routingMgr *routing.RoutingMgr) (ret *PacListMgr, err error){
	logger := log.GetLogger()
	ret = &PacListMgr{}
	if routingMgr == nil {
		return nil, errors.New("routing manager is nil")
	}
	ret.routingMgr = routingMgr
	ret.pacLists = make(map[string]*PacList)
	ret.proxyList.proxyDomains = make(map[string]bool)
	ret.proxyList.proxyIPs = make(map[string]bool)
	ret.ticker = time.NewTicker(time.Second * MONITOR_INTERVAL)
	ret.startMonitorPacList()

	logger.Info("Start pac List Manager successful")
	return
}
func (c *PacListMgr)Stop(){
	logger := log.GetLogger()
	c.stopMonitorPackList()
	logger.Info("Stop pac List Manager successful")
}


func (c *PacListMgr)ReadPacList(paths []string){
	logger := log.GetLogger()
	for _, path := range paths{
		if _, ok := c.pacLists[path]; !ok{
			if ret, err := parsePacList(path); err != nil{
				logger.Error("Parse Pac List file failed", zap.String("file", path), zap.String("error", err.Error()))
			}else{
				c.pacListsMux.Lock()
				c.pacLists[path] = ret
				c.pacListsMux.Unlock()
				logger.Info("Parse Pac List file successful", zap.String("file", path))
			}
		}else{
			logger.Warn("Pac list file path duplicated, so skip parsing", zap.String("file", path))
		}

	}
	c.composeProxyList()
	return
}


func (c * PacListMgr)CheckDomain(domain string) bool{
	logger := log.GetLogger()

	if len(domain) == 0 {
		logger.Debug("Domain is NOT in proxy_client list", zap.String("domain", domain))
		return false
	}
	stubs := strings.Split(domain, ".")
	{
		segs := make([]string, 0)
		for _, stub := range stubs{
			if len(stub) > 0{
				segs = append(segs, stub)
			}
		}
		stubs = segs
	}

	len := len(stubs)
	for i := len - 2; i >= 0; i--{
		stubs[i] = fmt.Sprintf("%s.%s", stubs[i], stubs[i+1])
	}
	c.proxyList.mux.RLock()
	proxyList := c.proxyList.proxyDomains
	c.proxyList.mux.RUnlock()

	for i := 0; i < len; i++{
		if blacked, ok := proxyList[stubs[i]]; ok {
			logger.Debug("Domain is in proxy_client list", zap.String("domain", domain), zap.Bool("blacked", blacked))
			return blacked
		}
	}

	logger.Debug("Domain is NOT in proxy_client list", zap.String("domain", domain))
	return false
}


func parsePacList(path string)  (ret *PacList, err error){
	logger := log.GetLogger()

	file, err := os.Open(path) // For read access.
	if err != nil {
		return nil, errors.Wrapf(err, "Open config file %s failed", path)
	}
	defer file.Close()

	ret = &PacList{}
	ret.Domains = make(map[string]bool)
	ret.IPs = make(map[string]bool)
	if lastModified, err := os.Stat(path); err != nil{
		logger.Error("Get pac file stat failed", zap.String("file", path), zap.String("error", err.Error()))
		ret.lastModified = time.Now()
	}else{
		ret.lastModified = lastModified.ModTime()
	}

	reader := bufio.NewReader(file)

	lineBuffer := make([]byte, 0)
	for line, isPrefix, readError := reader.ReadLine(); readError == nil; line, isPrefix, readError = reader.ReadLine(){
		if isPrefix {
			lineBuffer = append(lineBuffer, line...)
		}else if len(lineBuffer) > 0 {
			if err = ret.parsePacListLine(lineBuffer); err != nil{
				return nil, err
			}
			lineBuffer = make([]byte, 0)
		}else{
			if err = ret.parsePacListLine(line); err != nil{
				return nil, err
			}
		}
	}
	if err != nil {
		return nil, errors.Wrapf(err, "Read config file %s failed", path)
	}

	return
}


func (c *PacList)equal(other *PacList) bool{
	if len(c.Domains) != len(other.Domains) ||
		len(c.IPs) != len(other.IPs){
		return false
	}
	for key := range c.Domains{
		if _, ok := other.Domains[key]; !ok{
			return false
		}
	}
	for key := range c.IPs{
		if _, ok := other.IPs[key]; !ok{
			return false
		}
	}

	return true
}

func (c *PacList) parsePacListLine(line []byte) (err error){
	if len(line) == 0{
		return
	}
	//logger := log.GetLogger()
	var re *regexp.Regexp

	// replace all white space etc
	line = bytes.Replace(line, []byte{' '}, []byte{}, -1)

	// pac version
	if re , err = regexp.Compile(regex_pacVersion_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_pacVersion_))
	}
	if re.Match(line) {
		//logger.Debug("ParsePAC match pac version", zap.String("line", string(line[:])))
		return
	}

	// pac comment
	if re , err = regexp.Compile(regex_commentRegex_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_commentRegex_))
	}
	if re.Match(line) {
		//logger.Debug("ParsePAC match comment ", zap.String("line", string(line[:])))
		return
	}

	// white domain
	bDomainType := common.DOMAIN_BLACK_LIST
	if re , err = regexp.Compile(regex_whiteRegex_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_whiteRegex_))
	}

	matchByte := line
	if matches := re.FindAllSubmatch(line, -1); len(matches) > 0 {
		if len(matches[0][1]) > 0 {
			matchByte = matches[0][1]
			bDomainType = common.DOMAIN_WHITE_LIST
		}

	}

	// http and https
	if re , err = regexp.Compile(regex_http_https_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_http_https_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		matchByte = matches[0][1]
	}


	// domain 0
	if re , err = regexp.Compile(regex_domain_0_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_0_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		matchByte = matches[0][1]
	}

	// domain 1
	if re , err = regexp.Compile(regex_domain_1_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_1_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		matchByte = matches[0][1]
	}


	// domain 2
	if re , err = regexp.Compile(regex_domain_2_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_2_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 1 {
		matchByte = matches[1][1]
	}

	// ip
	if re , err = regexp.Compile(regex_ip_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_ip_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		ip := string(matches[0][1][:])
		c.IPs[ip] = bDomainType
		//logger.Debug("ParsePAC find ip", zap.String("line", string(line[:])), zap.String("ip", ip), zap.Bool("black_list", bDomainType))
		return
	}


	// domain last
	if re , err = regexp.Compile(regex_domain_last_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_last_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		domain := string(matches[0][1][:])
		c.Domains[domain] = bDomainType
		//logger.Debug("ParsePAC find domain", zap.String("line", string(line[:])), zap.String("domain", domain), zap.Bool("black_list", bDomainType))
		return
	}


	// domain regex
	if re , err = regexp.Compile(regex_domain_regex_); err != nil{
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_regex_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		domain := string(matches[0][1][:])
		c.Domains[domain] = bDomainType
		//logger.Debug("ParsePAC find domain", zap.String("line", string(line[:])), zap.String("domain", domain), zap.Bool("black_list", bDomainType))
	}else{
		//logger.Debug("ParsePAC can not find domain or ip", zap.String("line", string(line[:])))
	}
	return
}