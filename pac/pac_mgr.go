package pac

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/routing"
	"go.uber.org/zap"
	"os"
	"regexp"
	"sync"
)

const MONITOR_INTERVAL = 5

const (
	regex_pacVersion_   = "^\\[(.*)\\]$"
	regex_commentRegex_ = "^!(.*)$"
	regex_whiteRegex_   = "^@@([^ ]+)$"
	regex_http_https_   = "^\\|https?://([^ /]+)(/.*)?$"
	regex_domain_0_     = "^\\|\\|([^ /]+)(/.*)?$"
	regex_domain_1_     = "^\\.([^ /]+)(/.*)?$"
	regex_domain_2_     = "([^\\*\\.]*\\*\\.)([^ /]+)(/.*)?$"
	regex_ip_           = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/?(.*)$"
	regex_domain_last_  = "^([^ /\\*\\|]+)(/.*)?$"
	regex_domain_regex_ = "^/(.+)/$"
)

type PacList struct {
	Domains map[string]bool
	IPs     map[string]bool
}
type ProxyList struct {
	// for proxy_client
	proxyDomains map[string]bool
	proxyIPs     map[string]bool
	sync.RWMutex
}
type PacListMgr struct {
	// for reading paclist and compare
	sync.Mutex
	pacLists  map[string]*PacList
	proxyList ProxyList

	// routing table
	routingMgr *routing.RoutingMgr
}

func StartPacListMgr(routingMgr *routing.RoutingMgr) (ret *PacListMgr, err error) {
	logger := log.GetLogger()
	ret = &PacListMgr{}
	if routingMgr == nil {
		return nil, errors.New("routing manager is nil")
	}
	ret.routingMgr = routingMgr
	ret.pacLists = make(map[string]*PacList)
	ret.proxyList.proxyDomains = make(map[string]bool)
	ret.proxyList.proxyIPs = make(map[string]bool)

	logger.Info("Start pac List Manager successful")
	return
}
func (c *PacListMgr) Stop() {
	logger := log.GetLogger()
	logger.Info("Stop pac List Manager successful")
}

func (c *PacListMgr) ReloadPacList(paths []string) {
	c.loadPacLists(paths, true)
}

func (c *PacListMgr) ReadPacList(paths []string) {
	c.loadPacLists(paths, false)
}
func (c *PacListMgr) loadPacLists(paths []string, reload bool) {
	logger := log.GetLogger()
	if reload {
		c.Lock()
		c.pacLists = make(map[string]*PacList)
		c.Unlock()
	}
	for _, path := range paths {
		if _, ok := c.pacLists[path]; !ok {
			if ret, err := parsePacList(path); err != nil {
				logger.Error("Parse Pac List file failed", zap.String("file", path), zap.String("error", err.Error()))
			} else {
				c.Lock()
				c.pacLists[path] = ret
				c.Unlock()
				logger.Info("Parse Pac List file successful", zap.String("file", path))
			}
		} else {
			logger.Warn("Pac list file path duplicated, so skip parsing", zap.String("file", path))
		}

	}

	proxyDomains := make(map[string]bool)
	proxyIPs := make(map[string]bool)

	func() {
		c.Lock()
		defer c.Unlock()
		for _, pacList := range c.pacLists {
			for domain, flag := range pacList.Domains {
				proxyDomains[domain] = flag
			}
			for ip, flag := range pacList.IPs {
				proxyIPs[ip] = flag
			}
		}
	}()

	c.proxyList.Lock()
	defer c.proxyList.Unlock()

	if reload {
		// reloading
		ipListDelete := make([]string, 0)
		for ip := range c.proxyList.proxyIPs {
			if _, ok := proxyIPs[ip]; !ok {
				ipListDelete = append(ipListDelete, ip)
				logger.Debug("Ip delete list", zap.String("ip", ip))
			}
		}

		c.proxyList.proxyDomains = proxyDomains
		c.proxyList.proxyIPs = proxyIPs

		c.routingMgr.ReloadPacList(proxyDomains, proxyIPs, ipListDelete)
	} else {
		// first time

		c.proxyList.proxyDomains = proxyDomains
		c.proxyList.proxyIPs = proxyIPs

		logger.Info("Composing new proxy_client list finished, start to populate routing table")
		// now lets re-populate routing table

		c.routingMgr.LoadPacList(proxyDomains, proxyIPs)

	}

	return
}

func (c *PacListMgr) AddDomain(domain string, flag bool) {
	c.proxyList.Lock()
	defer c.proxyList.Unlock()
	c.proxyList.proxyDomains[domain] = flag
}

func (c *PacListMgr) CheckDomain(domain string) bool {
	logger := log.GetLogger()
	stubs := common.GenerateDomainStubs(domain)
	if stubs == nil {
		return false
	}
	length := len(stubs)
	if length == 0 {
		return false
	}

	c.proxyList.RLock()
	defer c.proxyList.RUnlock()
	proxyList := c.proxyList.proxyDomains

	for i := 0; i < length; i++ {
		if blacked, ok := proxyList[stubs[i]]; ok {
			logger.Debug("Domain is in proxy_client list", zap.String("domain", domain), zap.Bool("blacked", blacked))
			return blacked
		}
	}

	logger.Debug("Domain is NOT in proxy_client list", zap.String("domain", domain))
	return false
}

func parsePacList(path string) (ret *PacList, err error) {

	file, err := os.Open(config.GetPathFromWorkingDir(path)) // For read access.
	if err != nil {
		return nil, errors.Wrapf(err, "Open config file %s failed", path)
	}
	defer file.Close()

	ret = &PacList{}
	ret.Domains = make(map[string]bool)
	ret.IPs = make(map[string]bool)

	reader := bufio.NewReader(file)

	lineBuffer := make([]byte, 0)
	for line, isPrefix, readError := reader.ReadLine(); readError == nil; line, isPrefix, readError = reader.ReadLine() {
		if isPrefix {
			lineBuffer = append(lineBuffer, line...)
		} else if len(lineBuffer) > 0 {
			if err = ret.parsePacListLine(lineBuffer); err != nil {
				return nil, err
			}
			lineBuffer = make([]byte, 0)
		} else {
			if err = ret.parsePacListLine(line); err != nil {
				return nil, err
			}
		}
	}

	return
}

func (c *PacList) equal(other *PacList) bool {
	if len(c.Domains) != len(other.Domains) ||
		len(c.IPs) != len(other.IPs) {
		return false
	}
	for key := range c.Domains {
		if _, ok := other.Domains[key]; !ok {
			return false
		}
	}
	for key := range c.IPs {
		if _, ok := other.IPs[key]; !ok {
			return false
		}
	}

	return true
}

func (c *PacList) parsePacListLine(line []byte) (err error) {
	if len(line) == 0 {
		return
	}
	//logger := log.GetLogger()
	var re *regexp.Regexp

	// replace all white space etc
	line = bytes.Replace(line, []byte{' '}, []byte{}, -1)

	// pac version
	if re, err = regexp.Compile(regex_pacVersion_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_pacVersion_))
	}
	if re.Match(line) {
		//logger.Debug("ParsePAC match pac version", zap.String("line", string(line[:])))
		return
	}

	// pac comment
	if re, err = regexp.Compile(regex_commentRegex_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_commentRegex_))
	}
	if re.Match(line) {
		//logger.Debug("ParsePAC match comment ", zap.String("line", string(line[:])))
		return
	}

	// white domain
	bDomainType := common.DOMAIN_BLACK_LIST
	if re, err = regexp.Compile(regex_whiteRegex_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_whiteRegex_))
	}

	matchByte := line
	if matches := re.FindAllSubmatch(line, -1); len(matches) > 0 {
		if len(matches[0][1]) > 0 {
			// ignore white list
			//return
			matchByte = matches[0][1]
			bDomainType = common.DOMAIN_WHITE_LIST
		}

	}

	// http and https
	if re, err = regexp.Compile(regex_http_https_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_http_https_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		matchByte = matches[0][1]
	}

	// domain 0
	if re, err = regexp.Compile(regex_domain_0_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_0_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		matchByte = matches[0][1]
	}

	// domain 1
	if re, err = regexp.Compile(regex_domain_1_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_1_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		matchByte = matches[0][1]
	}

	// domain 2
	if re, err = regexp.Compile(regex_domain_2_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_2_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 1 {
		matchByte = matches[1][1]
	}

	// ip
	if re, err = regexp.Compile(regex_ip_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_ip_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		ip := string(matches[0][1][:])
		if originDomainType, ok := c.IPs[ip]; ok {
			c.IPs[ip] = bDomainType || originDomainType
		} else {
			c.IPs[ip] = bDomainType
		}

		//logger.Debug("ParsePAC find ip", zap.String("line", string(line[:])), zap.String("ip", ip), zap.Bool("black_list", bDomainType))
		return
	}

	// domain last
	if re, err = regexp.Compile(regex_domain_last_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_last_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		domain := string(matches[0][1][:])
		if originDomainType, ok := c.Domains[domain]; ok {
			c.Domains[domain] = bDomainType || originDomainType
		} else {
			c.Domains[domain] = bDomainType
		}
		//logger.Debug("ParsePAC find domain", zap.String("line", string(line[:])), zap.String("domain", domain), zap.Bool("black_list", bDomainType))
		return
	}

	// domain regex
	if re, err = regexp.Compile(regex_domain_regex_); err != nil {
		return errors.Wrap(err, fmt.Sprintf("Compile regex failed: %s", regex_domain_regex_))
	}
	if matches := re.FindAllSubmatch(matchByte, -1); len(matches) > 0 {
		domain := string(matches[0][1][:])
		if originDomainType, ok := c.Domains[domain]; ok {
			c.Domains[domain] = bDomainType || originDomainType
		} else {
			c.Domains[domain] = bDomainType
		}
		//logger.Debug("ParsePAC find domain", zap.String("line", string(line[:])), zap.String("domain", domain), zap.Bool("black_list", bDomainType))
	} else {
		//logger.Debug("ParsePAC can not find domain or ip", zap.String("line", string(line[:])))
	}
	return
}
