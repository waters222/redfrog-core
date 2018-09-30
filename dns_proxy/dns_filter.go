package dns_proxy

import (
	"bufio"
	"bytes"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"os"
	"regexp"
	"sync"
)

const (
	FILTER_ACTION_UNSPECIFIC = iota
	FILTER_ACTION_BLOCK
	FILTER_ACTION_PASS
)
const (
	FILTER_BLACK = false
	FILTER_WHITE = true
)
type dnsFilter struct{
	blackMux sync.RWMutex
	blackedDomains map[string]bool

	whiteMux     sync.RWMutex
	whiteDomains map[string]bool
}

func LoadFilter(blackList []string, whiteList []string) (ret *dnsFilter, err error){
	logger := log.GetLogger()
	ret = &dnsFilter{blackedDomains: make(map[string]bool), whiteDomains: make(map[string]bool)}
	if err = ret.readBlackList(blackList); err != nil{
		return
	}
	if err = ret.readWhiteList(whiteList); err != nil{
		return
	}
	logger.Info("Load DNS filter successful", zap.Strings("blacklist", blackList), zap.Strings("whiteList", whiteList))
	return
}

func (c *dnsFilter) readBlackList(fileList []string) error{
	if fileList != nil && len(fileList) > 0{
		for _, file := range fileList{
			if len(file) > 0 {
				if err := c.readList(file, FILTER_BLACK); err != nil{
					return err
				}
			}
		}
	}
	return nil
}

func (c *dnsFilter) readWhiteList(fileList []string) error{
	if fileList != nil && len(fileList) > 0{
		for _, file := range fileList{
			if err := c.readList(file, FILTER_WHITE); err != nil{
				return err
			}
		}
	}
	return nil
}

func (c *dnsFilter) readList(path string, flag bool) (err error){
	file, err := os.Open(path) // For read access.
	if err != nil {
		err = errors.Wrapf(err, "Open filter list file %s failed", path)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	lineBuffer := make([]byte, 0)
	for line, isPrefix, readError := reader.ReadLine(); readError == nil; line, isPrefix, readError = reader.ReadLine() {
		if isPrefix {
			lineBuffer = append(lineBuffer, line...)
		} else if len(lineBuffer) > 0 {
			if err = c.parseFilterListLine(lineBuffer, flag); err != nil {
				err = errors.Wrapf(err, "Parse filter list file %s failed", path)
				return
			}
			lineBuffer = make([]byte, 0)
		} else {
			if err = c.parseFilterListLine(line, flag); err != nil {
				err = errors.Wrapf(err, "Parse filter list file %s failed", path)
				return
			}
		}
	}

	return
}

func (c *dnsFilter) parseFilterListLine(line []byte, flag bool) error{
	line = filterComment(line)
	domain, err := extractDomain(line)
	if err != nil{
		return err
	}
	if flag == FILTER_WHITE{
		c.whiteMux.Lock()
		defer c.whiteMux.Unlock()
		c.whiteDomains[string(domain[:])] = true
	}else{
		c.blackMux.Lock()
		defer c.blackMux.Unlock()
		c.blackedDomains[string(domain[:])] = true
	}

	return nil
}

func filterComment(line []byte) []byte{
	if line == nil{
		return nil
	}
	idx := bytes.IndexByte(line, '#')
	if idx == -1 {
		return line
	}else {
		return line[:idx]
	}
}
func extractDomain(line []byte) ([]byte, error){
	if line == nil || len(line) == 0{
		return nil, nil
	}
	if re, err := regexp.Compile("(?:\\A|\\s)(([0-9\\p{L}][0-9\\p{L}-]{0,62}\\.)+[0-9\\p{L}][\\p{L}-]*[0-9\\p{L}]{1,62})(?:\\s|\\z)"); err != nil {
		return nil, err
	}else{
		matches := re.FindAllSubmatch(line, -1)
		if len(matches) != 0 && len(matches[0]) >= 2{
			// make sure only 127 level deep sub-domain
			if bytes.Count(matches[0][1], []byte{'.'}) > 127{
				return nil, nil
			}
			return matches[0][1], nil
		}else{
			return nil, nil
		}
	}
}


func (c *dnsFilter) CheckDomain(domain string) uint8{
	logger := log.GetLogger()
	stubs := common.GenerateDomainStubs(domain)
	if stubs != nil && len(stubs) > 0 {
		// first check white list
		if c.checkWhiteList(stubs){
			logger.Debug("Domain is in white domain list", zap.String("domain", domain))
			return FILTER_ACTION_PASS
		}else if c.checkBlackList(stubs){
			logger.Debug("Domain is in black domain list", zap.String("domain", domain))
			return FILTER_ACTION_BLOCK
		}
	}

	return FILTER_ACTION_UNSPECIFIC
}
func (c *dnsFilter) checkWhiteList(stubs []string) bool{
	c.whiteMux.RLock()
	defer c.whiteMux.RUnlock()
	for i := 0; i < len(stubs); i++ {
		if _, ok := c.whiteDomains[stubs[i]]; ok {
			return true
		}
	}
	return false
}

func (c *dnsFilter) checkBlackList(stubs []string) bool{
	c.blackMux.RLock()
	defer c.blackMux.RUnlock()
	for i := 0; i < len(stubs); i++ {
		if _, ok := c.blackedDomains[stubs[i]]; ok {
			return true
		}
	}
	return false
}