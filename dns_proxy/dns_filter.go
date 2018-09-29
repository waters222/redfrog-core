package dns_proxy

import (
	"bufio"
	"bytes"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"go.uber.org/zap"
	"os"
	"sync"
	"github.com/weishi258/redfrog-core/log"
)

const (
	FILTER_BLACK = false
	FILTER_WHITE = true
)

type dnsFilter struct{
	sync.RWMutex
	domains	map[string]bool
}

func LoadFilter(blackList []string, whiteList []string) (ret *dnsFilter, err error){
	ret = &dnsFilter{}

	return
}

func (c *dnsFilter) readBlackList(fileList []string) error{
	if fileList != nil && len(fileList) > 0{
		for _, file := range fileList{
			if err := c.readList(file, FILTER_BLACK); err != nil{
				return err
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
			if err = c.parseFilterListLine(lineBuffer); err != nil {
				err = errors.Wrapf(err, "Parse filter list file %s failed", path)
				return
			}
			lineBuffer = make([]byte, 0)
		} else {
			if err = c.parseFilterListLine(line); err != nil {
				err = errors.Wrapf(err, "Parse filter list file %s failed", path)
				return
			}
		}
	}

	return
}

func (c *dnsFilter) parseFilterListLine(line []byte) (err error){
	if len(line) == 0 {
		return
	}

	line = bytes.Replace(line, []byte{' '}, []byte{}, -1)

	return
}



func (c *dnsFilter) CheckDomain(domain string) (ret bool){
	logger := log.GetLogger()
	ret = FILTER_WHITE
	stubs := common.GenerateDomainStubs(domain)
	if stubs == nil {
		return
	}
	length := len(stubs)
	if length == 0 {
		return
	}

	c.RLock()
	defer c.RUnlock()

	for i := 0; i < length; i++ {
		if flag, ok := c.domains[stubs[i]]; ok {
			logger.Debug("Domain is in filter list", zap.String("domain", domain), zap.Bool("flag", flag))
			return flag
		}
	}

	return
}