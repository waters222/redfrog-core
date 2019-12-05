package common

import (
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"math"
	"sync"
	"time"
)

type DnsSyncResolver struct {
	dnsIdQueue     chan uint16
	dnsQueryMap    map[uint16]chan<- *dns.Msg
	dnsQueryMapMux sync.RWMutex
}

func (c *DnsSyncResolver) Start() {
	c.dnsIdQueue = make(chan uint16, math.MaxUint16)
	c.dnsQueryMap = make(map[uint16]chan<- *dns.Msg)
	for i := 1; i < math.MaxUint16; i++ {
		c.dnsIdQueue <- uint16(i)
	}
}

func (c *DnsSyncResolver) ProcessDnsResponse(logger *zap.Logger, data []byte) {
	dnsId := binary.BigEndian.Uint16(data)
	// now we unpack
	resDns := new(dns.Msg)
	if err := resDns.Unpack(data); err != nil {
		if logger != nil {
			logger.Info("DNS unpack for proxy resolver failed", zap.String("error", err.Error()))
		}
		return
	}

	c.dnsQueryMapMux.Lock()
	// if id is exists then send signal for notification and delete this entry
	if sig, ok := c.dnsQueryMap[dnsId]; ok {
		delete(c.dnsQueryMap, dnsId)
		c.dnsQueryMapMux.Unlock()
		sig <- resDns
	} else {
		c.dnsQueryMapMux.Unlock()
	}
}

func (c *DnsSyncResolver) GetDnsId() uint16 {
	dnsId := <-c.dnsIdQueue
	return dnsId
}

func (c *DnsSyncResolver) PutDnsId(dnsId uint16) {
	c.dnsIdQueue <- dnsId
}

func (c *DnsSyncResolver) WaitResponse(dnsId uint16, timeout time.Duration) (response *dns.Msg, err error) {
	defer func() {
		// make sure id is recycled
		c.dnsIdQueue <- dnsId
	}()
	sig := make(chan *dns.Msg)
	c.dnsQueryMapMux.Lock()
	c.dnsQueryMap[dnsId] = sig
	c.dnsQueryMapMux.Unlock()

	// set timeout for dns query
	timeoutTimer := time.NewTimer(timeout)
	select {
	case dnsResponse := <-sig:
		if dnsResponse == nil {
			return nil, errors.New("dns sig channel close")
		} else {
			return dnsResponse, nil
		}

	case <-timeoutTimer.C:
		// remove from map and recycle id after timeout triggered
		c.dnsQueryMapMux.Lock()
		defer c.dnsQueryMapMux.Unlock()
		delete(c.dnsQueryMap, dnsId)
		return nil, errors.New(fmt.Sprintf("read dns from remote proxy timeout: %s, dnsID: %d", timeout.String(), dnsId))
	}
}

func (c *DnsSyncResolver) Stop() {
	c.dnsQueryMapMux.Lock()
	defer c.dnsQueryMapMux.Unlock()
	for _, v := range c.dnsQueryMap {
		// send nil signal to close
		v <- nil
	}
}
