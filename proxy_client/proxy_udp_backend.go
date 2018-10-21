package proxy_client

import (
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/log"
	"github.com/weishi258/redfrog-core/network"
	"go.uber.org/zap"
	"net"
	"sync"
	"time"
)

type udpBackendPayloadSignal struct {
	srcAddr 	*net.UDPAddr
	payload 	[]byte
}
type udpBackendEntry struct {
	conn 		*net.UDPConn
	timeout 	time.Duration
	addr		*net.UDPAddr
	signal      chan udpBackendPayloadSignal
	die			chan bool
}

type udpBackend struct{
	sync.RWMutex
	backend map[string]*udpBackendEntry
}
func (c *udpBackend) removeEntry(entry *udpBackendEntry){
	c.Lock()
	defer c.Unlock()
	delete(c.backend, entry.addr.String())
	entry.conn.Close()
	log.GetLogger().Debug("UDP proxy backend entry stopped", zap.String("addr", entry.addr.String()))
}
func (c *udpBackend) stop(){
	c.RLock()
	defer c.RUnlock()

	for _, entry := range c.backend{
		close(entry.die)
	}
	log.GetLogger().Info("UDP proxy backend stopped")

}

func NewUDPBackend() *udpBackend {
	ret := &udpBackend{}
	ret.backend = make(map[string]*udpBackendEntry)
	return ret
}

func (c *udpBackend) newUDPBackendEntry(addr *net.UDPAddr, timeout time.Duration) (*udpBackendEntry, error){
	if conn, err := network.DialTransparentUDP(addr); err != nil {
		return nil, errors.Wrapf(err, "UDP proxy backend listen using transparent failed for addr: %s", addr.String())
	}else{
		return &udpBackendEntry{conn: conn,
								addr: addr,
								timeout: timeout,
								signal: make(chan udpBackendPayloadSignal,
										common.CHANNEL_QUEUE_LENGTH),
								die: make(chan bool)},
				nil
	}
}

func (c *udpBackend) WriteBackUDPPayload(proxyClientUDPBackend common.ProxyClientInterface, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, payload []byte, udpTimeout time.Duration) (err error){
	chanKey := dstAddr.String()
	signal := udpBackendPayloadSignal{srcAddr, payload}
	c.Lock()
	defer c.Unlock()
	backChannelEntry, ok := c.backend[chanKey]
	if !ok{
		if backChannelEntry, err = c.newUDPBackendEntry(dstAddr, udpTimeout); err != nil{
			return errors.Wrapf(err, "UDP proxy failed for srcAddr: %s", srcAddr.String())
		}
		c.backend[chanKey] =  backChannelEntry
		go backChannelEntry.doWriteBackLoop(proxyClientUDPBackend, c)
	}

	backChannelEntry.signal <- signal
	return
}


func (c* udpBackendEntry) doWriteBackLoop(proxyClientUDPBackend common.ProxyClientInterface, udpBackendHandler *udpBackend){
	logger := log.GetLogger()

	defer udpBackendHandler.removeEntry(c)

	timer := time.NewTimer(c.timeout)
	timeout := time.Now()
	go c.doListenLoop(proxyClientUDPBackend)
	for {
		select {
		case ch := <-c.signal:
			if len(ch.payload) > 0 {
				if _, err := c.conn.WriteTo(ch.payload, ch.srcAddr); err != nil {
					logger.Error("UDP proxy backend write back failed",
						zap.String("src", ch.srcAddr.String()),
						zap.String("addr", c.addr.String()),
						zap.String("error", err.Error()))
					return
				} else {
					logger.Debug("UDP proxy backend write back successful",
						zap.String("src", ch.srcAddr.String()),
						zap.String("addr", c.addr.String()))
					timeout = timeout.Add(c.timeout)
				}
			}

		case <-timer.C:
			if diff := timeout.Sub(time.Now()); diff >= 0{
				timer.Reset(diff)
			}else{
				logger.Debug("UDP proxy backend timeout", zap.String("addr", c.addr.String()))
				return
			}
		case <- c.die:
			return
		}
	}

}

func (c* udpBackendEntry) doListenLoop(proxyClientUDPBackend common.ProxyClientInterface){
	for{
		select{
			case <- c.die:
				return
			default:
				buffer := proxyClientUDPBackend.GetUDPBuffer()
				if dataLen, srcAddr, err := c.conn.ReadFromUDP(buffer); err != nil{
					proxyClientUDPBackend.PutUDPBuffer(buffer)
					return
				}else{
					go proxyClientUDPBackend.HandleUDP(buffer, srcAddr, c.addr, dataLen)
				}
		}

	}
}