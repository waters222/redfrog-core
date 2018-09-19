package proxy_client

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/weishi258/kcp-go-ng"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/kcp_helper"
	"github.com/weishi258/redfrog-core/log"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
	"sync"
	"time"
)

const (
	SCAVENGER_COUNT = 128
)

type muxConn struct {
	session *smux.Session
	ttl     time.Time
}

type KCPBackend struct {
	smuxConfig *smux.Config
	config     config.KcptunConfig
	cipher     kcp.AheadCipher

	muxConns   []muxConn
	scavengers chan *smux.Session

	sync.Mutex
	connCount int
}

func StartKCPBackend(config config.KcptunConfig, crypt string, password string) (ret *KCPBackend, err error) {
	ret = &KCPBackend{}
	ret.config = config
	ret.smuxConfig = smux.DefaultConfig()
	ret.smuxConfig.MaxReceiveBuffer = config.Sockbuf
	ret.smuxConfig.KeepAliveInterval = time.Duration(config.KeepAliveInterval) * time.Second
	ret.smuxConfig.KeepAliveTimeout = time.Duration(config.KeepAliveTimeout) * time.Second

	ret.config.Nodelay, ret.config.Interval, ret.config.Resend, ret.config.NoCongestion = kcp_helper.GetModeSetting(ret.config.Mode,
		ret.config.Nodelay,
		ret.config.Interval,
		ret.config.Resend,
		ret.config.NoCongestion)

	if ret.cipher, err = kcp_helper.GetCipher(crypt, password); err != nil {
		err = errors.Wrap(err, "Create Kcp cipher failed")
		return
	}

	if config.Conn > 0 {
		ret.muxConns = make([]muxConn, config.Conn)
	} else {
		ret.muxConns = make([]muxConn, 1)
	}

	// we do not wait create kcp connection to block our main logic
	// so try to create conn, if failed then spawn go routing to do the job
	ret.Lock()
	for idx := range ret.muxConns {
		if conn, err := ret.createConn(); err != nil {
			go func() {
				newConn := ret.waitConn()
				ret.Lock()
				defer ret.Unlock()
				ret.muxConns[idx].session = newConn
				ret.muxConns[idx].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
			}()
		} else {
			ret.muxConns[idx].session = conn
			ret.muxConns[idx].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
		}

	}
	ret.Unlock()

	ret.scavengers = make(chan *smux.Session, SCAVENGER_COUNT)
	go ret.scavenger()

	log.GetLogger().Info("Kcp client start successful")
	return
}

func (c *KCPBackend) Stop() {
	logger := log.GetLogger()
	c.Lock()
	defer c.Unlock()
	for idx := range c.muxConns {
		if err := c.muxConns[idx].session.Close(); err != nil {
			logger.Error("Kcp close muxConn failed", zap.String("error", err.Error()))
		}

	}
	logger.Info("KCP backend stopped", zap.String("addr", c.config.Server))

}

func (c *KCPBackend) waitConn() *smux.Session {
	logger := log.GetLogger()
	for {
		if session, err := c.createConn(); err != nil {
			logger.Info("Kcp re-connecting and sleep for 1 seconds", zap.String("error", err.Error()))
			time.Sleep(time.Second)
		} else {
			return session
		}
	}
}

func (c *KCPBackend) createConn() (ret *smux.Session, err error) {
	kcpConn, err := kcp.DialWithOptionsAhead(c.config.Server, c.cipher, c.config.ThreadCount, c.config.Datashard, c.config.Parityshard)
	if err != nil {
		err = errors.Wrap(err, "Kcp create connection failed")
		return
	}

	kcpConn.SetStreamMode(true)
	kcpConn.SetWriteDelay(true)
	kcpConn.SetNoDelay(c.config.Nodelay, c.config.Interval, c.config.Resend, c.config.NoCongestion)
	kcpConn.SetWindowSize(c.config.Sndwnd, c.config.Rcvwnd)
	kcpConn.SetMtu(c.config.Mtu)
	kcpConn.SetACKNoDelay(c.config.Acknodelay)

	//if err = kcpConn.SetDSCP(c.config.Dscp); err != nil {
	//	log.GetLogger().Warn("Set DSCP failed", zap.String("error", err.Error()))
	//}

	if err = kcpConn.SetReadBuffer(c.config.Sockbuf); err != nil {
		err = errors.Wrap(err, "Set ReadBuffer failed")
		return
	}
	if err = kcpConn.SetWriteBuffer(c.config.Sockbuf); err != nil {
		err = errors.Wrap(err, "Set WriteBuffer failed")
		return
	}

	if c.config.Nocomp {
		if ret, err = smux.Client(kcpConn, c.smuxConfig); err != nil {
			err = errors.Wrap(err, "Kcp create smux client failed")
		}
	} else {
		if ret, err = smux.Client(kcp_helper.NewCompStream(kcpConn), c.smuxConfig); err != nil {
			err = errors.Wrap(err, "Kcp create smux client failed")
		}
	}

	return
}

func (c *KCPBackend) getSession() (sess *smux.Session, err error) {
	// modified for concurrence
	c.Lock()
	defer c.Unlock()
	idx := c.connCount % c.config.Conn
	c.connCount++
	sess = c.muxConns[idx].session
	ttl := c.muxConns[idx].ttl

	if sess != nil {
		if sess.IsClosed() || (c.config.AutoExpire > 0 && time.Now().After(ttl)) {
			c.scavengers <- sess
			// set session to nil so this slot is un-usable until waitConn return newConn
			c.muxConns[idx].session = nil
			c.muxConns[idx].ttl = time.Now()

			if sess, err = c.createConn(); err != nil {
				// well, we do not wait to wait for new connection
				go func() {
					sess = c.waitConn()
					c.Lock()
					defer c.Unlock()
					c.muxConns[idx].session = sess
					c.muxConns[idx].ttl = time.Now().Add(time.Duration(c.config.AutoExpire) * time.Second)
				}()
				return nil, errors.Wrap(err, fmt.Sprintf("Kcp connection is re-connecting for slot %d", idx))
			} else {
				c.muxConns[idx].session = sess
				c.muxConns[idx].ttl = time.Now().Add(time.Duration(c.config.AutoExpire) * time.Second)
			}
		}
		return sess, nil
	}
	return nil, errors.New(fmt.Sprintf("Kcp connection is re-connecting for slot %d", idx))
}

func (c *KCPBackend) GetKcpConn() (*smux.Stream, error) {
	sess, err := c.getSession()
	if err != nil {
		return nil, err
	}
	kcpConn, err := sess.OpenStream()
	if err != nil {
		return nil, errors.Wrap(err, "Kcp open stream failed")
	}
	return kcpConn, nil
}

func (c *KCPBackend) scavenger() {
	logger := log.GetLogger()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []muxConn
	for {
		select {
		case sess := <-c.scavengers:
			sessionList = append(sessionList, muxConn{sess, time.Now()})
			logger.Debug("Session marked as expired")
		case <-ticker.C:
			var newList []muxConn
			for k := range sessionList {
				s := sessionList[k]
				if s.session.NumStreams() == 0 || s.session.IsClosed() {
					logger.Debug("Session normally closed")
					s.session.Close()
				} else if c.config.ScavengeTTL >= 0 && time.Since(s.ttl) >= time.Duration(c.config.ScavengeTTL)*time.Second {
					logger.Debug("Session reached scavenge ttl")
					s.session.Close()
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}
