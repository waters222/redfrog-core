package kcp_helper

import (
	"crypto/sha1"
	"fmt"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/weishi258/kcp-go-ng"
	"golang.org/x/crypto/pbkdf2"
	"net"
)

func GetCipher(name string, password string) (ret kcp.AheadCipher, err error) {
	pass := pbkdf2.Key([]byte(password), []byte("Red_Frog_Rocks!!!"), 4096, 32, sha1.New)

	switch name {
	case "AEAD_CHACHA20_POLY1305":
		ret, _ = kcp.NewChacha20Ploy1305(pass[:32])
	case "AES-128-GCM":
		ret, _ = kcp.NewAES128GCM(pass[:16])
	case "AES-196-GCM":
		ret, _ = kcp.NewAES196GCM(pass[:24])
	case "AES-256-GCM":
		ret, _ = kcp.NewAES256GCM(pass[:32])
	default:
		err = errors.New(fmt.Sprintf("Unknown Kcp cither %s", name))
	}

	return ret, err
}

// helpers
type CompStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func NewCompStream(conn net.Conn) *CompStream {
	c := new(CompStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func (c *CompStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *CompStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *CompStream) Close() error {
	return c.conn.Close()
}

//
func GetModeSetting(mode string, noDelay, interval, resend, noCongestion int) (int, int, int, int) {
	switch mode {
	case "normal":
		return 0, 40, 2, 1
	case "fast":
		return 0, 30, 2, 1
	case "fast2":
		return 1, 20, 2, 1
	case "fast3":
		return 1, 10, 2, 1
	}
	return noDelay, interval, resend, noCongestion
}
