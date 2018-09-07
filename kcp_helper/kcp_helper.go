package kcp_helper

import (
	"crypto/sha1"
	"fmt"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
	"net"
)

func GetCipher(name string, password string) (kcp.BlockCrypt, error){
	var err error
	var ret kcp.BlockCrypt

	pass := pbkdf2.Key([]byte(password), []byte("1111"), 4096, 32, sha1.New)

	switch name {
	case "sm4":
		ret, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		ret, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		ret, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		ret, _ =  kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		ret, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		ret, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		ret, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		ret, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		ret, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		ret, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		ret, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		ret, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		err = errors.New(fmt.Sprintf("Unknown Kcp cither %s",  name))
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
func GetModeSetting(mode string, noDelay, interval, resend, noCongestion int) (int, int, int, int){
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