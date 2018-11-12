package common

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"io"
	"io/ioutil"
	"net"
	"os/exec"
	"strings"
)

const (
	AtTypeUdpIpv4 = 51
	AtTypeUdpIpv6 = 52
)

func GenerateDomainStubs(domain string) []string {
	if len(domain) == 0 {
		return nil
	}
	stubs := strings.Split(domain, ".")
	{
		segs := make([]string, 0)
		for _, stub := range stubs {
			if len(stub) > 0 {
				segs = append(segs, stub)
			}
		}
		stubs = segs
	}

	len := len(stubs)
	for i := len - 2; i >= 0; i-- {
		stubs[i] = fmt.Sprintf("%s.%s", stubs[i], stubs[i+1])
	}
	return stubs
}

func PipeCommand(cmds ...*exec.Cmd) (output []byte, err error) {

	length := len(cmds)

	if length == 0 {
		err = errors.New("No command to exec")
		return
	}
	preCmd := cmds[0]
	for i := 1; i < length; i++ {
		cmd := cmds[i]
		if cmd.Stdin, err = preCmd.StdoutPipe(); err != nil {
			return
		}
		if err = preCmd.Start(); err != nil {
			return
		}
		preCmd = cmd
	}
	var finalOut io.ReadCloser
	if finalOut, err = preCmd.StdoutPipe(); err != nil {
		return
	}
	if err = preCmd.Start(); err != nil {
		return
	}

	output, err = ioutil.ReadAll(finalOut)

	for i := 0; i < length; i++ {
		if err = cmds[i].Wait(); err != nil {
			return
		}
	}

	return
}

func ReadShadowsocksHeader(r io.Reader) (bool, socks.Addr, error) {
	b := make([]byte, socks.MaxAddrLen)
	_, err := io.ReadFull(r, b[:1]) // read 1st byte for address type
	if err != nil {
		return false, nil, err
	}

	switch b[0] {
	case socks.AtypDomainName:
		_, err = io.ReadFull(r, b[1:2]) // read 2nd byte for domain length
		if err != nil {
			return false, nil, err
		}
		_, err = io.ReadFull(r, b[2:2+int(b[1])+2])
		return false, b[:1+1+int(b[1])+2], err
	case socks.AtypIPv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return false, b[:1+net.IPv4len+2], err
	case socks.AtypIPv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return false, b[:1+net.IPv6len+2], err
	case AtTypeUdpIpv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return true, b[:1+net.IPv4len+2], err
	case AtTypeUdpIpv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return true, b[:1+net.IPv6len+2], err
	}

	return false, nil, socks.ErrAddressNotSupported
}

func ReadUdpOverTcp(r io.Reader, buffer []byte) (int, error) {
	// read udp packet size info
	_, err := io.ReadFull(r, buffer[:2])
	if err != nil {
		return 0, err
	}
	packetSize := binary.BigEndian.Uint16(buffer[:2])
	return io.ReadFull(r, buffer[:packetSize])
}

func WriteUdpOverTcp(w io.Writer, buffer []byte) (int, error) {
	packetSize := uint16(len(buffer))
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, packetSize)

	w.Write(b)
	return w.Write(buffer)
}
