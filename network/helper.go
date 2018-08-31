package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"unsafe"

	//"strings"
	"github.com/pkg/errors"
)

const (
	ipv4Regex = "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\:([0-9]+)$"
	ipv6Regex = "^\\[(.+)\\]\\:([0-9]+)$"
)

func ParseIPv4(addr string) (socketAddr syscall.SockaddrInet4, err error){
	var re *regexp.Regexp
	if re , err = regexp.Compile(ipv4Regex); err != nil{
		err = errors.Wrap(err, "Compile ipv4 regex failed")
		return
	}
	if matches := re.FindAllStringSubmatch(addr, -1); len(matches) == 0 && len(matches[0]) != 3{
		err = errors.New(fmt.Sprintf("Invalid ip address %s", addr))
	}else{
		if ipTemp := net.ParseIP(matches[0][1]); ipTemp == nil{
			err = errors.New(fmt.Sprintf("Invalid ip address: %s", matches[0][1]))
			return
		}else{
			ip := [4]byte{}
			copy(ip[:], ipTemp.To4())
			//ip := [4]byte{ipTemp[0], ipTemp[1], ipTemp[2], ipTemp[3]}
			if port, ee := strconv.ParseUint(matches[0][2], 10, 32); ee != nil{
				err = errors.New(fmt.Sprintf("Port parse failed: %s", matches[0][2]))
			}else{
				socketAddr = syscall.SockaddrInet4{Port: int(port), Addr: ip}
			}
		}
	}

	return
}

func ParseIPv6(addr string) (socketAddr syscall.SockaddrInet6, err error){
	var re *regexp.Regexp
	if re , err = regexp.Compile(ipv6Regex); err != nil{
		err = errors.Wrap(err, "Compile ipv6 regex failed")
		return
	}
	if matches := re.FindAllStringSubmatch(addr, -1); len(matches) == 0 && len(matches[0]) != 3{
		err = errors.New(fmt.Sprintf("Invalid ip address %s", addr))
	}else{
		if ipTemp := net.ParseIP(matches[0][1]); ipTemp == nil{
			err = errors.New(fmt.Sprintf("Invalid ip address: %s", matches[0][1]))
			return
		}else{
				ip := [16]byte{}
				copy(ip[:], ipTemp.To16())
				//ip := [16]byte{ipTemp[0], ipTemp[1], ipTemp[2], ipTemp[3], ipTemp[4], ipTemp[5], ipTemp[6], ipTemp[7], ipTemp[8], ipTemp[9], ipTemp[10], ipTemp[11], ipTemp[12], ipTemp[13], ipTemp[14], ipTemp[15]}
			if port, ee := strconv.ParseUint(matches[0][2], 10, 32); ee != nil{
				err = errors.New(fmt.Sprintf("Port parse failed: %s", matches[0][2]))
			}else{
				socketAddr = syscall.SockaddrInet6{Port: int(port), Addr: ip}
			}
		}
	}

	return
}

func ListenTransparentTCP(addr string, isIPv6 bool) (ln net.Listener, err error){
	socketType := syscall.AF_INET
	if isIPv6 {
		socketType = syscall.AF_INET6
	}

	var socketFD int
	if socketFD, err = syscall.Socket(socketType, syscall.SOCK_STREAM, syscall.IPPROTO_TCP); err != nil{
		err = errors.Wrap(err, "Open TCP socket failed")
		return
	}
	defer syscall.Close(socketFD)

	if err = syscall.SetsockoptInt(socketFD, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil{
		err = errors.Wrap(err, "Set sockopt IP_TRANSPARENT failed")
		return
	}

	if isIPv6 {
		var socketAddr syscall.SockaddrInet6
		if socketAddr, err = ParseIPv6(addr); err != nil{
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil{
			err = errors.Wrap(err, "Bind TCP socket failed")
			return
		}
	}else{

		var socketAddr syscall.SockaddrInet4
		if socketAddr, err = ParseIPv4(addr); err != nil{
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil{
			err = errors.Wrap(err, "Bind TCP socket failed")
			return
		}
	}

	syscall.Listen(socketFD, syscall.SOMAXCONN)

	tempFD := os.NewFile(uintptr(socketFD), "listenTCP")
	defer tempFD.Close()

	ln, err = net.FileListener(tempFD)
	return
}

func ListenTransparentUDP(addr string, isIPv6 bool) (ln *net.UDPConn, err error){
	socketType := syscall.AF_INET
	if isIPv6 {
		socketType = syscall.AF_INET6
	}

	var socketFD int
	if socketFD, err = syscall.Socket(socketType, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP); err != nil{
		err = errors.Wrap(err, "Open UDP socket failed")
		return
	}
	defer syscall.Close(socketFD)

	if err = syscall.SetsockoptInt(socketFD, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil{
		err = errors.Wrap(err, "Set sockopt IP_TRANSPARENT failed")
		return
	}
	if err = syscall.SetsockoptInt(socketFD, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1); err != nil{
		err = errors.Wrap(err, "Set sockopt IP_RECVORIGDSTADDR failed")
		return
	}

	if isIPv6 {
		var socketAddr syscall.SockaddrInet6
		if socketAddr, err = ParseIPv6(addr); err != nil{
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil{
			err = errors.Wrap(err, "Bind UDP socket failed")
			return
		}
	}else{

		var socketAddr syscall.SockaddrInet4
		if socketAddr, err = ParseIPv4(addr); err != nil{
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil{
			err = errors.Wrap(err, "Bind UDP socket failed")
			return
		}
	}

	tempFD := os.NewFile(uintptr(socketFD), "listenUDP")
	defer tempFD.Close()

	var conn net.Conn
	conn, err = net.FileConn(tempFD)
	if err == nil{
		ln = conn.(*net.UDPConn)
	}

	return
}

func ReadFromTransparentUDP(conn *net.UDPConn, b []byte, oob []byte) (len int, src *net.UDPAddr, dst *net.UDPAddr, err error){
	var oobn int
	if len, oobn, _, src, err = conn.ReadMsgUDP(b, oob); err != nil{
		return
	}

	var socketControlMsgs []syscall.SocketControlMessage
	if socketControlMsgs, err = syscall.ParseSocketControlMessage(oob[:oobn]); err != nil{
		return
	}

	for _, msg := range socketControlMsgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			originalDstRaw := &syscall.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				err = errors.Wrap(err, "Reading UDP original dst failed")
				return
			}
			switch originalDstRaw.Family {
				case syscall.AF_INET:
					pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
					p := (*[2]byte)(unsafe.Pointer(&pp.Port))
					dst = &net.UDPAddr{
						IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
						Port: int(p[0])<<8 + int(p[1]),
					}

				case syscall.AF_INET6:
					pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(originalDstRaw))
					p := (*[2]byte)(unsafe.Pointer(&pp.Port))
					dst = &net.UDPAddr{
						IP:   net.IP(pp.Addr[:]),
						Port: int(p[0])<<8 + int(p[1]),
						Zone: strconv.Itoa(int(pp.Scope_id)),
					}

				default:
					err = errors.Wrapf(err, fmt.Sprintf("UDP original dst is an unsupported network family: %v", originalDstRaw.Family))
					return
			}
		}
	}
	if dst == nil{
		err = errors.New("Can not obtain UDP origin dst")
	}

	return
}