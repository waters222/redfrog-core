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

func CheckIPFamily(addr string) (ret bool, err error) {
	var re *regexp.Regexp
	if re , err = regexp.Compile(ipv4Regex); err != nil{
		err = errors.Wrap(err, "Compile ip regex failed")
	}else{
		if matches := re.FindAllStringSubmatch(addr, -1); len(matches) != 0 && len(matches[0]) == 3 {
			ret = false
			return
		}
	}

	if re , err = regexp.Compile(ipv6Regex); err != nil{
		err = errors.Wrap(err, "Compile ip regex failed")
	}else{
		if matches := re.FindAllStringSubmatch(addr, -1); len(matches) != 0 && len(matches[0]) == 3 {
			ret = true
			return
		}
	}


	return
}


func ParseAddr(addr string, isIpV6 bool) (ip net.IP, port int, err error){
	var re *regexp.Regexp
	regexSelection := ipv4Regex
	if isIpV6 {
		regexSelection = ipv6Regex
	}
	if re , err = regexp.Compile(regexSelection); err != nil{
		err = errors.Wrap(err, "Compile ip regex failed")
		return
	}
	if matches := re.FindAllStringSubmatch(addr, -1); len(matches) == 0 && len(matches[0]) != 3{
		err = errors.New(fmt.Sprintf("Invalid ip address %s", addr))
	}else{
		var portTemp uint64
		if ip = net.ParseIP(matches[0][1]); ip == nil{
			err = errors.New(fmt.Sprintf("Invalid ip address: %s", matches[0][1]))
		}else if portTemp, err = strconv.ParseUint(matches[0][2], 10, 32); err != nil{
			err = errors.New(fmt.Sprintf("Port parse failed: %s", matches[0][2]))
		}else{
			port = int(portTemp)
		}
	}

	return
}


func ParseIPv4(addr string) (socketAddr syscall.SockaddrInet4, err error){
	var ip net.IP
	var port int
	if ip, port, err = ParseAddr(addr, false); err != nil{
		return
	}
	ipBuffer := [net.IPv4len]byte{}
	copy(ipBuffer[:], ip.To4())
	socketAddr = syscall.SockaddrInet4{Port: port, Addr: ipBuffer}

	return

}

func ParseIPv6(addr string) (socketAddr syscall.SockaddrInet6, err error){

	var ip net.IP
	var port int
	if ip, port, err = ParseAddr(addr, true); err != nil{
		return
	}
	ipBuffer := [net.IPv6len]byte{}
	copy(ipBuffer[:], ip.To16())
	socketAddr = syscall.SockaddrInet6{Port: port, Addr: ipBuffer}

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

func DialTransparentUDP(addr *net.UDPAddr, isIPv6 bool) (ln *net.UDPConn, err error){
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


	if isIPv6 {
		ip := [net.IPv6len]byte{}
		copy(ip[:], addr.IP.To16())
		socketAddr := syscall.SockaddrInet6{Addr: ip, Port:addr.Port}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil{
			err = errors.Wrap(err, "Bind UDP socket failed")
			return
		}

	}else{
		ip := [net.IPv4len]byte{}
		copy(ip[:], addr.IP.To4())
		socketAddr := syscall.SockaddrInet4{Addr: ip, Port:addr.Port}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil{
			err = errors.Wrap(err, fmt.Sprintf("Bind UDP socket %s failed", addr.String()))
			return
		}
	}

	tempFD := os.NewFile(uintptr(socketFD), fmt.Sprintf("dialUDP %s", addr.String()))
	defer tempFD.Close()

	var conn net.Conn
	conn, err = net.FileConn(tempFD)
	if err == nil{
		ln = conn.(*net.UDPConn)
	}

	return
}