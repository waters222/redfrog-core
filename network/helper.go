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

const (
	SOL_IP             = 0
	IP_TRANSPARENT     = 0x13
	IP_RECVORIGDSTADDR = 0x14
)
const (
	ShadowSocksAtypIPv4       = 1
	ShadowSocksAtypDomainName = 3
	ShadowSocksAtypIPv6       = 4
)

func CheckIPFamily(addr string) (ret bool, err error) {
	var re *regexp.Regexp
	if re, err = regexp.Compile(ipv4Regex); err != nil {
		err = errors.Wrap(err, "Compile ip regex failed")
	} else {
		if matches := re.FindAllStringSubmatch(addr, -1); len(matches) != 0 && len(matches[0]) == 3 {
			ret = false
			return
		}
	}

	if re, err = regexp.Compile(ipv6Regex); err != nil {
		err = errors.Wrap(err, "Compile ip regex failed")
	} else {
		if matches := re.FindAllStringSubmatch(addr, -1); len(matches) != 0 && len(matches[0]) == 3 {
			ret = true
			return
		}
	}

	return
}

func ParseAddr(addr string, isIpV6 bool) (ip net.IP, port int, err error) {
	var hostStr string
	var portStr string
	if hostStr, portStr, err = net.SplitHostPort(addr); err != nil {

		return
	}
	var portnum uint64
	if portnum, err = strconv.ParseUint(portStr, 10, 16); err != nil {
		err = errors.Wrap(err, "Port format invalid")
		return
	}
	port = int(portnum)

	ip = net.ParseIP(hostStr)
	if ip == nil {
		err = errors.New("IP format invalid")
		return
	}
	if isIpV6 {
		ip = ip.To16()
		if ip == nil {
			err = errors.New("Its not ipv6 address")
			return
		}
	} else {
		ip = ip.To4()
		if ip == nil {
			err = errors.New("Its not ipv4 address")
			return
		}
	}

	return
}

func ParseIPv4(addr string) (socketAddr syscall.SockaddrInet4, err error) {
	var ip net.IP
	var port int
	if ip, port, err = ParseAddr(addr, false); err != nil {
		return
	}
	ipBuffer := [net.IPv4len]byte{}
	copy(ipBuffer[:], ip.To4())
	socketAddr = syscall.SockaddrInet4{Port: port, Addr: ipBuffer}

	return

}

func ParseIPv6(addr string) (socketAddr syscall.SockaddrInet6, err error) {

	var ip net.IP
	var port int
	if ip, port, err = ParseAddr(addr, true); err != nil {
		return
	}
	ipBuffer := [net.IPv6len]byte{}
	copy(ipBuffer[:], ip.To16())
	socketAddr = syscall.SockaddrInet6{Port: port, Addr: ipBuffer}

	return

}

func ListenTransparentTCP(addr string, isIPv6 bool) (ln net.Listener, err error) {
	socketType := syscall.AF_INET
	if isIPv6 {
		socketType = syscall.AF_INET6
	}

	var socketFD int
	if socketFD, err = syscall.Socket(socketType, syscall.SOCK_STREAM, syscall.IPPROTO_TCP); err != nil {
		err = errors.Wrap(err, "Open TCP socket failed")
		return
	}
	defer syscall.Close(socketFD)

	if err = syscall.SetsockoptInt(socketFD, SOL_IP, IP_TRANSPARENT, 1); err != nil {
		err = errors.Wrap(err, "Set sockopt IP_TRANSPARENT failed")
		return
	}

	if isIPv6 {
		var socketAddr syscall.SockaddrInet6
		if socketAddr, err = ParseIPv6(addr); err != nil {
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil {
			err = errors.Wrap(err, "Bind TCP socket failed")
			return
		}
	} else {

		var socketAddr syscall.SockaddrInet4
		if socketAddr, err = ParseIPv4(addr); err != nil {
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil {
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

func ListenTransparentUDP(addr string, isIPv6 bool) (ln *net.UDPConn, err error) {

	socketType := syscall.AF_INET
	if isIPv6 {
		socketType = syscall.AF_INET6
	}

	var socketFD int
	if socketFD, err = syscall.Socket(socketType, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP); err != nil {
		err = errors.Wrap(err, "Open UDP socket failed")
		return
	}
	defer syscall.Close(socketFD)

	if err = syscall.SetsockoptInt(socketFD, SOL_IP, IP_TRANSPARENT, 1); err != nil {
		err = errors.Wrap(err, "Set sockopt IP_TRANSPARENT failed")
		return
	}
	if err = syscall.SetsockoptInt(socketFD, SOL_IP, IP_RECVORIGDSTADDR, 1); err != nil {
		err = errors.Wrap(err, "Set sockopt IP_RECVORIGDSTADDR failed")
		return
	}

	if isIPv6 {
		var socketAddr syscall.SockaddrInet6
		if socketAddr, err = ParseIPv6(addr); err != nil {
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil {
			err = errors.Wrap(err, "Bind UDP socket failed")
			return
		}
	} else {

		var socketAddr syscall.SockaddrInet4
		if socketAddr, err = ParseIPv4(addr); err != nil {
			return
		}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil {
			err = errors.Wrap(err, "Bind UDP socket failed")
			return
		}
	}

	tempFD := os.NewFile(uintptr(socketFD), "listenUDP")
	defer tempFD.Close()

	var conn net.Conn
	conn, err = net.FileConn(tempFD)
	if err == nil {
		ln = conn.(*net.UDPConn)
	}

	return
}

func ExtractOrigDstFromUDP(oobLen int, oobBuffer []byte) (dst *net.UDPAddr, err error) {
	var socketControlMsgs []syscall.SocketControlMessage
	if socketControlMsgs, err = syscall.ParseSocketControlMessage(oobBuffer[:oobLen]); err != nil {
		return
	}

	for _, msg := range socketControlMsgs {
		if msg.Header.Level == SOL_IP && msg.Header.Type == IP_RECVORIGDSTADDR {
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
	if dst == nil {
		err = errors.New("Can not obtain UDP origin dst")
	}

	return
}

func DialTransparentUDP(addr *net.UDPAddr) (ln *net.UDPConn, err error) {

	isIPv6 := addr.IP.To4() == nil

	socketType := syscall.AF_INET
	if isIPv6 {
		socketType = syscall.AF_INET6
	}

	var socketFD int
	if socketFD, err = syscall.Socket(socketType, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP); err != nil {
		err = errors.Wrap(err, "Open UDP socket failed")
		return
	}
	defer syscall.Close(socketFD)

	if err = syscall.SetsockoptInt(socketFD, SOL_IP, IP_TRANSPARENT, 1); err != nil {
		err = errors.Wrap(err, "Set sockopt IP_TRANSPARENT failed")
		return
	}

	if isIPv6 {
		ip := [net.IPv6len]byte{}
		copy(ip[:], addr.IP.To16())
		socketAddr := syscall.SockaddrInet6{Addr: ip, Port: addr.Port}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil {
			err = errors.Wrap(err, "Bind UDP socket failed")
			return
		}

	} else {
		ip := [net.IPv4len]byte{}
		copy(ip[:], addr.IP.To4())
		socketAddr := syscall.SockaddrInet4{Addr: ip, Port: addr.Port}
		if err = syscall.Bind(socketFD, &socketAddr); err != nil {
			err = errors.Wrap(err, fmt.Sprintf("Bind UDP socket %s failed", addr.String()))
			return
		}
	}

	tempFD := os.NewFile(uintptr(socketFD), fmt.Sprintf("dialUDP %s", addr.String()))
	defer tempFD.Close()

	var conn net.Conn
	conn, err = net.FileConn(tempFD)
	if err == nil {
		ln = conn.(*net.UDPConn)
	}

	return
}

func ConvertShadowSocksAddr(addr string) ([]byte, error) {
	var ret []byte
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("IP format invalid")
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		ret = make([]byte, 1+net.IPv4len+2)
		ret[0] = ShadowSocksAtypIPv4
		copy(ret[1:], ipv4)
	} else {
		ret = make([]byte, 1+net.IPv6len+2)
		ret[0] = ShadowSocksAtypIPv6
		copy(ret[1:], ip)
	}
	var hostPort uint64

	if hostPort, err = strconv.ParseUint(port, 10, 16); err != nil {
		return nil, errors.Wrap(err, "Port number format invalid")
	}

	ret[len(ret)-2], ret[len(ret)-1] = byte(hostPort>>8), byte(hostPort)

	return ret, nil

}

type InterfaceEntry struct {
	Name string
	Addr []string
}

func GetInterface() (entries []InterfaceEntry, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	entries = make([]InterfaceEntry, 0)
	for _, entry := range interfaces {
		if entry.Flags&net.FlagUp == 1 {
			// device is up
			if entry.Flags&net.FlagLoopback == 0 {
				// make sure its not loop back device
				var addrs []net.Addr
				if addrs, err = entry.Addrs(); err == nil && len(addrs) > 0 {
					addresses := make([]string, len(addrs))
					for i, addr := range addrs {
						addresses[i] = addr.String()
					}
					entries = append(entries, InterfaceEntry{entry.Name, addresses})
				}
			}
		}
	}
	if len(entries) == 0 {
		err = errors.New("Can not find valid interface")
		entries = nil
	}
	return
}
