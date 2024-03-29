package common

import (
	"github.com/miekg/dns"
	"net"
	"time"
)

const (
//DOMAIN_WHITE_LIST = false
//DOMAIN_BLACK_LIST = true
)
const (
	UDP_BUFFER_POOL_SIZE = 1024 * 10
	UDP_BUFFER_SIZE      = 1024 * 4

	DNS_BUFFER_POOL_SIZE = 1024 * 4
	DNS_BUFFER_SIZE      = 1024 * 2

	UDP_OOB_POOL_SIZE   = 512
	UDP_OOB_BUFFER_SIZE = 1024 * 2

	CHANNEL_QUEUE_LENGTH = 5

	DOMAIN_BLACK_LIST = true
	DOMAIN_WHITE_LIST = false
)

type DNSServerInterface interface {
	ServerDNSPacket(msg *dns.Msg) ([]byte, error)
}

type ProxyClientInterface interface {
	ExchangeDNS(dnsAddr string, data []byte, timeout time.Duration) (response *dns.Msg, err error)
	SetDNSProcessor(server DNSServerInterface)
	HandleUDP(buffer []byte, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, dataLen int)
	GetUDPBuffer() []byte
	PutUDPBuffer(buffer []byte)
}
