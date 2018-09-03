package proxy_client

import(
	"fmt"
	"github.com/pkg/errors"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/weishi258/redfrog-core/config"
	"github.com/weishi258/redfrog-core/network"
	"net"
)
type proxyBackend struct{
	cipher_		core.Cipher
	addr_		net.TCPAddr
}

func InitProxyBackend(config config.ServerConfig) (ret *proxyBackend, err error){

	ret = &proxyBackend{}

	var isIPv6 bool
	if isIPv6, err = network.CheckIPFamily(config.RemoteServer); err != nil{
		err = errors.Wrap(err, fmt.Sprintf("Invalid IP format: %s", config.RemoteServer))
		return
	}
	if ip, port, error := network.ParseAddr(config.RemoteServer, isIPv6); error != nil{
		err = errors.Wrap(error, "Parse IPv4 failed")
		return
	}else{
		ret.addr_ = net.TCPAddr{IP: ip, Port: port}
	}


	if ret.cipher_, err = core.PickCipher(config.Crypt, []byte{}, config.Password); err != nil{
		err = errors.Wrap(err, "Generate cipher failed")
		return
	}

	return
}

func (c *proxyBackend) CreateConn(){
	net.Dial()
}