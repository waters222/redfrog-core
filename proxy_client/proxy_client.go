package proxy_client

import "github.com/weishi258/redfrog-core/config"

type ProxyClient struct {
	servers_				[]proxyBackend
	udpLeakyBuffer_ 		chan[][]byte

}

func StartProxyClient(config config.ShadowsocksConfig) (err error){

	return
}

func (c *ProxyClient)Stop(){

}