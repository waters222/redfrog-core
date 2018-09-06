package config

import (
	"os"
	"io/ioutil"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	)


type DnsConfig struct {
	ListenAddr			string 		`yaml:"listen-addr"`
	LocalResolver		[]string	`yaml:"local-resolver"`
	ProxyResolver		[]string	`yaml:"proxy-resolver"`
	DnsTimeout			int			`yaml:"dns-timeout"`

}

type KcptunConfig struct {
	Enable		bool		`yaml:"enable"`
	RemoteServer 	string 		`yaml:"remote-server"`
	Crypt			string 		`yaml:"crypt"`
	Key				string 		`yaml:"key"`
	Mode			string 		`yaml:"mode"`
	Conn			int			`yaml:"conn"`
	AutoExpire		int			`yaml:"autoexpire"`
	Mtu				int			`yaml:"mtu"`
	Sndwnd			int			`yaml:"sndwnd"`
	Rcvwnd			int			`yaml:"rcvwnd"`
	Datashard		int			`yaml:"datashard"`
	Parityshard		int			`yaml:"parityshard"`
	Dscp			int			`yaml:"dscp"`
	Nocomp			bool		`yaml:"nocomp"`
}

type RemoteServerConfig struct{
	RemoteServer	string 			`yaml:"remote-server"`
	Crypt			string 			`yaml:"crypt"`
	Password		string 			`yaml:"password"`
	Kcptun			KcptunConfig	`yaml:"kcptun"`
}

type ShadowsocksConfig struct{
	ListenAddr 		string            `yaml:"listen-addr"`
	UdpTimeout 		int               `yaml:"udp-timeout"`
	TcpTimeout 		int               `yaml:"tcp-timeout"`
	PacList   		[]string             `yaml:"pac-list"`
	Servers   		[]RemoteServerConfig `yaml:"servers"`
}
type Config struct {
	DefaultNat 		string 				`yaml:"default-nat"`
	Dns				DnsConfig			`yaml:"dns"`
	Shadowsocks 	ShadowsocksConfig 	`yaml:"shadowsocks"`
}

//var config_ *Config
//
//func GetConfig() *Config{
//	return config_
//}
//func setConfig(config *Config){
//	config_ = config
//}

func ParseClientConfig(path string) (ret Config, err error){
	file, err := os.Open(path) // For read access.
	if err != nil {
		err = errors.Wrapf(err, "Open config file %s failed", path)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		err = errors.Wrapf(err, "Read config file %s failed", path)
		return
	}

	ret = Config{}
	if err = yaml.Unmarshal(data, &ret); err != nil{
		err = errors.Wrapf(err, "Parse config file %s failed", path)
		return
	}

	return
}