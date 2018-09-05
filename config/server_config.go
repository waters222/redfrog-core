package config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type ServerConfig struct {
	ListenPort			int 	`yaml:"listen-port"`
	UdpTimeout			int 	`yaml:"udp-timeout"`
	TcpTimeout			int 	`yaml:"tcp-timeout"`
	Crypt				string 	`yaml:"Crypt"`
	Password			string 	`yaml:"password"`
	Kcptun			KcptunConfig	`yaml:"kcptun"`
}



func ParseServerConfig(path string) (ret ServerConfig, err error){
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

	ret = ServerConfig{}
	if err = yaml.Unmarshal(data, &ret); err != nil{
		err = errors.Wrapf(err, "Parse config file %s failed", path)
		return
	}

	return
}
