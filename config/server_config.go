package config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type ServerSwarmConfig struct {
	Servers				[]ServerConfig	`yaml:"servers"`
}

type ServerConfig struct {
	ListenPort			int 	`yaml:"listen-port"`
	UdpTimeout			int 	`yaml:"udp-timeout"`
	TcpTimeout			int 	`yaml:"tcp-timeout"`
	Crypt				string 	`yaml:"crypt"`
	Password			string 	`yaml:"password"`
	Kcptun			KcptunConfig	`yaml:"kcptun"`
}
func (c * ServerConfig)UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig ServerConfig
	raw := rawConfig{
		TcpTimeout: 120,
		UdpTimeout: 60,
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}
	*c = ServerConfig(raw)
	return nil
}




func ParseServerConfig(path string) (ret ServerSwarmConfig, err error){
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

	ret = ServerSwarmConfig{}
	if err = yaml.Unmarshal(data, &ret); err != nil{
		err = errors.Wrapf(err, "Parse config file %s failed", path)
		return
	}

	return
}
