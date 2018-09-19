package config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type KcptunConfig struct {
	Enable            bool   `yaml:"enable"`
	Server            string `yaml:"server"`
	Crypt             string `yaml:"crypt"`
	Mode              string `yaml:"mode"`
	Conn              int    `yaml:"conn"`
	AutoExpire        int    `yaml:"autoexpire"`
	Mtu               int    `yaml:"mtu"`
	Sndwnd            int    `yaml:"sndwnd"`
	Rcvwnd            int    `yaml:"rcvwnd"`
	Datashard         int    `yaml:"datashard"`
	Parityshard       int    `yaml:"parityshard"`
	Dscp              int    `yaml:"dscp"`
	Nocomp            bool   `yaml:"nocomp"`
	Sockbuf           int    `yaml:"sock-buf"`
	KeepAliveTimeout  int    `yaml:"keep-alive-timeout"`
	KeepAliveInterval int    `yaml:"keep-alive-interval"`
	Acknodelay        bool   `yaml:"acknodelay"`
	Nodelay           int    `yaml:"nodelay"`
	Interval          int    `yaml:"interval"`
	Resend            int    `yaml:"resend"`
	NoCongestion      int    `yaml:"no-congestion"`
	ScavengeTTL       int    `yaml:"scavenge-ttl"`

	ListenAddr  string `yaml:"listen-addr"`
	ThreadCount int    `yaml:"thread"`
}

func (c *KcptunConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig KcptunConfig
	raw := rawConfig{
		Enable:            false,
		Mode:              "fast",
		Conn:              1,
		AutoExpire:        0,
		Mtu:               1350,
		Sndwnd:            128,
		Rcvwnd:            512,
		Datashard:         -1,
		Parityshard:       -1,
		Dscp:              0,
		Nocomp:            false,
		Sockbuf:           4194304,
		KeepAliveInterval: 10,
		KeepAliveTimeout:  120,
		Acknodelay:        true,
		Nodelay:           0,
		Interval:          50,
		Resend:            0,
		NoCongestion:      0,
		ScavengeTTL:       600,
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	*c = KcptunConfig(raw)
	return nil
}

type RemoteServerConfig struct {
	RemoteServer string       `yaml:"remote-server"`
	Crypt        string       `yaml:"crypt"`
	Password     string       `yaml:"password"`
	Kcptun       KcptunConfig `yaml:"kcptun"`
}

type ShadowsocksConfig struct {
	UdpTimeout int                  `yaml:"udp-timeout"`
	TcpTimeout int                  `yaml:"tcp-timeout"`
	PacList    []string             `yaml:"pac-list"`
	Servers    []RemoteServerConfig `yaml:"servers"`
}

func (c *ShadowsocksConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig ShadowsocksConfig
	raw := rawConfig{
		TcpTimeout: 120,
		UdpTimeout: 60,
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}
	*c = ShadowsocksConfig(raw)
	return nil
}

type DnsCacheConfig struct {
	Enable  bool `yaml:"enable"`
	Timeout int  `yaml:"timeout"`
}

type DnsConfig struct {
	ListenAddr    string         `yaml:"listen-addr"`
	LocalResolver []string       `yaml:"local-resolver"`
	ProxyResolver []string       `yaml:"proxy-resolver"`
	DnsTimeout    int            `yaml:"dns-timeout"`
	SendNum       int            `yaml:"send-num"`
	Cache         DnsCacheConfig `yaml:"cache"`
}

func (c *DnsConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig DnsConfig
	raw := rawConfig{
		DnsTimeout: 120,
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}
	*c = DnsConfig(raw)
	return nil
}

type Config struct {
	Dns            DnsConfig         `yaml:"dns"`
	Shadowsocks    ShadowsocksConfig `yaml:"shadowsocks"`
	PacketMask     string            `yaml:"packet-mask"`
	ListenPort     int               `yaml:"listen-port"`
	IgnoreIP       []string          `yaml:"ignore-ip"`

	Gateway 		string            `yaml:"gateway"`
	Addr         	string            `yaml:"addr"`
	InterfaceIn     string            `yaml:"interface-in"`
	InterfaceOut    string            `yaml:"interface-out"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig Config
	raw := rawConfig{
		PacketMask: "0x1/0x1",
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}
	*c = Config(raw)
	return nil
}

func ParseClientConfig(path string) (ret Config, err error) {
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
	if err = yaml.Unmarshal(data, &ret); err != nil {
		err = errors.Wrapf(err, "Parse config file %s failed", path)
		return
	}

	return
}
