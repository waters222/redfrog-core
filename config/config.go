package config

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/weishi258/redfrog-core/common"
	"github.com/weishi258/redfrog-core/log"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/exec"
)

type KcptunConfig struct {
	Enable            bool   `yaml:"enable"`
	Server            string `yaml:"server"`
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
func (c *KcptunConfig)Equal(other *KcptunConfig) bool{
	if c.Enable == other.Enable &&
		c.Server == other.Server &&
		c.Mode == other.Mode &&
		c.Conn == other.Conn &&
		c.AutoExpire == other.AutoExpire &&
		c.Mtu == other.Mtu &&
		c.Sndwnd == other.Sndwnd &&
		c.Rcvwnd == other.Rcvwnd &&
		c.Datashard == other.Datashard &&
		c.Parityshard == other.Parityshard &&
		c.Dscp == other.Dscp &&
		c.Nocomp == other.Nocomp &&
		c.Sockbuf == other.Sockbuf &&
		c.KeepAliveTimeout == other.KeepAliveTimeout &&
		c.KeepAliveInterval == other.KeepAliveInterval &&
		c.Acknodelay == other.Acknodelay &&
		c.Nodelay == other.Nodelay &&
		c.Interval == other.Interval &&
		c.Resend == other.Resend &&
		c.NoCongestion == other.NoCongestion &&
		c.ScavengeTTL == other.ScavengeTTL &&
		c.ListenAddr == other.ListenAddr &&
		c.ThreadCount == other.ThreadCount {
			return true
	}

	return false
}


type RemoteServerConfig struct {
	Enable		bool			`yaml:"enable"`
	UdpTimeout   int          `yaml:"udp-timeout"`
	TcpTimeout   int          `yaml:"tcp-timeout"`
	RemoteServer string       `yaml:"remote-server"`
	Crypt        string       `yaml:"crypt"`
	Password     string       `yaml:"password"`
	Kcptun       KcptunConfig `yaml:"kcptun"`
}

func (c *RemoteServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig RemoteServerConfig
	raw := rawConfig{
		TcpTimeout: 120,
		UdpTimeout: 60,
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}
	*c = RemoteServerConfig(raw)
	return nil
}
func (c *RemoteServerConfig) Equal(other *RemoteServerConfig) bool{
	if c.Enable == other.Enable &&
		c.UdpTimeout == other.UdpTimeout &&
		c.TcpTimeout == other.TcpTimeout &&
		c.RemoteServer == other.RemoteServer &&
		c.Crypt == other.Crypt &&
		c.Password == other.Password &&
		c.Kcptun.Equal(&other.Kcptun){
			return true
	}
	return false
}

type ShadowsocksConfig struct {
	Servers []RemoteServerConfig `yaml:"servers"`
}

type DnsFilterConfig struct {
	Enable			bool 		`yaml:"enable"`
	WhiteLists		[]string	`yaml:"white-list"`
	BlackLists		[]string	`yaml:"black-list"`
}

type DnsConfig struct {
	LocalResolver []string       	`yaml:"local-resolver"`
	ProxyResolver []string       	`yaml:"proxy-resolver"`
	SendNum       int            	`yaml:"send-num"`
	Timeout		  int			 	`yaml:"timeout"`
	Cache         bool 				`yaml:"cache"`
	FilterConfig  DnsFilterConfig 	`yaml:"filter"`
}

func (c *DnsConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig DnsConfig
	raw := rawConfig{
		SendNum : 1,
		Cache : true,
		Timeout: 5,
	}

	if err := unmarshal(&raw); err != nil {
		return err
	}

	*c = DnsConfig(raw)
	return nil
}

type Config struct {
	Dns          DnsConfig         `yaml:"dns"`
	Shadowsocks  ShadowsocksConfig `yaml:"shadowsocks"`
	PacketMask   string            `yaml:"packet-mask"`
	ListenPort   int               `yaml:"listen-port"`
	IgnoreIP     []string          `yaml:"ignore-ip"`
	Interface    []string           `yaml:"interface"`
	PacList      []string          `yaml:"pac-list"`
	RoutingTable int               `yaml:"routing-table"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig Config
	raw := rawConfig{
		PacketMask:   "0x1/0x1",
		RoutingTable: 100,
		IgnoreIP:     []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"},
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

	// make sure no duplicate shadowsocks server
	shadowsocksServer := make(map[string]bool)
	serversFiltered := make([]RemoteServerConfig, 0)
	for _, serverConfig := range ret.Shadowsocks.Servers{
		if _, ok := shadowsocksServer[serverConfig.RemoteServer]; !ok{
			shadowsocksServer[serverConfig.RemoteServer] = true
			serversFiltered = append(serversFiltered, serverConfig)
		}else{
			log.GetLogger().Warn("Found duplicate shadowsocks server", zap.Any("config", serverConfig))
		}
	}
	ret.Shadowsocks.Servers = serversFiltered


	// check local resolver

	if ret.Dns.LocalResolver == nil || len(ret.Dns.LocalResolver) == 0{
		var serversBytes []byte
		if serversBytes, err = common.PipeCommand(exec.Command("cat", "/etc/resolv.conf"),
													exec.Command("grep", "-i", "^nameserver"),
													exec.Command("head", "-n5"),
													exec.Command("cut", "-d", " ", "-f2")); err != nil{
			err = errors.Wrap(err,"extract dns server from /etc/resolve.conf failed")
			return
		}
		if len(serversBytes) == 0{
			err = errors.New("extract dns server from /etc/resolve.conf failed: because its empty")
			return
		}
		stubs := bytes.Split(serversBytes, []byte{'\n'})
		ret.Dns.LocalResolver = make([]string, 0)
		for _, stub := range stubs{
			if len(stub) > 0{
				stub = bytes.TrimSpace(stub)
				ret.Dns.LocalResolver = append(ret.Dns.LocalResolver, string(stub[:]))
			}
		}
		if len(ret.Dns.LocalResolver) == 0{
			err = errors.New("extract dns server from /etc/resolve.conf failed: format wrong")
			return
		}
	}
	return
}
