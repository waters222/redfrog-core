module github.com/weishi258/redfrog-core

go 1.12

require (
	github.com/Sirupsen/logrus v1.4.2
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/coreos/go-semver v0.3.0
	github.com/golang/snappy v0.0.1
	github.com/klauspost/crc32 v1.2.0 // indirect
	github.com/miekg/dns v1.1.22
	github.com/onsi/ginkgo v1.10.3 // indirect
	github.com/onsi/gomega v1.7.1 // indirect
	github.com/pkg/errors v0.8.1
	github.com/shadowsocks/go-shadowsocks2 v0.0.11
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/weishi258/go-iptables v0.4.1
	github.com/weishi258/kcp-go-ng v0.0.0-20191205054520-39a714713c69
	github.com/xtaci/smux v1.4.6
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20191202143827-86a70503ff7e
	golang.org/x/sys v0.0.0-20191204072324-ce4227a45e2e
	gopkg.in/airbrake/gobrake.v2 v2.0.9 // indirect
	gopkg.in/gemnasium/logrus-airbrake-hook.v2 v2.1.2 // indirect
	gopkg.in/yaml.v2 v2.2.7
)

replace (
	github.com/Sirupsen/logrus v1.0.5 => github.com/sirupsen/logrus v1.0.5
	github.com/Sirupsen/logrus v1.3.0 => github.com/Sirupsen/logrus v1.0.6
	github.com/Sirupsen/logrus v1.4.0 => github.com/sirupsen/logrus v1.0.6
	github.com/Sirupsen/logrus v1.4.2 => github.com/sirupsen/logrus v1.0.6
)
