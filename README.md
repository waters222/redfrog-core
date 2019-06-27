# RedFrog

Gateway level shadowsocks client/server for passing through firewall and censorship.
____

#1. How to build
```bash
## clone repo
git clone https://github.com/weishi258/redfrog-core
## install dependency
dep ensure -v 
### build multiple x86 & arm based client & server
./build.sh
```

#2. Deploy server
1. upload build server binary (e.g redfrog-server) to remote server

2. simple run the server with command
```bash
./redfrog-server -c sample-server.yaml -log output.log
```

3. adding to linux systemd service  
a. copy server binary to location <path/redfrog-server>  
b. adding new service file to location `/etc/systemd/system/redfrogserver.service`

```
[Unit]
After=network.target

[Service]
ExecStart=<path>/redfrog-server -c <path>/sample-server.yaml -log <path>/output.log
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
Type=simple
User=root

[Install]
WantedBy=default.target
```
c. start service: `systemctl start redfrogserver`
  
d. enable service for auto start: `systemctl enable redfrogserver`

#3. Deploy client
1. upload client binary to local gateway server
  
2. Simple run the client with command
```bash
<path>/redfrog-client -c <path>/prod-config.yaml -d <path>/redfrog -log <path>/output.log
``` 

3, Adding to linux systemd service
a. adding new service file to location `/etc/systemd/system/redfrogserver.service`
```
[Unit]
After=network.target

[Service]
ExecStart=<path>/redfrog-client-arm64 -c<path>/prod-config.yaml -d <path>/redfrog -log<path>/output.log
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
Type=simple
User=root

[Install]
WantedBy=default.target
```
b. start service: `systemctl start redfrog`  
c. enable service: `systemctl enable redfrog`

#4 Server config explain
this config start the proxy server to listen on two ports: 8420 and 8421 with kcptun support
```yaml
servers:
  - listen-addr: "0.0.0.0:8420"
    tcp-timeout: 120
    udp-timeout: 60
    crypt: "AEAD_CHACHA20_POLY1305"
    Password: "123321A"
    kcptun:
      enable: true
      listen-addr: "0.0.0.0:8420"
      mode: "fast"
      thread: 4
      conn: 4
      autoexpire: 0
      mtu: 1350
      sndwnd: 128
      rcvwnd: 512
      datashard: -1
      parityshard: -1
      dscp: 0
      nocomp: false
      keep-alive-interval: 10
      keep-alive-timeout: 30
      sock-buf : 4194304
  - listen-addr: "0.0.0.0:8421"
    tcp-timeout: 120
    udp-timeout: 60
    crypt: "AEAD_CHACHA20_POLY1305"
    Password: "123321A"
    kcptun:
      enable: true
      listen-addr: "0.0.0.0:8421"
      mode: "fast"
      thread: 4
      conn: 4
      autoexpire: 0
      mtu: 1350
      sndwnd: 128
      rcvwnd: 512
      datashard: -1
      parityshard: -1
      dscp: 0
      nocomp: false
      keep-alive-interval: 10
      keep-alive-timeout: 30
      sock-buf : 4194304
```

#5 Client config explain
it start the proxy client with dns filter on
1. Add multiple pac lists to the tag `pac-list`
2. Add multiple proxy connection (it will use round robin) to remote server with kcptun enabled
```yaml
packet-mask: "0x1/0x1"
routing-table: 100
listen-port: 9090
ipset: true
dns:
  listen-addr: "192.168.0.2:53"
  proxy-resolver:
  - "127.0.0.11"
  timeout: 5
  cache: false
  filter:
    enable: true
    white-list:
    - "white.txt"
    black-list:
    - "black.txt"
pac-list:
  - "gfw-list.txt"
  - "custom-list.txt"
shadowsocks:
  servers:
  - enable: true
    remote-server: "192.168.1.2:8420"
    crypt: "AEAD_CHACHA20_POLY1305"
    Password: "123321A"
    tcp-timeout: 20
    udp-timeout: 10
    udp-over-tcp: true
    kcptun:
      enable: true
      server: "192.168.1.2:8420"
      mode: "fast"
      thread: 1
      conn: 1
      autoexpire: 0
      mtu: 1350
      sndwnd: 128
      rcvwnd: 512
      datashard: -1
      parityshard: -1
      dscp: 0
      nocomp: false
      keep-alive-interval: 10
      keep-alive-timeout: 30
      sock-buf : 4194304
  - enable: true
    remote-server: "192.168.1.2:8421"
    crypt: "AEAD_CHACHA20_POLY1305"
    Password: "123321A"
    tcp-timeout: 20
    udp-timeout: 10
    udp-over-tcp: true
    kcptun:
      enable: true
      server: "192.168.1.2:8421"
      mode: "fast"
      thread: 1
      conn: 1
      autoexpire: 0
      mtu: 1350
      sndwnd: 128
      rcvwnd: 512
      datashard: -1
      parityshard: -1
      dscp: 0
      nocomp: false
      keep-alive-interval: 10
      keep-alive-timeout: 30
      sock-buf : 4194304
```

#6 How to use it for local network devices
The client is gateway level rule based proxy all you need to do is:
1. config the local router to use the client device ip as the new gateway and DNS server
2. config each device to use the client device as gateway and DNS server