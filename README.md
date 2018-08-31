# RedFrog

Based on [miekg/dns](https://github.com/miekg/dns)


```bash

### list nat rules
sudo iptables -t nat -L --line-numbers
### delete rule based on line

sudo iptables -t nat -D OUTPUT 1

### Add DNAT chain for local test

sudo iptables  -t nat -A OUTPUT -p tcp -d 192.168.1.1 -j DNAT --to-destination 10.0.0.52:9090
sudo iptables  -t nat -A OUTPUT -p udp -d 192.168.1.1 -j DNAT --to-destination 10.0.0.52:9090



sudo iptables -t mangle --flush
sudo iptables -t mangle -X

sudo iptables -t mangle -N DIVERT
sudo iptables -t mangle -A DIVERT -j MARK --set-mark 0x1/0x1
sudo iptables -t mangle -A DIVERT -j ACCEPT
sudo iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT

sudo iptables -t mangle -N PROXY
sudo iptables -t mangle -A PROXY -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 9090
sudo iptables -t mangle -A PROXY -j ACCEPT

sudo iptables -t mangle -A PREROUTING -p tcp -d 1.2.3.4 -j PROXY



# del ip rule
sudo ip rule show
sudo ip rule add fwmark 0x1/0x1 lookup 101

#del ip route
sudo ip route show 101
sudo ip route add local default dev lo table 101
 
 # run test proxy server
sudo ./tcprdr -4 -t -L 0.0.0.0 9090 127.0.0.1 9191 
```





```bash

# open tracing
sudo iptables -t raw -A PREROUTING  -i enp0s8 -p tcp -s 192.168.0.10 -j TRACE 
sudo tail -f /var/log/kern.log | grep 'TRACE:'

```

```bash
## list route
sudo ip r|grep default

## remove default gw
sudo ip route del default via 192.168.0.1
## adding default gateway
sudo ip route add default via 192.168.0.1


```

```bash

#chagne from 0 to 1
sudo nano /proc/sys/net/ipv4/ip_forward

sudo nano /etc/sysctl.conf
#remove for net.ipv4.ip_forward-1
sudo sysctl -p /etc/sysctl.conf 

sudo iptables --flush
sudo iptables -t nat --flush
sudo iptables --delete-chain

# accept incoming connection if local initialed
sudo iptables -A INPUT -i enp0s3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

## forward from enp0s8 to enp0s3
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
# forward from enp0s3 to enp0s8 if enp0s8 initialed the conn
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
## MASQUERADE all connection for post routing
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

sudo iptables -A INPUT -i enp0s8 -j ACCEPT

```