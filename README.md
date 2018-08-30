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

```


```bash
## list route
sudo ip r|grep default

## adding default gateway
sudo ip route add default via 192.168.0.1
## remove default gw
sudo ip route del default via 192.168.0.1

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

```