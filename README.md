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