#!/bin/sh

iptables -t filter --flush INPUT
iptables -t filter -A INPUT -j ACCEPT

iptables -t filter --flush FORWARD
iptables -t filter -A FORWARD  -j ACCEPT

iptables -t nat --flush POSTROUTING
iptables -t nat -A POSTROUTING  -j MASQUERADE


ip rule add fwmark 0x1/0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

cd /app
./redfrog-client -c gateway-config.yaml -l debug