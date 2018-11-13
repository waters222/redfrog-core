#!/bin/sh

export INTERFACE_IN=eth0
export INTERFACE_OUT=eth1


iptables -t filter --flush INPUT
iptables -t filter -A INPUT  -j ACCEPT

iptables -t filter --flush FORWARD
iptables -t filter -A FORWARD -i $INTERFACE_IN -o $INTERFACE_OUT -j ACCEPT

iptables -t nat --flush POSTROUTING
iptables -t nat -A POSTROUTING -o $INTERFACE_OUT   -j MASQUERADE


ip6tables -t filter --flush INPUT
ip6tables -t filter -A INPUT  -j ACCEPT

ip6tables -t filter --flush FORWARD
ip6tables -t filter -A FORWARD -i $INTERFACE_IN -o $INTERFACE_OUT -j ACCEPT

ip6tables -t nat --flush POSTROUTING
ip6tables -t nat -A POSTROUTING -o $INTERFACE_OUT   -j MASQUERADE


iptables -t filter --flush INPUT
iptables -t filter -A INPUT -j ACCEPT

iptables -t filter --flush FORWARD
iptables -t filter -A FORWARD  -j ACCEPT

iptables -t nat --flush POSTROUTING
iptables -t nat -A POSTROUTING  -j MASQUERADE

cd /app
./redfrog-client -c gateway-config.yaml -l debug