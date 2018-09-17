# confige iptables
sudo sysctl -w net.ipv4.ip_forward=1

sudo iptables --flush
sudo iptables -t nat --flush
sudo iptables --delete-chain

sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A FORWARD -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A POSTROUTING  -j MASQUERADE

sudo iptables -A INPUT -j ACCEPT

sudo ip rule add fwmark 0x1/0x1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
￼￼￼￼￼
# config client
sudo redfrog-client -c config.yaml -l debug > output.log &
