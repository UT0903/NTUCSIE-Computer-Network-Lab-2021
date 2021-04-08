#! /bin/bash
iptables -A FORWARD -i wlx74da38f8c74b -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i wlx74da38f8c74b -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i wlx74da38f8c74b -j DROP
iptables -t nat -A PREROUTING -i wlx74da38f8c74b -p tcp --dport 80 -j DNAT --to-destination 10.42.0.1:9090
iptables -t nat -A PREROUTING -i wlx74da38f8c74b -p tcp --dport 443 -j DNAT --to-destination 10.42.0.1:9090