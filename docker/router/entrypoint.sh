#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -p icmp -j ACCEPT
iptables -A FORWARD -p icmp -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -p icmp -j MASQUERADE

iptables -A FORWARD -i eth0 -o eth1 -p tcp --syn --dport 22 -m state --state NEW -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j DNAT --to-destination 10.0.1.3
iptables -t nat -A POSTROUTING -o eth1 -p tcp --dport 22 -s 172.17.0.0/16 -d 10.0.1.3 -j SNAT --to-source 10.0.1.2

iptables -A FORWARD -i eth1 -o eth2 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth1 -p tcp --sport 22 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth1 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth2 -p tcp --sport 22 -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -i eth2 -s 10.0.3.3 -j ACCEPT

service ssh start
rsyslogd

if [ -z "$@" ]; then
    exec /bin/bash
else
    exec $@
fi
