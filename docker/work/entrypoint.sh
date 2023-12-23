#!/bin/bash

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -s 10.0.1.3 -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -s 10.0.1.0/24 -j ACCEPT

ip route del default
ip route add default via 10.0.3.2 dev eth0 

service ssh start
rsyslog

if [ -z "$@" ]; then
    exec /bin/bash
else
    exec $@
fi
