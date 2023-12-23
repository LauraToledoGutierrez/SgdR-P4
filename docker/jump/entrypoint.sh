#!/bin/bash

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -s 10.0.1.2 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 10.0.3.3 -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -s 10.0.3.0/24 -j ACCEPT

ip route del default
ip route add default via 10.0.1.2 dev eth0

echo -e "Match Address 10.0.1.2\n  AllowUsers jump\n" >> /etc/ssh/sshd_config
echo -e "Match Address 10.0.3.3\n  AllowUsers op\n" >> /etc/ssh/sshd_config

service ssh start
rsyslogd

if [ -z "$@" ]; then
    exec /bin/bash
else
    exec $@
fi
