#!/bin/bash

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -i eth0 -s 10.0.3.3 -j ACCEPT 

iptables -A INPUT -p udp --sport 53 -i eth0 -j ACCEPT

iptables -A INPUT -p tcp --sport 80 -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp --sport 443 -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp --dport 5000 -i eth0 -s 10.0.1.2 -j ACCEPT 
iptables -A INPUT -p tcp --sport 5000 -i eth0 -s 10.0.2.4 -j ACCEPT  
iptables -A INPUT -p tcp --sport 5000 -i eth0 -s 10.0.2.3 -j ACCEPT  

service ssh start
service rsyslog start

echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

touch /var/log/auth.log

service ssh restart
service rsyslog restart

ip route del default
ip route add default via 10.0.1.2 dev eth0

./main

if [ -z "$@" ]; then
    exec /bin/bash
else
    exec $@
fi
