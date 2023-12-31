#!/bin/bash

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -i eth0 -s 10.0.3.3 -j ACCEPT

iptables -A INPUT -p udp --dport 514 -i eth0 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 514 -i eth0 -s 10.0.2.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 514 -i eth0 -s 10.0.3.0/24 -j ACCEPT

service ssh start
service rsyslog start

echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

rm /etc/rsyslog.d/20-forward-logs.conf
rm /etc/rsyslog.d/50-sshd.conf

sed -i '/module(load="imudp")/s/^#//g' /etc/rsyslog.conf
sed -i '/input(type="imudp" port="514")/s/^#//g' /etc/rsyslog.conf

mkdir -p /var/log/remotelogs/
chown -R root:adm /var/log/remotelogs

service rsyslog restart

touch /var/log/auth.log

sed -i 's/logpath = \/var\/log\/auth.log/logpath = \/var\/log\/remotelogs\/logs\/sshd.log/g' 

service ssh restart
service rsyslog restart

ip route del default
ip route add default via 10.0.3.2 dev eth0 

if [ -z "$@" ]; then
    exec /bin/bash
else
    exec $@
fi
