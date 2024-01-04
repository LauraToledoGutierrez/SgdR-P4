FROM debian:buster
RUN apt-get update && apt-get install -y iptables openssh-server rsyslog fail2ban


COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh
