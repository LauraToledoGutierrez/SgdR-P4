FROM debian

RUN apt-get update && \
    apt-get install -y \
	iptables \
	iproute2 \
	net-tools \
	tcpdump \
	iputils-ping \
	nano \
 	less \
	openssh-server \
	rsyslog \
	curl \
	sudo \
	&& \
    apt-get clean

COPY assets/rsyslog/sshd_config /etc/ssh/sshd_config
RUN chmod 644 /etc/ssh/sshd_config && \
    chown root:root /etc/ssh/sshd_config && \
    useradd -ms /bin/bash op && \
    mkdir /home/op/.ssh && \
    chmod 700 /home/op/.ssh
COPY assets/authorized_keys.op /home/op/.ssh/authorized_keys
RUN chown op:op -R /home/op

COPY assets/sudoers.op /etc/sudoers.d/op
