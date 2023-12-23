FROM midebian

RUN useradd -ms /bin/false jump && \
    mkdir /home/jump/.ssh && \
    chmod 700 /home/jump/.ssh
COPY authorized_keys /home/jump/.ssh/authorized_keys
RUN chown jump:jump -R /home/jump

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
