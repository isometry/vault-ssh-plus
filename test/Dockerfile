FROM debian:latest

RUN apt update \
    && apt install -y openssh-server \
    && service ssh start \
    && useradd -m testuser

EXPOSE 22

CMD ["-o", "TrustedUserCAKeys=/etc/ssh/trusted-user-ca-keys"]
ENTRYPOINT ["/usr/sbin/sshd", "-De"]
