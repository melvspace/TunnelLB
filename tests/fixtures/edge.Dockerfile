FROM debian:bookworm-20261005-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ENV container=docker
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        systemd systemd-sysv openssh-server ca-certificates curl sudo iproute2 python3 procps \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* /etc/machine-id \
    && touch /etc/machine-id \
    && mkdir -p /root/.ssh \
    && chmod 700 /root/.ssh \
    && printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' \
        'PermitRootLogin prohibit-password' 'AllowTcpForwarding no' 'X11Forwarding no' \
        > /etc/ssh/sshd_config.d/tunnellb-e2e.conf \
    && systemctl enable ssh \
    && systemctl mask systemd-remount-fs.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "-c", "ssh-keygen -A >/dev/null 2>&1; exec /sbin/init"]
