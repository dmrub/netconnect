FROM alpine:3.7

LABEL maintainer="Dmitri Rubinstein <dmitri.rubinstein@dfki.de>"

COPY files/supervisord.conf /etc/supervisord.conf
COPY files/bootstrap.sh /usr/local/bin/bootstrap.sh
COPY files/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN set -xe; \
    apk add --update --no-cache --virtual .build-deps \
        augeas \
        py-pip git tar; \
    apk add --no-cache \
        bash tini supervisor curl python openssh; \
    mkdir -p /var/run/supervisor /var/log/supervisor; \
    chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/bootstrap.sh; \
    mkdir -p ~root/.ssh /etc/authorized_keys; chmod 700 ~root/.ssh/; \
    augtool 'set /files/etc/ssh/sshd_config/AuthorizedKeysFile ".ssh/authorized_keys /etc/authorized_keys/%u"'; \
    augtool 'set /files/etc/ssh/sshd_config/PermitRootLogin yes'; \
    augtool 'set /files/etc/ssh/sshd_config/PasswordAuthentication yes'; \
    augtool 'set /files/etc/ssh/sshd_config/Port 22'; \
    cp -a /etc/ssh /etc/ssh.cache; \
    apk del .build-deps; \
    rm -rf /var/cache/apk/*; \
    \
    echo 'root:root' | chpasswd;

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
