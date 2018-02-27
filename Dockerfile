FROM alpine:3.7

LABEL maintainer="Dmitri Rubinstein <dmitri.rubinstein@dfki.de>"

COPY docker-files/supervisord.conf /etc/supervisord.conf
COPY docker-files/bootstrap.sh /usr/local/bin/bootstrap.sh
COPY docker-files/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker-files/rshell.sh /usr/local/bin/rshell.sh
COPY requirements.txt /usr/src/app/requirements.txt

RUN set -xe; \
    apk add --update --no-cache --virtual .build-deps \
        augeas \
        py-pip python-dev git tar gcc musl-dev linux-headers; \
    apk add --no-cache \
        bash tini supervisor curl python nginx openssh; \
    mkdir -p /var/run/supervisor /var/log/supervisor; \
    chmod +x /usr/local/bin/entrypoint.sh \
             /usr/local/bin/bootstrap.sh \
             /usr/local/bin/rshell.sh; \
    pip install -r /usr/src/app/requirements.txt; \
    rm /etc/motd; \
    mkdir -p ~root/.ssh /etc/authorized_keys; chmod 700 ~root/.ssh/; \
    augtool 'set /files/etc/ssh/sshd_config/AuthorizedKeysFile ".ssh/authorized_keys /etc/authorized_keys/%u"'; \
    augtool 'set /files/etc/ssh/sshd_config/PermitRootLogin yes'; \
    augtool 'set /files/etc/ssh/sshd_config/PasswordAuthentication yes'; \
    augtool 'set /files/etc/ssh/sshd_config/Port 22'; \
    cp -a /etc/ssh /etc/ssh.cache; \
    apk del .build-deps; \
    rm -rf /var/cache/apk/*; \
    \
    echo 'root:root' | chpasswd; \
    adduser -D -g "Login user" -h "/home/luser" -s /usr/local/bin/rshell.sh luser; \
    passwd -u luser; \
    mkdir -p /home/luser/.ssh; \
    chmod 700 /home/luser/.ssh/; \
    touch /home/luser/.ssh/authorized_keys; \
    for f in /keys/*; do \
      if [ -r "$f" ]; then cat "$f" >> /home/luser/.ssh/authorized_keys; fi; \
    done; \
    chmod 0600 /home/luser/.ssh/authorized_keys; \
    chown -R luser:luser /home/luser;

COPY controller.py /usr/src/app/controller.py
COPY templates/ /usr/src/app/templates/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
