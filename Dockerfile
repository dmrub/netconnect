FROM alpine:3.7

LABEL maintainer="Dmitri Rubinstein <dmitri.rubinstein@dfki.de>"

ENV NC_NGINX_PORT=8080 \
    NC_SSHD_PORT=22 \
    NC_CONTROLLER_PORT=9090 \
    NC_ROOT_PASSWORD="" \
    NC_ROOT_AUTHORIZED_KEYS="" \
    NC_USER="nc" \
    NC_USERID=1001 \
    NC_GROUP=nc \
    NC_GROUPID=1001 \
    NC_PASSWORD="" \
    NC_AUTHORIZED_KEYS="" \
    NC_HOME="/home/nc" \
    NC_RUN="" \
    NC_ALLOW_TCP_FORWARDING="remote"

COPY docker-files/supervisord.conf /etc/supervisord.conf
COPY docker-files/bootstrap.sh /usr/local/bin/bootstrap.sh
COPY docker-files/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker-files/rshell.py /usr/local/bin/rshell.py
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
             /usr/local/bin/rshell.py; \
    pip install -r /usr/src/app/requirements.txt; \
    rm /etc/motd; \
    passwd -d root; \
    mkdir -p ~root/.ssh /etc/authorized_keys; \
    printf 'set /files/etc/ssh/sshd_config/AuthorizedKeysFile ".ssh/authorized_keys /etc/authorized_keys/%%u"\n'\
'set /files/etc/ssh/sshd_config/ClientAliveInterval 30\n'\
'set /files/etc/ssh/sshd_config/ClientAliveCountMax 5\n'\
'set /files/etc/ssh/sshd_config/PermitRootLogin yes\n'\
'set /files/etc/ssh/sshd_config/PasswordAuthentication yes\n'\
'set /files/etc/ssh/sshd_config/Port 22\n'\
'set /files/etc/ssh/sshd_config/AllowTcpForwarding no\n'\
'set /files/etc/ssh/sshd_config/Match[1]/Condition/Group "wheel"\n'\
'set /files/etc/ssh/sshd_config/Match[1]/Settings/AllowTcpForwarding yes\n'\
'save\n'\
'quit\n' | augtool; \
    cp -a /etc/ssh /etc/ssh.cache; \
    apk del .build-deps; \
    rm -rf /var/cache/apk/*;

COPY controller.py flask_reverse_proxy.py \
     /usr/src/app/
COPY templates/ /usr/src/app/templates/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
