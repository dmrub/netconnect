#!/bin/bash

message() {
    echo >&2 "[entrypoint.sh] $*"
}

info() {
    message "info: $*"
}

error() {
    echo >&2 "* [entrypoint.sh] Error: $*"
}

fatal() {
    error "$@"
    exit 1
}

message "info: EUID=$EUID args: $*"

usage() {
    echo "Entrypoint Script"
    echo
    echo ""
    echo "$0 [options]"
    echo "options:"
    echo "      --print-env            Display environment"
    echo "      --help"
    echo "      --help-entrypoint      Display this help and exit"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|--help-entrypoint)
            usage
            exit
            ;;
        --print-env)
            env >&2
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            break
            ;;
        *)
            break
            ;;
    esac
done

write-set-args() {
    local set_cmd="set -- " arg val
    for arg in "$@"; do
        printf -v val "%q" "$arg"
        set_cmd="$set_cmd $val"
    done

    echo "$set_cmd"
}

# Initialization
info "Preparing container ..."

if [[ -n "${NC_ROOT_PASSWORD}" ]]; then
    info "Set root password"
    echo "root:${NC_ROOT_PASSWORD}" | /usr/sbin/chpasswd
else
    info "Delete root password"
    /usr/bin/passwd -d root
fi

if [[ -n "${NC_ROOT_AUTHORIZED_KEYS}" ]]; then
    info "Copy root's authorized keys"
    mkdir -p ~root/.ssh
    echo "${NC_ROOT_AUTHORIZED_KEYS}" >> ~root/.ssh/authorized_keys
    chmod 0700 ~root/.ssh
    chmod 0600 ~root/.ssh/authorized_keys
fi

NC_SHELL=/usr/local/bin/rshell.py

if [[ -n "${NC_USER}" ]]; then
    info "Create user ${NC_USER}"

    /usr/sbin/addgroup -g "${NC_GROUPID}" "${NC_GROUP}"
    if [[ -d "${NC_HOME}" ]]; then
        /usr/sbin/adduser -u "${NC_USERID}" -G "${NC_GROUP}" -s "${NC_SHELL}" -h "${NC_HOME}" -H -D "${NC_USER}"
    else
        /usr/sbin/adduser -u "${NC_USERID}" -G "${NC_GROUP}" -s "${NC_SHELL}" -h "${NC_HOME}" -D "${NC_USER}"
    fi
    if [[ -n "${NC_PASSWORD}" ]]; then
        info "Set ${NC_USER}'s password"
        echo "${NC_USER}:${NC_PASSWORD}" | /usr/sbin/chpasswd
    else
        info "Delete ${NC_USER}'s password"
        /usr/bin/passwd -d "${NC_USER}"
    fi

    if [[ -n "${NC_AUTHORIZED_KEYS}" ]]; then
        info "Install authorized keys for $NC_USER user to $NC_HOME/.ssh/authorized_keys"
        mkdir -p "$NC_HOME/.ssh"
        chmod 700 "$NC_HOME/.ssh"
        touch "$NC_HOME/.ssh/authorized_keys"
        echo "${NC_AUTHORIZED_KEYS}" >> "$NC_HOME/.ssh/authorized_keys"
        chmod 0600 "$NC_HOME/.ssh/authorized_keys";
        chown -R "$NC_USER:$NC_GROUP" "$NC_HOME";
    fi

    if [[ -n "${NC_ALLOW_TCP_FORWARDING}" ]]; then
        case "${NC_ALLOW_TCP_FORWARDING}" in
            yes|all|no|local|remote) ;;
            *) fatal "NC_ALLOW_TCP_FORWARDING is set to invalid value '$NC_ALLOW_TCP_FORWARDING', should be one of: yes | all | no | local | remote";;
        esac
        info "Set sshd option AllowTcpForwarding to ${NC_ALLOW_TCP_FORWARDING} for user ${NC_USER}"
        cat >> /etc/ssh/sshd_config <<EOF
Match User ${NC_USER}
  AllowTcpForwarding "${NC_ALLOW_TCP_FORWARDING}"
EOF
    fi
fi
unset NC_PASSWORD

NC_NGINX_PORT=${NC_NGINX_PORT:-8080}
NC_SSHD_PORT=${NC_SSHD_PORT:-22}
NC_CONTROLLER_PORT=${NC_CONTROLLER_PORT:-9090}

sed -i -e 's/Port[[:blank:]]\+[0-9]\+.*$/Port '"${NC_SSHD_PORT}"'/g' /etc/ssh/sshd_config

export NC_USER NC_USERID \
       NC_GROUP NC_GROUPID NC_SHELL NC_HOME \
       NC_RUN NC_NGINX_PORT NC_SSHD_PORT \
       NC_CONTROLLER_PORT

if [[ -n "$NC_RUN" ]]; then
    info "Executing: /bin/sh -c $NC_RUN"
    /bin/sh -c "$NC_RUN"
fi

write-set-args "$@" > /usr/local/bin/entrypoint-args.sh

mkdir -p /var/run/supervisor /var/log/supervisor || exit 1
exec /usr/bin/supervisord -c /etc/supervisord.conf
