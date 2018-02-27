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

while [[ $# > 0 ]]; do
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

write-set-args "$@" > /usr/local/bin/entrypoint-args.sh

mkdir -p /var/run/supervisor /var/log/supervisor || exit 1
exec /usr/bin/supervisord -c /etc/supervisord.conf
