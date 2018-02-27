#!/bin/bash

commands=("register" "unregister" "getfreeport")

message() {
    echo >&2 "[rshell.sh] $*"
}

info() {
    message "info: $*"
}

error() {
    echo >&2 "* [rshell.sh] Error: $*"
}

fatal() {
    error "$@"
    exit 1
}

CTL_SOCK=/var/run/connector.sock
CONTROLLER=/usr/src/app/controller.py

register() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        cat <<EOF
register [--help | -h]    print this
register PORT [ NAME [ TYPE [ DESCRIPTION ] ] ] register service running on port PORT with specified NAME, TYPE
                                                and DESCRIPTION. When no NAME is specified PORT is used as NAME.
EOF
        return 0
    fi
    if [[ -z "$1" ]]; then
        error "Port number missing"
        return 1
    fi

    message "Register port=$1 name=${2:-$1} type=$3 description=$4"
    #curl -X PUT --unix-socket "$CTL_SOCK" \
    #    -H "Content-Type: application/json" http://localhost:8080/ports/29754 -d '{ "name": "data" }'
    "$CONTROLLER" --control-unix-socket "$CTL_SOCK" register \
                  --name "${2:-$1}" --type "$3" --description "$4" "$1"
}

unregister() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        cat <<EOF
unregister [--help | -h]  print this
unregister PORT | NAME    unregister service bound to the port PORT or named NAME
EOF
        return 0
    fi
    if [[ -z "$1" ]]; then
        error "Port number or service name missing"
        return 1
    fi

    message "Unregister port $1"
    #curl -X PUT --unix-socket "$CTL_SOCK" \
    #    -H "Content-Type: application/json" http://localhost:8080/ports/29754 -d '{ "name": "data" }'
    "$CONTROLLER" --control-unix-socket "$CTL_SOCK" unregister "$1"
}

getfreeport() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        cat <<EOF
getfreeport [--help | -h] print this
getfreeport [NUM_PORTS]   print NUM_PORTS free TCP/IP ports
EOF
        return 0
    fi
    local num_sockets=${1:-1}
    python -c '''
from __future__ import print_function
import socket, sys
num_sockets = int(sys.argv[1])
sockets = []
try:
    for i in range(num_sockets):
        s = socket.socket()
        sockets.append(s)
        s.bind(("", 0))
        print(s.getsockname()[1])
finally:
    for s in sockets:
        try:
            s.close()
        except:
            pass
    ''' "$num_sockets"
}

runcmd()
{
    # Provide an option to exit the shell
    if [[ "$1" == "exit" || "$1" == "q" ]]
    then
        exit

    # You can do exact string matching for some alias:
    elif [[ "$1" == "help" ]]
    then
        echo "Type exit or q to quit."
        echo "Commands you can use:"
        echo "  help"
        echo "  exit"
        echo "  q"
        local cmd
        for cmd in "${commands[@]}"; do
            echo "  $cmd"
        done
    else
        local cmd
        local ok=false
        for cmd in "${commands[@]}"; do
            if [[ "$cmd" == "$1" ]]; then
                ok=true
            fi
        done
        if $ok; then
            "${@}"
        else
            error "Unsupported command '$1': $@"
        fi
    fi
}

# Optionally show a friendly welcome-message with instructions since it is a custom shell
echo "Welcome, $(whoami). Type 'help' for information."

cleanup() {
    exit
}

# Optionally log the logout
trap cleanup INT EXIT

#for arg in "$@"; do
#    echo "Arg: $arg"
#done

runline() {
    local ln
    local cmd
    local ok=true
    while $ok; do
        ln=()
        if ! IFS=';' read -r -a ln -d ';'; then
            ok=false
        fi
        IFS=$' \t' read -r -a cmd<<<"${ln[*]}"
        runcmd "${cmd[@]}"
    done;
}

# Optionally check for '-c custom_command' arguments passed directly to shell
# Then you can also use ssh user@host custom_command, which will execute /root/rbash.sh
if [[ "$1" == "-c" ]]
then
    shift
    runline <<<"$1"
else
    while echo -n "> " && IFS=$'\n' read -r -a ln
    do
        for i in "${ln[@]}"; do
            runline <<< "$i"
        done 
    done
fi
