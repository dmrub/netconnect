#!/bin/bash

THIS_DIR=$( (cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) )

IMAGE_PREFIX=${IMAGE_PREFIX:-netconnect}
IMAGE_TAG=${IMAGE_TAG:-latest}
IMAGE_NAME=${IMAGE_PREFIX}:${IMAGE_TAG}

read-keys() {
    local key_dir=$1
    local keys key
    if [[ -d "$key_dir" ]]; then
        for f in "$key_dir"/*.pub; do
            if [[ -r "$f" ]]; then
                key="$(< "$f")"
                if [[ -z "$keys" ]]; then
                    keys=$key
                elif [[ "$keys" == *$'\n' ]]; then
                keys="${keys}${key}"
                else
                    keys="${keys}$'\n'${key}"
                fi
            fi
        done
    fi
    echo "$keys"
}

cd "$THIS_DIR"
#ARGS=(--privileged)
#ARGS=(--cap-add=SYS_PTRACE)
ARGS=()
NC_AUTHORIZED_KEYS="$(read-keys keys)"
NC_ROOT_AUTHORIZED_KEYS="$(read-keys root-keys)"

set -xe
docker run -p 2222:22 -p 9090:9090 -p 8080:8080 "${ARGS[@]}" \
       -e NC_AUTHORIZED_KEYS="$NC_AUTHORIZED_KEYS" \
       -e NC_ROOT_AUTHORIZED_KEYS="$NC_ROOT_AUTHORIZED_KEYS" \
       --name=netconnect \
       --rm -ti "${IMAGE_NAME}" "$@"
