#!/bin/bash

THIS_DIR=$( (cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) )

IMAGE_PREFIX=${IMAGE_PREFIX:-netconnect}
IMAGE_TAG=${IMAGE_TAG:-latest}
IMAGE_NAME=${IMAGE_PREFIX}:${IMAGE_TAG}

set -xe
cd "$THIS_DIR"
#ARGS=(--privileged)
#ARGS=(--cap-add=SYS_PTRACE)
ARGS=()
docker run -p 2222:22 -p 9090:9090 -p 8080:8080 "${ARGS[@]}" --name=netconnect \
       --rm -ti "${IMAGE_NAME}" "$@"
