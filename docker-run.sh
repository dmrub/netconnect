#!/bin/bash

THIS_DIR=$( (cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) )

IMAGE_PREFIX=${IMAGE_PREFIX:-netconnect}
IMAGE_TAG=${IMAGE_TAG:-latest}
IMAGE_NAME=${IMAGE_PREFIX}:${IMAGE_TAG}

set -xe
cd "$THIS_DIR"
docker run -p 2222:22 --name=connector --rm -ti "${IMAGE_NAME}" "$@"
