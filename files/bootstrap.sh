#!/bin/bash

if [[ -e /usr/local/bin/entrypoint-args.sh ]]; then
    source /usr/local/bin/entrypoint-args.sh
fi

# generate host keys if not present
ssh-keygen -A

supervisorctl start sshd
