#!/bin/bash

set -e

# The agent uses the kernel module where the container's kernel has one and
# runs wireguard itself otherwise; the latter needs the tun device.
if [ ! -e /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
fi

exec /app/cheesecloth --log-level debug "$@"
