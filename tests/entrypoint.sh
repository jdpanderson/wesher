#!/bin/bash

set -e

# Parse arguments
args=("$@")
while [[ $# -gt 0 ]]; do case $1 in
    --interface)
    iface=$2
    shift
    ;;
esac; shift; done

# Create tun device if necessary
if [ ! -e /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
fi

wireguard ${iface:-wgoverlay}
exec /app/cheesecloth --log-level debug "${args[@]}"
