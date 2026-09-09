#!/bin/bash

set -e

declare -A started_containers

cleanup() {
    if [ ${#started_containers[@]} -gt 0 ]; then
        echo "Stopping all remaining containers: ${started_containers[@]}"
        docker container rm -f ${started_containers[@]}
    fi
    echo "Removing shared networks"
    docker network rm cheesecloth_test cheesecloth_test6
}

docker build -t cheesecloth-test "$(dirname "$0")"

# The underlay must not overlap the default overlay net (10.0.0.0/8), so pick the subnet explicitly.
docker network create --subnet 172.30.0.0/24 cheesecloth_test
docker network create --ipv6 --subnet fd00:57::/64 cheesecloth_test6
trap cleanup EXIT

# network the next containers join; tests switch it for the IPv6 cases
network=cheesecloth_test

run_test_container() {
    local name=$1
    echo "Starting $name"
    shift
    local hostname=$1
    shift
    docker run -d --cap-add=NET_ADMIN --cap-add=NET_RAW --device /dev/net/tun --security-opt label=disable --name ${name} --hostname ${hostname} -v $(pwd):/app --network=${network} cheesecloth-test "$@"
    started_containers[$name]=$name
}

stop_test_container() {
    echo "Stopping $1"
    docker container rm -f $1
    unset started_containers[$1]
}

# invite <container> <uses> [cheesecloth flags...]: mint an enrolment token on a running
# member, retrying while its agent is still starting. Prints the token.
invite() {
    local container=$1 uses=$2
    shift 2
    local token
    for _ in $(seq 1 30); do
        if token=$(docker exec "$container" /app/cheesecloth invite --ttl 5m --uses "$uses" "$@" 2>/dev/null) && [ -n "$token" ]; then
            echo "$token"
            return 0
        fi
        sleep 0.5
    done
    echo "could not mint a token on $container" >&2
    docker logs "$container" >&2
    return 1
}

ping_ok() { # ping_ok <from-container> <to-host> [containers whose logs to dump on failure...]
    local from=$1 to=$2
    shift 2
    docker exec "$from" ping -c1 -W1 "$to" || { for c in "$from" "$@"; do docker logs "$c"; done; false; }
}

test_3_node_up() {
    run_test_container test1-orig test1 --init
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"
    run_test_container test3-orig test3 --join test1-orig --join-key "$token"

    sleep 3

    ping_ok test1-orig test2 test2-orig
    ping_ok test1-orig test3 test3-orig
    # addresses are allocated from the bottom of the overlay net: the root takes .1
    docker exec test1-orig ip -4 addr show wgoverlay | grep -q "inet 10.0.0.1/32" || { docker exec test1-orig ip addr; false; }
    docker exec test2-orig ip -4 addr show wgoverlay | grep -qE "inet 10.0.0.[23]/32" || { docker exec test2-orig ip addr; false; }
    # the token is spent: a fourth node cannot use it
    run_test_container test4-orig test4 --join test1-orig --join-key "$token"
    if [ "$(docker wait test4-orig)" = 0 ]; then echo "spent token was accepted"; docker logs test4-orig; false; fi
    docker logs test4-orig 2>&1 | grep -q "join key" || { docker logs test4-orig; false; }

    stop_test_container test4-orig
    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

test_5_node_up() {
    run_test_container test1-orig test1 --init
    token=$(invite test1-orig 4)
    for n in 2 3 4 5; do
        run_test_container test$n-orig test$n --join test1-orig --join-key "$token"
    done

    sleep 5

    for n in 2 3 4 5; do ping_ok test1-orig test$n test$n-orig; done

    for n in 5 4 3 2 1; do stop_test_container test$n-orig; done
}

# a restarted node rejoins from its persisted identity; the stale --join-key on
# its command line is ignored
test_node_restart() {
    run_test_container test1-orig test1 --init
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"

    sleep 3

    docker stop test2-orig
    docker start test2-orig

    sleep 3

    ping_ok test1-orig test2 test2-orig
    docker logs test2-orig 2>&1 | grep -q "ignoring --join-key" || { docker logs test2-orig; false; }

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# joiners started at the same time with a shared multi-use token
test_cluster_simultaneous_start() {
    run_test_container test1-orig test1 --init
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" &
    run_test_container test3-orig test3 --join test1-orig --join-key "$token" &
    wait
    started_containers[test2-orig]=test2-orig
    started_containers[test3-orig]=test3-orig

    sleep 3

    ping_ok test1-orig test2 test2-orig
    ping_ok test1-orig test3 test3-orig
    ping_ok test2-orig test3 test3-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

test_multiple_clusters_restart() {
    cluster1='--cluster-port 7946 --wireguard-port 51820 --interface wg1 --overlay-net 10.10.0.0/16'
    cluster2='--cluster-port 7947 --wireguard-port 51821 --interface wg2 --overlay-net 10.11.0.0/16'

    run_test_container test1-orig test1 --init $cluster1
    run_test_container test2-orig test2 --init $cluster2
    token1=$(invite test1-orig 1 --interface wg1)
    token2=$(invite test2-orig 1 --interface wg2)
    run_test_container test3-orig test3 --join test1-orig --join-key "$token1" $cluster1
    docker exec -d test3-orig bash -c "/entrypoint.sh --join test2-orig --join-key $token2 $cluster2"

    sleep 3

    docker stop test3-orig
    docker start test3-orig
    docker exec -d test3-orig bash -c "/entrypoint.sh $cluster2" # rejoins from state, no token

    sleep 3

    ping_ok test3-orig test1 test1-orig
    ping_ok test3-orig test2 test2-orig
    ping_ok test1-orig test3 test3-orig
    ping_ok test2-orig test3 test3-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# IPv6 underlay (gossip, enrolment and wireguard endpoints over fd00:57::/64) and IPv6 overlay
test_ipv6_cluster() {
    network=cheesecloth_test6
    local v6='--bind-addr :: --overlay-net fd00:10::/64'
    run_test_container test1-orig test1 --init $v6
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" $v6
    run_test_container test3-orig test3 --join test1-orig --join-key "$token" $v6
    network=cheesecloth_test

    sleep 3

    ping_ok test1-orig test2 test2-orig
    ping_ok test3-orig test1 test1-orig
    docker exec test1-orig /app/cheesecloth status | grep -q '^address: *fd00:10:' || (docker exec test1-orig /app/cheesecloth status; false)

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# IPv6 overlay over the IPv4 underlay
test_ipv6_overlay() {
    run_test_container test1-orig test1 --init --overlay-net fd00:10::/64
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" --overlay-net fd00:10::/64

    sleep 3

    ping_ok test1-orig test2 test2-orig
    ping_ok test2-orig test1 test1-orig

    stop_test_container test2-orig
    stop_test_container test1-orig
}

test_node_leave() {
    run_test_container test1-orig test1 --init
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"

    sleep 3

    ping_ok test1-orig test2 test2-orig

    docker stop test2-orig # SIGTERM: clean leave

    sleep 3

    if docker exec test1-orig grep -q test2 /etc/hosts; then
        echo "stale hosts entry for test2"; docker logs test1-orig; false
    fi

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a revoked node is dropped by its peers and can no longer talk to them
test_revoke() {
    run_test_container test1-orig test1 --init
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"
    run_test_container test3-orig test3 --join test1-orig --join-key "$token"

    sleep 3

    ping_ok test1-orig test3 test3-orig
    docker exec test1-orig /app/cheesecloth revoke test3

    sleep 3

    if docker exec test1-orig grep -q test3 /etc/hosts; then
        echo "revoked node still in test1's hosts"; docker logs test1-orig; false
    fi
    docker exec test1-orig /app/cheesecloth status | grep -q test3 && { echo "revoked node still a wireguard peer"; false; }
    # the revocation also reached test2, which never talked to the operator
    for _ in $(seq 1 20); do
        docker exec test2-orig grep -q test3 /etc/hosts || break
        sleep 0.5
    done
    if docker exec test2-orig grep -q test3 /etc/hosts; then
        echo "revocation did not reach test2"; docker logs test2-orig; false
    fi
    ping_ok test1-orig test2 test2-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# run the named tests, or all of them
tests=("$@")
if [ ${#tests[@]} -eq 0 ]; then
    tests=($(declare -F | grep -Eo '\<test_.*$'))
fi
for test_func in "${tests[@]}"; do
    echo "--- Running $test_func:"
    $test_func
    echo "--- OK"
done
