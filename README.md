[![Build Status](https://github.com/jdpanderson/wesher/actions/workflows/main.yaml/badge.svg)](https://github.com/jdpanderson/wesher/actions/workflows/main.yaml)

This is a maintained fork of [costela/wesher](https://github.com/costela/wesher).

# wesher

<img src="./dist/wesher.svg" width="300"/>

`wesher` creates and manages an encrypted mesh overlay network across a group of nodes, using [wireguard](https://www.wireguard.com/).

Its main use-case is adding low-maintenance security to public-cloud networks or connecting different cloud providers.

**Note**: mesh membership is decided by signed admission records and invitation tokens rather than a shared key; see
[security considerations](#security-considerations) below for what a compromised node can and cannot do.

## Quickstart

0. Before starting:
   1. make sure the [wireguard](https://www.wireguard.com/) kernel module is available on all nodes. It is bundled with linux newer than 5.6 and can otherwise be installed following the instructions [here](https://www.wireguard.com/install/).

   2. The following ports must be accessible between all nodes (see [configuration options](#configuration-options) to change these):
      - 51820 UDP (wireguard) and TCP (enrolment of new nodes)
      - 7946 UDP and TCP (cluster gossip)

1. Download the latest release for your architecture:

   ```
   $ wget -O wesher https://github.com/jdpanderson/wesher/releases/latest/download/wesher-$(go env GOARCH)
   $ chmod a+x wesher
   ```

2. On the first node, start a new cluster:
   ```
   # ./wesher --init
   ```

   This starts the daemon in the foreground. The node generates its identity and becomes the cluster's root.

3. Still on that node (or any node already in the cluster), mint an invitation for the node you want to add:
   ```
   # wesher invite
   7xk3...
   valid for 10m0s, 1 use(s). On the new node:
     wesher --join <this host> --join-key 7xk3...
   ```

   The token lives only in the inviting node's memory until it is used or expires. `--uses N` lets one token enrol
   several nodes, for example when a group of machines boots together.

4. On the new node:
   ```
   # wesher --join x.x.x.x --join-key 7xk3...
   ```

   Where `x.x.x.x` is the hostname or IP of the node that minted the token. The two nodes prove to each other that
   they know the token, the new node is admitted, and the token is discarded on both sides. From then on the node
   restarts with plain `wesher`; its identity and the membership records are kept in `/var/lib/wesher/`.

   To remove a node again, on any member: `wesher revoke NAME`.

### Permissions 

Note that `wireguard` - and therefore `wesher` - need root access to work properly.

It is also possible to give the `wesher` binary enough capabilities to manage the `wireguard` interface via:
```
# setcap cap_net_admin=eip wesher
```
This will enable running as an unprivileged user, but some functionality (like automatic adding peer entries to
`/etc/hosts`; see [configuration options](#configuration-options) below) will not work.

### (optional) systemd integration

A minimal `systemd` unit file is provided under the `dist` folder and can be copied to `/etc/systemd/system`:
```
# wget -O /etc/systemd/system/wesher.service https://raw.githubusercontent.com/jdpanderson/wesher/main/dist/wesher.service
# systemctl daemon-reload
# systemctl enable wesher
```
The provided unit file assumes `wesher` is installed to `/usr/local/sbin`.

For an unattended first start, put `WESHER_JOIN=x.x.x.x` and `WESHER_JOIN_KEY=...` in `/etc/default/wesher`
(see [configuration options](#configuration-options) below). Once the node is enrolled the key is ignored on later
starts and can be removed from the file.

## Checking on a node

`wesher status` shows the wireguard interface and its peers, with the last handshake age and traffic counters, naming
peers from the persisted cluster state. Add `--json` for machine-readable output and `--interface` if not using the
default. It needs the same privileges as the agent.

```
# wesher status
interface: wgoverlay
address:   10.171.249.28/32
port:      51820
pubkey:    41p91phfnFloks55MFP1iZfRQ11VdEpTAufFwv8j810=
peers:     2

NAME   OVERLAY         ENDPOINT         HANDSHAKE  RX       TX
test2  10.171.252.205  10.89.0.3:51820  12s ago    1.5 KiB  3.0 KiB
test3  10.171.251.146  10.89.0.4:51820  never      0 B      0 B
```

`wesher invite` and `wesher revoke NAME` manage membership through the running agent (see [Quickstart](#quickstart)).

## Installing from source

```
$ git clone https://github.com/jdpanderson/wesher.git
$ cd wesher
$ make
```
This builds a bit-by-bit identical binary to the released ones, assuming the same go version is used to build its respective git tag.

Alternatively, without a checkout (`--version` will then report `dev` rather than a tag):
```
$ go install github.com/jdpanderson/wesher@latest
```

## Features

The `wesher` tool builds a cluster and manages the configuration of wireguard on each node to create peer-to-peer
connections between all nodes, thus forming a full mesh VPN.
This approach may not scale for hundreds of nodes (benchmarks accepted 😉), but is sufficiently performant to join
several nodes across multiple cloud providers, or simply to secure inter-node comunication in a single public-cloud.

### Automatic Key management

The wireguard private keys are created on startup for each node and the respective public keys are then broadcast
across the cluster.

The control-plane cluster communication is secured with a pre-shared AES-256 key. This key can be be automatically
created during startup of the first node in a cluster, or it can be provided (see [configuration](#configuration-options)).
The cluster key must then be sent to other nodes via a out-of-band secure channel (e.g. ssh, cloud-init, etc).
Once set, the cluster key is saved locally and reused on the next startup.

### Automatic IP address management

The overlay IP address of each node is automatically selected out of a private network (`10.0.0.0/8` by default; MUST be different from the underlying network used for cluster communication) and is consistently hashed based on the peer's hostname.

The use of consistent hashing means a given node will always receive the same overlay IP address (see [limitations](#overlay-ip-collisions)
of this approach below).

**Note**: the node's hostname is also used by the underlying cluster management (using [memberlist](https://github.com/hashicorp/memberlist))
to identify nodes and must therefore be unique in the cluster.

### Automatic /etc/hosts management

To ease intra-node communication, `wesher` also adds entries to `/etc/hosts` for each peer in the mesh. This enables using the nodes' hostnames to ensure communication over the secured overlay network (assuming `files` is the first entry for `hosts` in `/etc/nsswitch.conf`).

See [configuration](#configuration-options) below for how to disable this behavior.

### Seamless restarts

If a node in the cluster is restarted, it re-joins the last-known nodes using its persisted identity.
This means a restart requires no manual intervention, even if every node restarts at once.

## Configuration options

All options can be passed either as command-line flags or environment variables:

| Option | Env | Description | Default |
|---|---|---|---|
| `--join HOST,...` | WESHER_JOIN | comma separated list of hostnames or IP addresses of existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members |  |
| `--join-key TOKEN` | WESHER_JOIN_KEY | invitation token from `wesher invite` on a member; needed only the first time this node joins, ignored afterwards |  |
| `--init` | WESHER_INIT | start a new cluster with this node as its root; any known state from previous runs will be forgotten | `false` |
| `--control-socket PATH` | WESHER_CONTROL_SOCKET | unix socket used by `wesher invite` and `wesher revoke` | `/run/wesher/<interface>.sock` |
| `--bind-addr ADDR` | WESHER_BIND_ADDR | address to bind for cluster membership; `0.0.0.0` or `::` binds every interface of that family and advertises one of its addresses (public preferred). The family decides whether the cluster runs over IPv4 or IPv6, see [IPv4 and IPv6](#ipv4-and-ipv6) | `0.0.0.0` |
| `--cluster-port PORT` | WESHER_CLUSTER_PORT | port used for membership gossip traffic (both TCP and UDP); must be the same across cluster | `7946` |
| `--wireguard-port PORT` | WESHER_WIREGUARD_PORT | port used for wireguard traffic (UDP); must be the same across cluster | `51820` |
| `--overlay-net ADDR/MASK` | WESHER_OVERLAY_NET | the network in which to allocate addresses for the overlay mesh network (CIDR format); smaller networks increase the chance of IP collision | `10.0.0.0/8` |
| `--interface DEV` | WESHER_INTERFACE | name of the wireguard interface to create and manage | `wgoverlay` |
| `--mtu MTU` | WESHER_MTU | MTU of the wireguard interface | `1420` |
| `--persistent-keepalive DURATION` | WESHER_PERSISTENT_KEEPALIVE | interval at which peers send keepalives, to keep NAT mappings open (e.g. `25s`); `0` disables | `0` |
| `--no-etc-hosts` | WESHER_NO_ETC_HOSTS | whether to skip writing hosts entries for each node in mesh | `false` |
| `--log-level LEVEL` | WESHER_LOG_LEVEL | set the verbosity (one of debug/info/warn/error) | `warn` |

## IPv4 and IPv6

Any address option accepts either family. Two independent choices are made per cluster:

- **Underlay** (cluster gossip and wireguard endpoints): the family of `--bind-addr` decides. `0.0.0.0` (the default)
  or a specific IPv4 address makes an IPv4 cluster; `::` or a specific IPv6 address makes an IPv6 cluster. Every node
  of a cluster must use the same family, since an IPv4-only node cannot reach an IPv6-only one. Dual-stack hosts can
  join either kind of cluster.
- **Overlay** (the mesh addresses): the family of `--overlay-net`, independent of the underlay. An IPv6 overlay such
  as `fd00:10::/64` over an IPv4 underlay works, and so does the reverse.

With a wildcard bind address, wesher advertises one of the host's addresses of that family to the cluster, preferring
a public one, then any global unicast address (RFC 1918 and unique local addresses included). Link-local addresses and
addresses on the wesher interface itself are never chosen. Set a specific `--bind-addr` to control it.

## Running multiple clusters

To make a node be a member of multiple clusters, simply start multiple wesher instances.  
Each instance **must** have different values for the following settings:
- `--interface`
- either `--cluster-port` or `--bind-addr`
- `--wireguard-port`

The following settings are not required to be unique, but recommended:
- `--overlay-net` (to reduce the chance of node address conflicts; see [Overlay IP collisions](#overlay-ip-collisions))

## Security considerations

There is no cluster-wide secret. Each node has a persisted identity (an Ed25519 key), and membership is a set of
signed admission records rooted at the node that ran `--init`. A new node is admitted when it and an existing member
prove to each other that they know an invitation token; the token exists only during that exchange. Cluster gossip is
encrypted and authenticated per pair of nodes with keys derived from their identities, and a node installs a peer's
wireguard key only if the peer's identity is a valid member and signed its metadata. The design is described in
[`docs/membership.md`](docs/membership.md).

Compromise of a node yields that node's identity, which any member can revoke with `wesher revoke`. Until revoked, an
attacker holding it can:
- access services exposed on the overlay network
- impersonate that node and disrupt traffic to and from it
It cannot decrypt traffic between other nodes, and it cannot admit new nodes without also minting a token on a member.

Node metadata received over the cluster is validated before use: peers whose metadata is not signed by a valid member,
whose overlay address falls outside `--overlay-net` or whose wireguard key does not parse are logged and ignored.

This membership model is not compatible with upstream wesher's shared cluster key; a cluster is migrated by recreating it.

## Current known limitations

### Overlay IP collisions

Since the assignment of IPs on the overlay network is decided by the individual node and implemented as a
naive hashing of the hostname, there can be no guarantee two hosts will not generate the same overlay IPs.
A larger `--overlay-net` reduces the chance; collision detection is a candidate for future work.

### Split-brain

Once a cluster is joined, there is currently no way to distinguish a failed node from an intentionally removed one.
This is partially by design: growing and shrinking your cluster dynamically (e.g. via autoscaling) should be as easy
as possible.

However, this does mean longer connection loss between any two parts of the cluster (e.g. across a WAN link between
different cloud providers) can lead to a split-brain scenario where each side thinks the other side is simply "gone".

There is currently no clean solution for this problem, but one could work around it by designating edge nodes which
periodically restart `wesher` with the `--join` option pointing to the other side.
Static seed nodes that are re-joined periodically are a candidate for future work.
