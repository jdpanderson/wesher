[![Build Status](https://github.com/jdpanderson/cheesecloth/actions/workflows/main.yaml/badge.svg)](https://github.com/jdpanderson/cheesecloth/actions/workflows/main.yaml)

# cheesecloth

`cheesecloth` creates and manages an encrypted mesh overlay network across a group of nodes, using [wireguard](https://www.wireguard.com/).

Its main use-case is adding low-maintenance security to public-cloud networks or connecting different cloud providers.

cheesecloth began as a fork of [costela/wesher](https://github.com/costela/wesher) and keeps its overall shape, but
shares no wire protocol, state or key model with it: membership is decided by per-node identities and invitation
tokens rather than a shared cluster key.

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
   $ wget -O cheesecloth https://github.com/jdpanderson/cheesecloth/releases/latest/download/cheesecloth-$(go env GOARCH)
   $ chmod a+x cheesecloth
   ```

2. On the first node, start a new cluster:
   ```
   # ./cheesecloth --init
   ```

   This starts the daemon in the foreground. The node generates its identity and becomes the cluster's root.

3. Still on that node (or any node already in the cluster), mint an invitation for the node you want to add:
   ```
   # cheesecloth invite
   7xk3...
   valid for 10m0s, 1 use(s). On the new node:
     cheesecloth --join <this host> --join-key 7xk3...
   ```

   The token lives only in the inviting node's memory until it is used or expires. `--uses N` lets one token enrol
   several nodes, for example when a group of machines boots together.

4. On the new node:
   ```
   # cheesecloth --join x.x.x.x --join-key 7xk3...
   ```

   Where `x.x.x.x` is the hostname or IP of the node that minted the token. The two nodes prove to each other that
   they know the token, the new node is admitted, and the token is discarded on both sides. From then on the node
   restarts with plain `cheesecloth`; its identity and the membership records are kept in `/var/lib/cheesecloth/`.

   To remove a node again, on any member: `cheesecloth revoke NAME`.

### Permissions 

Note that `wireguard` - and therefore `cheesecloth` - need root access to work properly.

It is also possible to give the `cheesecloth` binary enough capabilities to manage the `wireguard` interface via:
```
# setcap cap_net_admin=eip cheesecloth
```
This will enable running as an unprivileged user, but some functionality (like automatic adding peer entries to
`/etc/hosts`; see [configuration options](#configuration-options) below) will not work.

### (optional) systemd integration

A minimal `systemd` unit file is provided under the `dist` folder and can be copied to `/etc/systemd/system`:
```
# wget -O /etc/systemd/system/cheesecloth.service https://raw.githubusercontent.com/jdpanderson/cheesecloth/main/dist/cheesecloth.service
# systemctl daemon-reload
# systemctl enable cheesecloth
```
The provided unit file assumes `cheesecloth` is installed to `/usr/local/sbin`.

Put the node's settings in `/etc/cheesecloth/config.yaml` (see [configuration options](#configuration-options) below).
The join key never goes in the file: enrol the node once by hand, or from a provisioning step, with
`cheesecloth --join-key TOKEN` (the `join` hosts can come from the file), then let the unit start it on every boot.

## Checking on a node

`cheesecloth status` shows the wireguard interface and its peers, with the last handshake age and traffic counters, naming
peers from the persisted cluster state. Add `--json` for machine-readable output and `--interface` if not using the
default. It needs the same privileges as the agent.

```
# cheesecloth status
interface: wgoverlay
address:   10.171.249.28/32
port:      51820
pubkey:    41p91phfnFloks55MFP1iZfRQ11VdEpTAufFwv8j810=
peers:     2

NAME   OVERLAY         ENDPOINT         HANDSHAKE  RX       TX
test2  10.171.252.205  10.89.0.3:51820  12s ago    1.5 KiB  3.0 KiB
test3  10.171.251.146  10.89.0.4:51820  never      0 B      0 B
```

`cheesecloth invite` and `cheesecloth revoke NAME` manage membership through the running agent (see [Quickstart](#quickstart)).

## Installing from source

```
$ git clone https://github.com/jdpanderson/cheesecloth.git
$ cd cheesecloth
$ make
```
This builds a bit-by-bit identical binary to the released ones, assuming the same go version is used to build its respective git tag.

Alternatively, without a checkout (`--version` will then report `dev` rather than a tag):
```
$ go install github.com/jdpanderson/cheesecloth/cmd/cheesecloth@latest
```

## Features

The `cheesecloth` tool builds a cluster and manages the configuration of wireguard on each node to create peer-to-peer
connections between all nodes, thus forming a full mesh VPN.
This approach may not scale for hundreds of nodes (benchmarks accepted 😉), but is sufficiently performant to join
several nodes across multiple cloud providers, or simply to secure inter-node comunication in a single public-cloud.

### Automatic key management

Each node has a persisted identity, created on its first start. The wireguard private key is created fresh on every
start and its public key is gossiped across the cluster, signed by the node's identity.

Cluster communication is encrypted and authenticated per pair of nodes with keys derived from their identities; there
is no shared cluster key. New nodes are admitted with a short-lived invitation token minted on an existing member (see
[Quickstart](#quickstart)).

### Automatic IP address management

The overlay IP address of each node is automatically selected out of a private network (`10.0.0.0/8` by default; MUST be different from the underlying network used for cluster communication) and is consistently hashed based on the peer's hostname.

The use of consistent hashing means a given node will always receive the same overlay IP address (see [limitations](#overlay-ip-collisions)
of this approach below).

**Note**: the node's hostname is also used by the underlying cluster management (using [memberlist](https://github.com/hashicorp/memberlist))
to identify nodes and must therefore be unique in the cluster.

### Automatic /etc/hosts management

To ease intra-node communication, `cheesecloth` also adds entries to `/etc/hosts` for each peer in the mesh. This enables using the nodes' hostnames to ensure communication over the secured overlay network (assuming `files` is the first entry for `hosts` in `/etc/nsswitch.conf`).

See [configuration](#configuration-options) below for how to disable this behavior.

### Seamless restarts

If a node in the cluster is restarted, it re-joins the last-known nodes using its persisted identity.
This means a restart requires no manual intervention, even if every node restarts at once.

## Configuration options

Options come from command-line flags or from a YAML configuration file, `/etc/cheesecloth/config.yaml` by default or
the file named by `--config`. Config keys are the flag names without the leading dashes, e.g. `bind-addr: "::"`.
A flag given on the command line overrides the file. Unknown keys in the file are an error, as are `join-key` and
`init`, which are one-time actions and stay on the command line. Environment variables are not read.
An annotated example lives in [`dist/config.yaml`](dist/config.yaml).

| Option | Config key | Description | Default |
|---|---|---|---|
| `--join HOST,...` | `join` | comma separated list of hostnames or IP addresses of existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members |  |
| `--join-key TOKEN` | command line only | invitation token from `cheesecloth invite` on a member; needed only the first time this node joins, ignored afterwards |  |
| `--init` | command line only | start a new cluster with this node as its root; any known state from previous runs will be forgotten | `false` |
| `--control-socket PATH` | `control-socket` | unix socket used by `cheesecloth invite` and `cheesecloth revoke` | `/run/cheesecloth/<interface>.sock` |
| `--bind-addr ADDR` | `bind-addr` | address to bind for cluster membership; `0.0.0.0` or `::` binds every interface of that family and advertises one of its addresses (public preferred). The family decides whether the cluster runs over IPv4 or IPv6, see [IPv4 and IPv6](#ipv4-and-ipv6) | `0.0.0.0` |
| `--cluster-port PORT` | `cluster-port` | port used for membership gossip traffic (both TCP and UDP); must be the same across cluster | `7946` |
| `--wireguard-port PORT` | `wireguard-port` | port used for wireguard traffic (UDP); must be the same across cluster | `51820` |
| `--overlay-net ADDR/MASK` | `overlay-net` | the network in which to allocate addresses for the overlay mesh network (CIDR format); smaller networks increase the chance of IP collision | `10.0.0.0/8` |
| `--interface DEV` | `interface` | name of the wireguard interface to create and manage | `wgoverlay` |
| `--mtu MTU` | `mtu` | MTU of the wireguard interface | `1420` |
| `--persistent-keepalive DURATION` | `persistent-keepalive` | interval at which peers send keepalives, to keep NAT mappings open (e.g. `25s`); `0` disables | `0` |
| `--no-etc-hosts` | `no-etc-hosts` | whether to skip writing hosts entries for each node in mesh | `false` |
| `--log-level LEVEL` | `log-level` | set the verbosity (one of debug/info/warn/error) | `warn` |
| `--config PATH` | command line only | configuration file to read | `/etc/cheesecloth/config.yaml` |

## IPv4 and IPv6

Any address option accepts either family. Two independent choices are made per cluster:

- **Underlay** (cluster gossip and wireguard endpoints): the family of `--bind-addr` decides. `0.0.0.0` (the default)
  or a specific IPv4 address makes an IPv4 cluster; `::` or a specific IPv6 address makes an IPv6 cluster. Every node
  of a cluster must use the same family, since an IPv4-only node cannot reach an IPv6-only one. Dual-stack hosts can
  join either kind of cluster.
- **Overlay** (the mesh addresses): the family of `--overlay-net`, independent of the underlay. An IPv6 overlay such
  as `fd00:10::/64` over an IPv4 underlay works, and so does the reverse.

With a wildcard bind address, cheesecloth advertises one of the host's addresses of that family to the cluster, preferring
a public one, then any global unicast address (RFC 1918 and unique local addresses included). Link-local addresses and
addresses on the cheesecloth interface itself are never chosen. Set a specific `--bind-addr` to control it.

## Running multiple clusters

To make a node be a member of multiple clusters, simply start multiple cheesecloth instances.  
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

Compromise of a node yields that node's identity, which any member can revoke with `cheesecloth revoke`. Until revoked, an
attacker holding it can:
- access services exposed on the overlay network
- impersonate that node and disrupt traffic to and from it
It cannot decrypt traffic between other nodes, and it cannot admit new nodes without also minting a token on a member.

Node metadata received over the cluster is validated before use: peers whose metadata is not signed by a valid member,
whose overlay address falls outside `--overlay-net` or whose wireguard key does not parse are logged and ignored.

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
periodically restart `cheesecloth` with the `--join` option pointing to the other side.
Static seed nodes that are re-joined periodically are a candidate for future work.
