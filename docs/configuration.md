# Configuration

Options come from command-line flags or from a YAML configuration file,
`/etc/cheesecloth/config.yaml` by default (on Windows `%ProgramData%\cheesecloth\config.yaml`) or the file named by `--config`.
Config keys are the flag names without the leading dashes, e.g. `bind-addr: "::"`.
A flag given on the command line overrides the file. Unknown keys in the file are
an error, as are `join-key` and `init`, which are one-time actions and stay on the
command line. Environment variables are not read. An annotated example is in
[`dist/config.yaml`](../dist/config.yaml).

| Option | Config key | Description | Default |
|---|---|---|---|
| `--join HOST[:PORT],...` | `join` | comma separated list of hostnames or IP addresses of existing cluster members, with the cluster port unless given; if not provided, will attempt resuming any known state or otherwise wait for further members |  |
| `--join-key TOKEN` | command line only | invitation token from `cheesecloth invite` on a member; needed only the first time this node joins, ignored afterwards |  |
| `--init` | command line only | start a new cluster with this node as its root; any known state from previous runs will be forgotten | `false` |
| `--control-socket PATH` | `control-socket` | unix socket used by `cheesecloth invite` and `cheesecloth revoke` | `/run/cheesecloth/<interface>.sock` on Linux, see [Platforms](operations.md#platforms) |
| `--bind-addr ADDR` | `bind-addr` | address to bind for cluster membership; `0.0.0.0` or `::` binds every interface of that family and advertises one of its addresses (public preferred). The family decides whether the cluster runs over IPv4 or IPv6, see [IPv4 and IPv6](#ipv4-and-ipv6) | `0.0.0.0` |
| `--cluster-port PORT` | `cluster-port` | UDP port used for membership gossip and enrolment (QUIC); must be the same across cluster | `7946` |
| `--wireguard-port PORT` | `wireguard-port` | port used for wireguard traffic (UDP); must be the same across cluster | `51820` |
| `--overlay-net ADDR/MASK` | `overlay-net` | the network in which to allocate addresses for the overlay mesh network (CIDR format); must be the same across cluster | `10.0.0.0/8` |
| `--allowed-ips NET/MASK,...` | `allowed-ips` | extra networks reachable through this node, see [Routing networks through a node](#routing-networks-through-a-node); must not overlap `--overlay-net` |  |
| `--interface DEV` | `interface` | name of the wireguard interface to create and manage | `wgoverlay` |
| `--mtu MTU` | `mtu` | MTU of the wireguard interface | `1420` |
| `--persistent-keepalive DURATION` | `persistent-keepalive` | interval at which peers send keepalives, to keep NAT mappings open (e.g. `25s`); `0` disables | `0` |
| `--no-etc-hosts` | `no-etc-hosts` | whether to skip writing hosts entries for each node in mesh | `false` |
| `--userspace` | `userspace` | run WireGuard inside the agent instead of the kernel module (Linux); the default wherever the kernel has none, see [Platforms](operations.md#platforms) | `false` |
| `--log-level LEVEL` | `log-level` | set the verbosity (one of debug/info/warn/error) | `warn` |
| `--config PATH` | command line only | configuration file to read | `/etc/cheesecloth/config.yaml` on Linux and macOS, see [Platforms](operations.md#platforms) |

## Overlay addresses

The overlay IP address of each node is allocated out of a private network
(`10.0.0.0/8` by default; it must not overlap the network the nodes use to
reach each other). The node that ran `--init` takes the first address; each node
enrolled afterwards is assigned the lowest free address by the member that
admitted it, and that assignment is part of its signed admission record.
Addresses are therefore stable across restarts, allocated from the start of
the network, and agreed on by every member. A node claiming an address other
than its assigned one is ignored.

The overlay network must be the same on every node. Changing `--overlay-net`
on every node changes every address, since each node keeps its slot number.

The node's hostname identifies it in the cluster and must be unique; enrolment
refuses a name another member already holds.

## IPv4 and IPv6

Any address option accepts either family. Two independent choices are made per
cluster:

- **Underlay** (cluster gossip and wireguard endpoints): set by the family of
  `--bind-addr`. `0.0.0.0` (the default) or a specific IPv4 address makes
  an IPv4 cluster; `::` or a specific IPv6 address makes an IPv6 cluster. Every
  node of a cluster must use the same family, since an IPv4-only node cannot
  reach an IPv6-only one. Dual-stack hosts can join either kind of cluster.
- **Overlay** (the mesh addresses): the family of `--overlay-net`, independent
  of the underlay. An IPv6 overlay such as `fd00:10::/64` over an IPv4 underlay
  works, and so does the reverse.

With a wildcard bind address, cheesecloth advertises one of the host's addresses
of that family to the cluster, preferring a public one, then any global unicast
address (RFC 1918 and unique local addresses included). Link-local addresses and
addresses on the cheesecloth interface itself are never chosen. Set a specific
`--bind-addr` to control it.

## Routing networks through a node

A node can advertise networks behind it with `--allowed-ips` (for example a LAN,
or a cloud VPC's private range). Every peer adds them to that node's wireguard
allowed IPs and routes them over the overlay interface, so hosts on those
networks are reachable from the whole mesh through the advertising node. The
advertising node must have IP forwarding enabled (`sysctl net.ipv4.ip_forward=1`
or the IPv6 equivalent) and the hosts behind it need a way back, typically a
route for the overlay network via that node or masquerading on it.

Advertised networks are signed with the rest of the node's metadata. They must
not overlap the overlay network, and a network advertised by two nodes is routed
via the first by name; both cases are logged and otherwise ignored. Routes on the
overlay interface are managed by cheesecloth: anything added by hand is removed
on the next membership change.

## /etc/hosts

cheesecloth adds an entry to `/etc/hosts` for each peer, so the nodes' hostnames
resolve to their overlay addresses (assuming `files` comes first for `hosts` in
`/etc/nsswitch.conf`). `--no-etc-hosts` disables this. On Windows the file is
`%SystemRoot%\System32\drivers\etc\hosts`.

## Running multiple clusters

To make a node a member of several clusters, start one cheesecloth instance per
cluster. Each instance must have different values for:

- `--interface`
- either `--cluster-port` or `--bind-addr`
- `--wireguard-port`

`--overlay-net` need not differ but should, so a host in both clusters does not
see the same addresses twice.
