# Operations

## Permissions

wireguard, and therefore cheesecloth, needs root to work properly. The binary
can instead be given the capability to manage the wireguard interface:

```
# setcap cap_net_admin=eip cheesecloth
```

This allows running as an unprivileged user, but writing `/etc/hosts` will not
work (see `--no-etc-hosts` in [configuration](configuration.md)).

## systemd

A unit file is provided under `dist` and can be copied to `/etc/systemd/system`:

```
# wget -O /etc/systemd/system/cheesecloth.service https://raw.githubusercontent.com/jdpanderson/cheesecloth/main/dist/cheesecloth.service
# systemctl daemon-reload
# systemctl enable cheesecloth
```

It assumes cheesecloth is installed to `/usr/local/sbin`. It is a `Type=notify`
service: cheesecloth tells systemd it is ready once it has joined the cluster
and configured the interface, so a unit with `After=cheesecloth.service` and
`Requires=cheesecloth.service` starts with the overlay in place. `systemctl
status` shows the current peer count.

Put the node's settings in `/etc/cheesecloth/config.yaml`. The join key never
goes in the file: enrol the node once by hand, or from a provisioning step, with
`cheesecloth --join-key TOKEN` (the `join` hosts can come from the file), then
let the unit start it on every boot.

## Checking on a node

`cheesecloth status` shows the wireguard interface and its peers, with the last
handshake age, traffic counters and advertised routes, naming peers from the
persisted cluster state. Add `--json` for machine-readable output and
`--interface` if not using the default. It needs the same privileges as the agent.

```
# cheesecloth status
interface: wgoverlay
address:   10.0.0.1/32
port:      51820
pubkey:    gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA=
identity:  KE9rn7ryXPCL+A1uHT1Or7tnBG/eheIihMPaYcN9EME=
peers:     2

NAME     IDENTITY  OVERLAY   ENDPOINT              HANDSHAKE  RX     TX     ROUTES
linode2  mFrk3G+0  10.0.0.2  178.79.147.187:51820  2s ago     348 B  404 B  -
linode3  kwvzJSL2  10.0.0.3  172.105.13.112:51820  1s ago     348 B  404 B  -
```

`cheesecloth invite [--ttl 10m] [--uses 1]` creates an invitation token on a
running member. `cheesecloth revoke NAME|IDENTITY` removes a member. Every
peer stops talking to the revoked node; the revoked node is not notified.

## Restarts and recovery

A restarted node rejoins the last known peers using its persisted identity in
`/var/lib/cheesecloth/<interface>.json`. No token is needed, even if every node
restarts at once. A node that loses that file has lost its identity: enrol it
again with a fresh invitation and revoke the old identity.

## Installing from source

```
$ git clone https://github.com/jdpanderson/cheesecloth.git
$ cd cheesecloth
$ make
```

This builds a bit-by-bit identical binary to the released ones, given the same
Go version as the tag. Without a checkout (`--version` will then report `dev`):

```
$ go install github.com/jdpanderson/cheesecloth/cmd/cheesecloth@latest
```

## Packages

The repository carries packaging for two distributions. Both install the
binary, the systemd unit and `/etc/cheesecloth/config.yaml` as a configuration
file, and leave the service disabled: initialise or enrol the node once by
hand, edit the configuration, then `systemctl enable --now cheesecloth`.

- Debian and derivatives: `debian/`. Build with `dpkg-buildpackage -us -uc -b`
  from a checkout; see `debian/README.source` for the Go toolchain
  requirement. The binary is installed as `/usr/sbin/cheesecloth`.
- Arch Linux: `arch/PKGBUILD` builds the `cheesecloth-git` package from the
  repository with `makepkg`. The binary is installed as `/usr/bin/cheesecloth`.

## Security considerations

There is no cluster-wide secret. Each node has a persisted identity (an Ed25519
key), and membership is a set of signed admission records rooted at the node
that ran `--init`. A new node is admitted when it and an existing member prove
to each other that they know an invitation token; the token exists only during
that exchange. Cluster gossip runs over QUIC, inside a TLS 1.3 session per pair
of nodes authenticated by their identity keys (self-signed certificates, no CA),
and a node installs a peer's wireguard key only if the peer's identity is a valid
member and signed its metadata. The design is described in
[membership.md](membership.md).

An attacker who compromises a node obtains that node's identity, which any
member can revoke with `cheesecloth revoke`. Until it is revoked, the attacker
can:

- access services exposed on the overlay network
- impersonate that node and disrupt traffic to and from it
- attract traffic for any network outside the overlay by advertising it with
  `--allowed-ips`, since every member trusts every other member's advertisements

It cannot decrypt traffic between other nodes, and it cannot admit new nodes
without also minting a token on a member.

Nodes are expected to keep their clocks synchronised; records are ordered by the
issuer's clock (see [membership.md](membership.md#clocks)).

## Known limitations

### Overlay address collisions

Two nodes can be assigned the same overlay address only if two different members
admit new nodes at the same moment, before either admission has reached the
other. The signed records still decide: the earlier admission keeps the address
and every node ignores the later one, logging the collision. The losing node
keeps running without peers until it is enrolled again: stop it, delete
`/var/lib/cheesecloth/<interface>.json`, and start it with a fresh invitation.

### Split-brain

cheesecloth does not distinguish a failed node from one that was removed on
purpose. This is intentional, so that a cluster can grow and shrink without
configuration changes. A long connection loss between two parts of the cluster
(for example across a WAN link between providers) therefore causes each side to
treat the other as failed. A workaround is to restart cheesecloth periodically
on one node of each side with `--join` pointing at the other side. Static seed
nodes are a candidate for future work.
