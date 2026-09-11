[![Build Status](https://github.com/jdpanderson/cheesecloth/actions/workflows/main.yaml/badge.svg)](https://github.com/jdpanderson/cheesecloth/actions/workflows/main.yaml)

# cheesecloth

cheesecloth is an easy mesh network for tinkerers. Point it at a handful of machines, anywhere you like, and it knits
them into one private network over [WireGuard](https://www.wireguard.com/): every node talks to every other node
directly and encrypted, each gets a stable address and a hostname, and the whole thing survives reboots without you
touching it. There is no controller to run and no shared secret to guard. Adding a machine is one invitation; removing
one is one command.

## Quickstart

You need the WireGuard kernel module on every node (bundled with Linux 5.6 and later) and two UDP ports open between
them: 51820 for WireGuard and 7946 for cheesecloth itself.

1. Get the binary, on every node:

   ```
   $ wget -O cheesecloth https://github.com/jdpanderson/cheesecloth/releases/latest/download/cheesecloth-$(go env GOARCH)
   $ chmod a+x cheesecloth
   ```

2. On the first node, start a cluster:

   ```
   # ./cheesecloth --init
   ```

3. Still there, invite the next node:

   ```
   # ./cheesecloth invite
   7xk3...
   valid for 10m0s, 1 use(s). On the new node:
     cheesecloth --join <this host> --join-key 7xk3...
   ```

4. On the new node, do as it says:

   ```
   # ./cheesecloth --join first.example.net --join-key 7xk3...
   ```

That is the mesh. Repeat steps 3 and 4 from any member for each further node. Afterwards nodes restart with a bare
`cheesecloth`, `cheesecloth status` shows the peers, and `cheesecloth revoke NAME` removes one. For running it as a
service and everything else, see [operations](docs/operations.md).

## How it works

Each node has a persistent identity, an Ed25519 key it generates on first start. Membership is a set of signed
admission records rooted at the node that ran `--init`: to admit a node, an existing member signs a record for it, and
every node can check the chain of signatures back to the root. There is no cluster key to leak; a stolen node yields
one identity, which any member can revoke.

Admission happens over an invitation. `cheesecloth invite` mints a random token that lives only in that member's
memory until it is used or expires. Joiner and member prove to each other that they know it, the member signs the
admission, and both forget the token. The admission also assigns the joiner the lowest free address in the overlay
network, so addresses are dense, stable and agreed on by every node.

Nodes then gossip over QUIC on one UDP port, using [memberlist](https://github.com/hashicorp/memberlist) for
membership and failure detection. Every connection is a TLS 1.3 session authenticated by the identity certificates on
both ends, accepted only for valid members. Over it each node announces its ephemeral WireGuard key, its overlay address
and any networks it routes, signed by its identity. Peers verify the announcement against the records and configure
kernel WireGuard accordingly: peer keys, endpoints, allowed IPs, routes and `/etc/hosts` entries follow the membership
automatically.

## Further reading

- [Configuration](docs/configuration.md): every option, the config file, IPv6, routing networks through a node, and
  running several clusters on one host.
- [Operations](docs/operations.md): permissions, systemd, status, recovery, building from source, security
  considerations and known limitations.
- [Membership design](docs/membership.md): identities, records, the enrolment exchange and the transport, in detail.
- [wesher](https://github.com/costela/wesher): the project cheesecloth was forked from. It keeps wesher's shape, a
  gossiped WireGuard mesh, but shares no protocol, state or key model with it.
