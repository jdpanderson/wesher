# Identity-based membership

Status: design accepted and implemented 2026-09-08.

## Goals

- No cluster-wide secret exists, on disk or in memory, after enrolment.
- A human enrols a node by proving knowledge of a short-lived token; the
  token is then gone from every machine.
- A stolen node yields one revocable identity, not the cluster.
- Nodes restart unattended, including all of them at once.
- Protocol versions are explicit (enrolment message, packet version byte,
  TLS ALPN) so mismatched nodes fail closed rather than half-working.

## Roles of the two key layers

WireGuard already gives every node a key pair and protects the data plane
with a Noise handshake. It stays exactly as it is. What changes is how a
node decides *which* WireGuard public keys it will install as peers, and how
the gossip that carries them is protected. Today both rest on one symmetric
key that every node holds forever. They now rest on per-node identities and
a signed admission list.

## Identity

Each node has a 32-byte random seed, generated on first start and persisted
in its state file (mode 0600). Two keys derive from it:

| Key | Derivation | Used for |
|---|---|---|
| signing key (Ed25519) | `ed25519.NewKeyFromSeed(seed)` | signing admission records and node metadata; TLS certificate for gossip streams |
| DH key (X25519) | `HKDF-SHA256(seed, info="cheesecloth/dh/v1")` | pairwise keys for gossip packets and the enrolment exchange |

A node's **identity** is its Ed25519 public key. The DH public key travels
inside the node's admission record, so it is bound to the identity by the
admitter's signature.

## Admission records

Membership is a grow-only set of signed records, not a secret.

```
Admission  { Identity, DHKey, Name, Host, Admitter, IssuedAt, Signature }
Revocation { Identity, Revoker, IssuedAt, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v1`, `cheesecloth/revocation/v1`).

- The founding node signs its own admission (`Admitter == Identity`). That
  record is the **root**. Every other node pins the root's identity in its
  state file; a self-signed record is accepted only for the pinned root.
- An admission is valid if its signature verifies and its admitter is the
  root or itself holds a valid admission. Validity is evaluated recursively
  with a cycle guard.
- A revocation is valid if signed by a valid identity. A revoked identity is
  no longer a member. Admissions it issued earlier stay valid: those nodes
  proved token knowledge at the time, and cascading would surprise operators.
  Revoke them explicitly if that is what is wanted.
- Records are distributed by memberlist's push/pull state sync (whole set,
  union merge) and by broadcast when a record is created. Nodes persist the
  set, so a restarted node has it before contacting anyone.

### Overlay addresses

`Host` is the member's slot in the overlay network: its address is
`--overlay-net` with the host part set to `Host`. The root takes slot 1; an
admitter gives a joiner the lowest slot no admission in its set uses (slots of
revoked members are reused only when nothing else is free). Every node derives
every member's address from the same records, so addresses are stable across
restarts, dense in the overlay net, and independent of hostnames. Changing
`--overlay-net` on every node moves the whole mesh without re-enrolling.

Two members can be handed the same slot only if two admitters enrol joiners
at the same time, before either admission has spread. The records still
decide: the earlier admission (then the smaller identity) keeps the slot and
every node excludes the other, logging the collision. The losing node keeps
running but has no peers until it is enrolled again (delete its state file and
join with a fresh invitation).

## Enrolment

The join token is an invitation minted by a running member, not a long-lived
cluster secret:

```
member$  cheesecloth invite [--ttl 10m] [--uses 1]     -> prints TOKEN
newnode$ cheesecloth --join member --join-key TOKEN
```

The member keeps the 32-byte token only in memory, with its expiry and
remaining uses. The joiner holds it only for the exchange. Nothing writes it
to disk. Enrolment runs as a QUIC stream on the cluster port under ALPN
`cheesecloth-enrol/1`, so no new port is opened. The joiner is not a member
yet, so on that ALPN both sides only parse the other's identity certificate;
the exchange below then requires the identities named in the messages to be
the ones on the wire, and decides on the token.

Exchange, with `J`/`M` the joiner's and member's identities, `Jd`/`Md` their
DH public keys, and `K` the token:

1. Joiner -> Member: `Hello{Version, TokenID, J, Jd, nJ, Name}` where
   `TokenID = SHA-256(K)[:8]` lets the member pick the pending token without
   revealing it.
2. Both derive `ss = X25519(own DH private, other DH public)` and
   `kMac = HKDF-SHA256(ss || K, salt = nJ || nM, info="cheesecloth/enroll/v1")`.
   Member -> Joiner: `M, Md, nM, HMAC(kMac, "member" || transcript)`.
3. Joiner verifies; it now knows the member holds `K`. Joiner -> Member:
   `HMAC(kMac, "joiner" || transcript)`.
4. Member verifies, consumes one token use, signs an admission for `J`,
   broadcasts it, and sends the joiner the root record, the full record set,
   and its own gossip address. Both sides discard `K`.

`transcript = J || Jd || M || Md || nJ || nM || Name`. Binding both identities
and both DH keys into the MACs is what lets the token be dropped: after step 4
the identities are the trust anchors. The distinct labels stop reflection;
the nonces stop replay; mixing `ss` into the derivation means the MACs cannot
be forged by someone who learns `K` afterwards. Confidentiality comes from the
QUIC stream, whose TLS peers are the same `J` and `M`. A member that finds no
pending token for `TokenID` closes the stream without a reply, so the server
is not an oracle for token guessing. Tokens are 256-bit random, so a PAKE is
unnecessary.

## Gossip transport

memberlist's own encryption is disabled; cheesecloth supplies a `Transport`
that runs memberlist over QUIC (quic-go) on the cluster port, one UDP socket
for both listening and dialling so that peers see a node's gossip address as
the source of everything it sends.

Each pair of nodes shares one QUIC connection, authenticated on both sides by
TLS 1.3 with self-signed certificates for the nodes' Ed25519 identity keys:
there is no CA. Certificate verification ignores chains and asks the
membership set whether the peer's key is a valid member (root pinning is
implicit because validity derives from the root). ALPN `cheesecloth-gossip/1`
is required. memberlist packets travel as QUIC datagrams (RFC 9221), so its
packet budget is set to 1100 bytes; push/pull exchanges travel as streams.

A packet to a node with no connection yet is dropped while a connection is
dialled in the background, as UDP would drop it, and memberlist's next round
gets through. Failure detection relies on this: memberlist treats a lost probe
as evidence, and a send error as its own fault. A member that is revoked while
connected has its connection closed on the next packet or stream it sends.

## Node metadata

Gossiped per node (memberlist limit 512 bytes):
`{ OverlayAddr, WGPubKey, AllowedIPs, Identity, Signature }` with
`Signature = Ed25519(identity, "cheesecloth/meta/v1" || Name || OverlayAddr || WGPubKey || AllowedIPs...)`.
`AllowedIPs` are the extra networks the node routes (`--allowed-ips`), each
encoded as address bytes plus prefix length.
A node installs a peer's WireGuard key only if the identity is a valid member,
the signature verifies, and `OverlayAddr` is the address the peer's admission
assigns. This binds each node's ephemeral WireGuard key to its persisted
identity without persisting the WireGuard key, and stops a member from
claiming another's address.

## Restart and recovery

A restarting node has its seed, the pinned root, the record set, and its last
known peers on disk. It reconnects over TLS to any of them and rejoins. No
token and no operator are involved. If every node restarts at once, each still
has everything it needs; nothing has to be fetched. Losing a node's disk loses
that node's identity; it re-enrols with a fresh token and the old identity
can be revoked.

## Operations

- `cheesecloth --init`: create identity and root; start the cluster.
- `cheesecloth --join HOST --join-key TOKEN`: first start of a new node.
- `cheesecloth --join HOST` or bare `cheesecloth`: restart of an admitted node.
- `cheesecloth invite [--ttl] [--uses]`: mint a token on a member (via the control
  socket `/run/cheesecloth/<interface>.sock`).
- `cheesecloth revoke NAME|IDENTITY`: sign and broadcast a revocation.
- `cheesecloth status`: peers now show identity fingerprints.

## Out of scope for now

Rotation of the pinned root; cascading revocation; a PAKE for short human
codes; gossip forward secrecy (packets use static-static DH; WireGuard traffic
has forward secrecy already).
