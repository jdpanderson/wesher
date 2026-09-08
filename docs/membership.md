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
| DH key (X25519) | `HKDF-SHA256(seed, info="wesher/dh/v1")` | pairwise keys for gossip packets and the enrolment exchange |

A node's **identity** is its Ed25519 public key. The DH public key travels
inside the node's admission record, so it is bound to the identity by the
admitter's signature.

## Admission records

Membership is a grow-only set of signed records, not a secret.

```
Admission  { Identity, DHKey, Name, Admitter, IssuedAt, Signature }
Revocation { Identity, Revoker, IssuedAt, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`wesher/admission/v1`, `wesher/revocation/v1`).

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

## Enrolment

The join token is an invitation minted by a running member, not a long-lived
cluster secret:

```
member$  wesher invite [--ttl 10m] [--uses 1]     -> prints TOKEN
newnode$ wesher --join member --join-key TOKEN
```

The member keeps the 32-byte token only in memory, with its expiry and
remaining uses. The joiner holds it only for the exchange. Nothing writes it
to disk. Enrolment runs over TCP on the WireGuard port (WireGuard itself uses
only UDP on that port), so no new port is opened.

Exchange, with `J`/`M` the joiner's and member's identities, `Jd`/`Md` their
DH public keys, and `K` the token:

1. Joiner -> Member: `Hello{Version, TokenID, J, Jd, nJ, Name}` where
   `TokenID = SHA-256(K)[:8]` lets the member pick the pending token without
   revealing it.
2. Both derive `ss = X25519(own DH private, other DH public)` and
   `kMac, kEnc = HKDF-SHA256(ss || K, salt = nJ || nM, info="wesher/enroll/v1")`.
   Member -> Joiner: `M, Md, nM, HMAC(kMac, "member" || transcript)`.
3. Joiner verifies; it now knows the member holds `K`. Joiner -> Member:
   `HMAC(kMac, "joiner" || transcript)`.
4. Member verifies, consumes one token use, signs an admission for `J`,
   broadcasts it, and sends the joiner, encrypted under `kEnc`: the root
   record, the full record set, and its own gossip address. Both sides
   discard `K`.

`transcript = J || Jd || M || Md || nJ || nM || Name`. Binding both identities
and both DH keys into the MACs is what lets the token be dropped: after step 4
the identities are the trust anchors. The distinct labels stop reflection;
the nonces stop replay; mixing `ss` into the derivation means an eavesdropper
who later learns `K` still cannot recover `kEnc`. A member that finds no
pending token for `TokenID` closes the connection without a reply, so the
server is not an oracle for token guessing. Tokens are 256-bit random, so a
PAKE is unnecessary.

## Gossip transport

memberlist's own encryption is disabled; wesher supplies a `Transport` that
wraps memberlist's `NetTransport` and authenticates every message with node
identities.

**Packets (UDP)**: `0x01 || sender identity (32) || nonce (12) || AES-256-GCM(
key = pairKey, ad = header || recipient identity, plaintext)`. `pairKey =
HKDF-SHA256(X25519(sender DH, recipient DH), salt = sorted identities,
info="wesher/gossip/v1")`, cached per peer. A receiver drops packets from
identities that are not valid members. The 61-byte overhead is subtracted
from memberlist's UDP buffer size.

**Streams (TCP)**: TLS 1.3 with mutual authentication. Each node presents a
self-signed certificate for its Ed25519 signing key; the peer certificate is
accepted only if its public key is a valid member (root pinning is implicit
because validity derives from the root). Streams carry the join push/pull,
so a node that knows a member's address can rejoin with no other knowledge.

To encrypt a packet the sender needs the recipient's identity for a given
`ip:port`. The cluster keeps an address book filled from node metadata as
memberlist reports members, and from the enrolment reply. A packet to an
address not yet in the book fails to send; memberlist retries on its next
gossip round, by which time the streamed push/pull has populated the book.

## Node metadata

Gossiped per node (memberlist limit 512 bytes):
`{ OverlayAddr, WGPubKey, Identity, Signature }` with
`Signature = Ed25519(identity, "wesher/meta/v1" || Name || OverlayAddr || WGPubKey)`.
A node installs a peer's WireGuard key only if the identity is a valid member
and the signature verifies. This binds each node's ephemeral WireGuard key to
its persisted identity without persisting the WireGuard key.

## Restart and recovery

A restarting node has its seed, the pinned root, the record set, and its last
known peers on disk. It reconnects over TLS to any of them and rejoins. No
token and no operator are involved. If every node restarts at once, each still
has everything it needs; nothing has to be fetched. Losing a node's disk loses
that node's identity; it re-enrols with a fresh token and the old identity
can be revoked.

## Operations

- `wesher --init`: create identity and root; start the cluster.
- `wesher --join HOST --join-key TOKEN`: first start of a new node.
- `wesher --join HOST` or bare `wesher`: restart of an admitted node.
- `wesher invite [--ttl] [--uses]`: mint a token on a member (via the control
  socket `/run/wesher/<interface>.sock`).
- `wesher revoke NAME|IDENTITY`: sign and broadcast a revocation.
- `wesher status`: peers now show identity fingerprints.

## Out of scope for now

Rotation of the pinned root; cascading revocation; a PAKE for short human
codes; gossip forward secrecy (packets use static-static DH; WireGuard traffic
has forward secrecy already).
