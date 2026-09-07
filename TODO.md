# wesher adoption TODO

Working list for evaluating and adopting wesher. Ordered by priority; we work
through it top to bottom, one item at a time, and check items off as we go.
Items marked **DECISION** need a joint call before work starts.

Baseline (2026-09-07, upstream `main` @ 8887b51, last commit 2024-11-11):

| Metric | Value |
|---|---|
| Total statement coverage | 17.4% |
| `cluster` / `common` / `etchosts` / `wg` / `main` | 10.3% / 66.7% / 28.6% / 30.0% / 0.0% |
| `go.mod` Go directive | 1.18 (local toolchain is 1.27) |
| CI Go matrix | 1.18.x, 1.19.x (both EOL) |
| `go build`, `go vet`, `go test -race` | all pass |
| Direct deps with newer versions | 8 of 9 (see phase 2) |

## Phase 0: groundwork

- [x] **DECISION**: fork strategy. Keep module path `github.com/costela/wesher`
      until phase 3 so fixes stay easy to upstream; revisit then.
- [x] Add `make coverage` and `make test` targets.
- [x] Add `make vulncheck` and `make lint` (pinned via `go run pkg@version`) and a
      non-blocking CI job. Lint is non-blocking until its 7 findings are fixed:
      3 errcheck (phase 3) and 4 govet inline warnings that vanish with the Go
      directive bump (phase 2). govulncheck: 0 called vulnerabilities, 36 in
      required modules that are not reached (phase 2 motivation).
- [x] Baseline numbers recorded in the table above.

## Phase 1: fill out the test suite

Target: every function that does not require `NET_ADMIN` reaches near 100%.
Functions that touch netlink/wgctrl get covered by root-gated tests or e2e.

Pure logic, no privileges needed (do first, cheap wins):

- [ ] `key.UnmarshalText` (key.go): valid key, bad base64, wrong length.
- [ ] `AgentCmd.Validate` (agent.go): key length check, overlay mask not a
      multiple of 8, bind-addr + bind-iface conflict, bind-iface resolution
      (use `lo`), autodetect fallback to `0.0.0.0`.
- [ ] `computeClusterKey` (cluster/cluster.go): provided key wins, state key
      used when none provided, random key generated and stored when both empty.
- [ ] `loadState` (cluster/state.go): missing file, fallback to deprecated
      `state.json` path, malformed JSON leaves state untouched, unreadable file
      warns. Existing test writes to `/tmp` directly; move to `t.TempDir()`.
- [ ] `state.save`: unwritable directory error path.
- [ ] `delegateNode` (cluster/delegate.go): `NodeMeta` success and over-limit
      error, no-op methods return nil.
- [ ] `common.Node`: `String`, `EncodeMeta` over-limit error, `DecodeMeta` with
      garbage input.
- [ ] `etchosts.WriteEntries` end to end against a temp file: add, update,
      remove entries, preserve unmanaged lines, preserve file mode, missing
      hosts file error, `movePreservePerms` copy fallback (cross-device rename
      failure is hard to trigger; at least cover the happy path and the nil
      `Logger` case, which currently panics; see phase 3).
- [ ] `wg.nodesToPeerConfigs` and `wg.addrToIPNet`: IPv4 and IPv6 nodes, bad
      public key error.
- [ ] `wg.State.assignOverlayAddr`: already well covered; add a `/32` prefix
      and a mask-not-multiple-of-8 case to pin behaviour.

Needs a real memberlist or network privileges:

- [ ] `cluster.New` / `Join` / `Leave` / `Update` / `Members`: two in-process
      memberlists on loopback with distinct ports. Covers the event loop and
      state persistence on membership change.
- [ ] **DECISION**: how to cover `wg.New`, `SetUpInterface`, `DownInterface`
      (wireguard.go). Options: (a) introduce small interfaces over netlink and
      wgctrl and mock them, (b) root-gated tests that run in a network
      namespace and skip without `CAP_NET_ADMIN`, (c) rely on the docker e2e
      suite only. Suggest (b) plus keeping (c); (a) adds indirection to 180
      lines of code for little gain.
- [ ] Make the e2e suite runnable locally: it depends on the external image
      `docker.io/costela/wesher-test`; build it from `tests/Dockerfile` instead
      and bump that Dockerfile off `golang:1.18`.
- [ ] Add an e2e case for a node leaving (verifies peer removal and hosts
      cleanup), which no current e2e test exercises.

## Phase 2: update dependencies with minimal code change

- [ ] Bump `go.mod` Go directive (suggest 1.24 or 1.25: recent, but not the
      bleeding edge our CI runners may lack). Replace deprecated `io/ioutil`
      calls (cluster/state.go, etchosts/etchosts.go) with `os` equivalents.
- [ ] `golang.org/x/crypto` 0.21 -> latest and `golang.org/x/net` 0.23 -> latest
      (indirect, but both old enough to carry published CVEs; do these first
      and run `govulncheck`).
- [ ] `github.com/hashicorp/memberlist` 0.5.1 -> 0.6.0. Read the changelog:
      this is the one most likely to change behaviour (gossip, encryption).
- [ ] `golang.zx2c4.com/wireguard/wgctrl` 2022-05 -> 2024-12 (pulls newer
      `mdlayher/netlink`, `genetlink`, `socket`).
- [ ] `github.com/vishvananda/netlink` 1.3.0 -> 1.3.1, then check whether the
      upstream `Wireguard` link type now exists so `wg/netlink.go` shim can go.
- [ ] `github.com/alecthomas/kong` 1.4.0 -> 1.16.1. Check `default:"withargs"`
      and `BeforeApply`/`AfterApply` hook semantics still match.
- [ ] `logrus` 1.9.3 -> 1.10.2, `testify` 1.9.0 -> 1.12.1, `go-isatty`,
      `backoff/v4` (already latest v4; note v5 exists, skip for now).
- [ ] `go mod tidy`, re-run unit tests, race tests, and e2e. Re-measure
      coverage to confirm nothing regressed.
- [ ] CI: bump `actions/checkout`, `setup-go`, `upload-artifact` to current
      majors; Go matrix to two supported versions; pin
      `softprops/action-gh-release` to a current release. Add `govulncheck` and
      lint steps.

## Phase 3: review and update the codebase

Correctness issues found during the initial read (verify each, then fix):

- [ ] `etchosts.movePreservePerms` dereferences `eh.Logger` without a nil check
      in the rename-fallback path, unlike the rest of the package (panic when
      `Logger` is unset and rename fails).
- [ ] `etchosts.writeEntries` deletes from the caller's map as a side effect.
      Copy it first.
- [ ] `AgentCmd.Run` calls `logrus.Fatal` and `os.Exit(0)` instead of returning
      errors, so deferred cleanup never runs and the function is untestable.
      Return errors and let `main` exit.
- [ ] `Cluster.Update` installs the memberlist delegates after
      `memberlist.Create`; memberlist reads `Config.Delegate` during `Create`
      and on every gossip cycle, so this is a data race and the local node's
      metadata is only pushed by the `UpdateNode` call. Restructure so the
      node metadata is known before `Create`.
- [ ] `Cluster.Name` dereferences `localNode`, nil until `Update` is called.
- [ ] `Cluster.Members` starts a goroutine with no shutdown path and an
      unbuffered result channel; the 100-slot events buffer is a documented
      workaround for a memberlist deadlock. Give the loop a context.
- [ ] `SetUpInterface` adds a route per peer but never removes routes for
      peers that left; stale `/32` routes accumulate until the interface goes
      down. `ReplacePeers: true` already handles the wireguard side.
- [ ] `--bind-iface` picks `addrs[0]` blindly, which may be IPv6 or link-local.
      Prefer a global unicast IPv4, or make family selectable.
- [ ] `computeClusterKey` prints the generated key only when stdout is a TTY,
      so a systemd-started first node never reveals its key (upstream TODO
      suggests a `showkey` subcommand).
- [ ] `common.Node.DecodeMeta` trusts peer metadata blindly (upstream TODO).
      At minimum validate that `OverlayAddr` is inside the configured overlay
      net and `PubKey` parses, and log-and-skip otherwise.
- [ ] Join retry uses `backoff.NewExponentialBackOff()` defaults, which give
      up after 15 minutes. Decide whether that is intended.
- [ ] `LogLevelFlag.AfterApply` calls `Fatal` instead of returning the error.

Hygiene:

- [ ] Replace `nolint: errcheck` sites with explicit logging where the error is
      useful (state save failures are worth a warning).
- [ ] Wire up `golangci-lint` with a modest config and fix what it reports.
- [ ] Update README: configuration table, CI badge, and the "future version"
      promises to reflect what we actually plan.
- [ ] **DECISION**: module path rename and README ownership (deferred from
      phase 0).

## Phase 4: features

Candidates, roughly by value-to-effort. Each is a **DECISION** to discuss
before starting; none are committed yet.

- [ ] Configurable MTU (`--mtu`, default 1420). Upstream TODO; trivial.
- [ ] `showkey` subcommand to print the persisted cluster key.
- [ ] Persistent keepalive option for peers behind NAT
      (`--persistent-keepalive`).
- [ ] Remove stale routes and hosts entries when a peer leaves (overlaps with
      the phase 3 route item; may fall out of that fix).
- [ ] Extra `AllowedIPs` per node so a node can route a subnet into the mesh
      (advertised via node metadata).
- [ ] Static / seed nodes to mitigate split-brain (upstream roadmap item):
      periodically re-join configured addresses.
- [ ] Overlay IP collision detection: warn or refuse when two members hash to
      the same address (upstream roadmap item).
- [ ] Config file support (kong supports YAML/JSON loaders) alongside flags
      and env.
- [ ] `status` subcommand or health endpoint listing peers, handshake age, and
      overlay addresses.
- [ ] systemd `sd_notify` readiness and a `Type=notify` unit file.
- [ ] Cluster key rotation (upstream roadmap item; largest effort, needs a
      protocol design).
- [ ] IPv6 underlay support and verification (memberlist and endpoint
      handling are IPv4-assumed in places).
