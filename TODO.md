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
      until phase 5 so fixes stay easy to upstream; revisit then.
- [x] Add `make coverage` and `make test` targets.
- [x] Add `make vulncheck` and `make lint` (pinned via `go run pkg@version`) and a
      non-blocking CI job. Lint is non-blocking until its 7 findings are fixed:
      3 errcheck (phase 5) and 4 govet inline warnings that vanish with the Go
      directive bump (phase 2). govulncheck: 0 called vulnerabilities, 36 in
      required modules that are not reached (phase 2 motivation).
- [x] Baseline numbers recorded in the table above.

## Phase 1: pure-logic unit tests

Target: every function that does not require `NET_ADMIN` reaches near 100%.

Pure logic, no privileges needed (done 2026-09-07; total coverage 17.4% -> 41.1%):

- [x] `key.UnmarshalText` (key.go): valid key, bad base64, wrong length.
- [x] `AgentCmd.Validate` (agent.go): key length check, overlay mask not a
      multiple of 8, bind-addr + bind-iface conflict, bind-iface resolution
      (uses `lo`), autodetect. Remaining gaps are OS error branches.
- [x] `computeClusterKey` (cluster/cluster.go): provided key wins, state key
      used when none provided, random key generated and stored when both empty.
- [x] `loadState` (cluster/state.go): missing file, deprecated path fallback,
      malformed JSON, unreadable file. Tests use `t.TempDir()`;
      `deprecatedStatePath` became a var to allow overriding it.
- [x] `state.save`: unwritable directory error path.
- [x] `delegateNode` (cluster/delegate.go): `NodeMeta` success and over-limit,
      no-op methods.
- [x] `common.Node`: `String`, `EncodeMeta` over-limit, `DecodeMeta` garbage.
- [x] `etchosts.WriteEntries` end to end against a temp file: add, update,
      remove, preserve unmanaged lines, preserve mode, missing file, nil
      `Logger` happy path, no leftover temp files. The rename-fallback branch
      of `movePreservePerms` is still uncovered (needs a cross-device rename).
- [x] `wg.nodesToPeerConfigs` and `wg.addrToIPNet`: IPv4 and IPv6, bad key,
      empty list.
- [x] `wg.State.assignOverlayAddr`: `/32` and non-byte-aligned mask cases.

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

## Phase 3: tests that require root or a live cluster

Covers what phase 1 could not: memberlist integration and the netlink/wgctrl
code. Root-gated tests skip without `CAP_NET_ADMIN`; the docker e2e suite stays
as the end-to-end check.

- [ ] `cluster.New` / `Join` / `Leave` / `Update` / `Members`: two in-process
      memberlists on loopback with distinct ports. Covers the event loop and
      state persistence on membership change.
- [ ] `wg.New`, `SetUpInterface`, `DownInterface` (wireguard.go): root-gated
      tests in a private network namespace, skipped without `CAP_NET_ADMIN`.
      Decided 2026-09-07: root-gated here, testability seams in phase 4.
- [ ] Make the e2e suite runnable locally: it depends on the external image
      `docker.io/costela/wesher-test`; build it from `tests/Dockerfile` instead
      and bump that Dockerfile off `golang:1.18`.
- [ ] Add an e2e case for a node leaving (verifies peer removal and hosts
      cleanup), which no current e2e test exercises.

## Phase 4: adapt the code for automated testing

Restructure so the privileged and external paths can be exercised without
root, then adapt the phase 3 tests to use the seams.

- [ ] **DECISION**: shape of the seams. Suggest small interfaces for the
      netlink and wgctrl calls in `wg`, injected into `State`, with the real
      implementations as the default. Keep `wg/netlink.go`-style shims out.
- [ ] `AgentCmd.Run`: return errors instead of `Fatal`/`os.Exit` so the loop
      body can be driven from a test.
- [ ] `cluster`: allow injecting a memberlist config (bind to loopback, short
      timers) and give `Members` a shutdown path.
- [ ] `etchosts`: make the rename step overridable so the copy fallback is
      testable.
- [ ] Convert phase 3 tests to run unprivileged via the seams where that adds
      coverage; keep the root-gated versions as integration checks.
- [ ] Re-measure coverage; target near 100% for everything outside `main`.

## Phase 5: review and update the codebase

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

## Phase 6: features

Candidates, roughly by value-to-effort. Each is a **DECISION** to discuss
before starting; none are committed yet.

- [ ] Configurable MTU (`--mtu`, default 1420). Upstream TODO; trivial.
- [ ] `showkey` subcommand to print the persisted cluster key.
- [ ] Persistent keepalive option for peers behind NAT
      (`--persistent-keepalive`).
- [ ] Remove stale routes and hosts entries when a peer leaves (overlaps with
      the phase 5 route item; may fall out of that fix).
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
