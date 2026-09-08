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
- [x] `AgentCmd.Validate` (agent.go): overlay mask not a
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
- [x] `wg.overlayAddr`: `/32` and non-byte-aligned mask cases.

## Phase 2: update dependencies with minimal code change

Done 2026-09-07, one commit per bump. Only code change: `io/ioutil` -> `os`
and dropping the `wg/netlink.go` shim.

- [x] Go directive 1.18 -> 1.26 (latest x/crypto requires 1.26). `io/ioutil`
      replaced with `os` equivalents.
- [x] `golang.org/x/crypto`, `x/net`, `x/sys`, `x/sync` -> latest. govulncheck:
      36 -> 1 unreached module vulnerabilities; the remaining one is the
      unmaintained `x/crypto/openpgp` package, not imported here, no fix.
- [x] `hashicorp/memberlist` 0.5.1 -> 0.6.0. Reviewed the source diff: atomics,
      keyring locking fix, push-pull size cap, lowercased errors. No API or
      wire change.
- [x] `wgctrl` 2022-05 -> 2024-12.
- [x] `vishvananda/netlink` 1.3.0 -> 1.3.1; `netlink.Wireguard` now exists, so
      `wg/netlink.go` is gone.
- [x] `kong` 1.4.0 -> 1.16.1. Verified `--version`, `--help`, `Validate` and
      `AfterApply` ordering behave identically by running both binaries.
- [x] `logrus`, `go-isatty`, `testify`, and all indirect deps of built
      packages (`go get -u ./...`). `backoff/v4` already latest; v5 skipped.
- [x] `go mod tidy`; unit and race tests pass; coverage unchanged at 41.1%.
      e2e not run here: it needs the test image fix, which is a phase 3 item.
- [x] CI: Go matrix 1.26.x/1.27.x; checkout v7, setup-go v7, upload-artifact
      v7, download-artifact v8, action-gh-release v3.

## Phase 3: tests that require root or a live cluster

Covers what phase 1 could not: memberlist integration and the netlink/wgctrl
code. Root-gated tests skip without `CAP_NET_ADMIN`; the docker e2e suite stays
as the end-to-end check.

- [x] `cluster.New` / `Join` / `Leave` / `Update` / `Members`: two in-process
      memberlists on loopback. Exposed two real data races on `state` (fixed
      in their own commit, see phase 5 list). Cluster coverage 36% -> 92%.
- [x] `wg.New`, `SetUpInterface`, `DownInterface`: netns-gated tests, skipped
      without `CAP_NET_ADMIN`. `make test-privileged` runs the suite under
      `unshare -r`, which is enough. wg coverage 39% -> 85% privileged;
      remaining lines are netlink error branches (phase 4 seams).
- [x] e2e suite builds its image from `tests/Dockerfile` (golang:1.27) and
      runs locally. All 5 original scenarios pass on the phase 2 dependencies.
- [x] e2e `test_node_leave`: clean SIGTERM leave removes the peer's hosts
      entry. `tests/e2e.sh <name>...` runs selected cases.
- [x] e2e runs under rootless podman (`docker` aliased to `podman`):
      containers get `--cap-add=NET_RAW`, `--device /dev/net/tun` and
      `--security-opt label=disable`; all no-ops under docker. Known gap:
      `test_multiple_clusters_restart` fails under podman because the
      restarted container gets a new IP and the non-PID-1 wesher instance is
      killed without leaving, so memberlist sees a name conflict. Passes
      under docker, where the IP is reused.

Privileged coverage after phase 3: 67.8% total (cluster 92%, common 92%,
etchosts 66%, wg 85%, main 25%).

## Phase 4: adapt the code for automated testing

Done 2026-09-07. Seams are unexported and injected; public API unchanged.

- [x] **DECISION** (taken as proposed, open to revision): `wg.State` holds the
      subsets of `*netlink.Handle` and `*wgctrl.Client` it uses as two small
      interfaces; `New` wires the real ones, `newState` takes fakes.
- [x] `AgentCmd.Run` returns errors; `loop` and `apply` take
      `clusterController`/`wgController`/`hostsWriter` interfaces and are
      driven by fakes. Termination returns nil instead of `os.Exit(0)`.
- [x] `cluster`: `Leave` closes a `done` channel that stops the `Members`
      goroutine and closes its channel; `Leave` is idempotent (memberlist
      panics on a second leave). `newMemberlistConfig` package var lets tests
      use fast timers; added a failed-node detection test.
- [x] `etchosts`: unexported `rename` hook; copy fallback now tested. Logging
      goes through a nil-safe helper (the fallback path dereferenced a nil
      `Logger`).
- [x] Netns-gated wg tests kept as integration checks; fakes cover the error
      branches unprivileged.
- [x] Coverage: 41.1% -> 79.7% privileged (main 50%, cluster 92%, common 92%,
      etchosts 80%, wg 95%). Unprivileged: wg 91%, rest identical.
      All 6 e2e scenarios pass.

Remaining uncovered lines: `AgentCmd.Run` wiring (needs a real cluster and
interface), `main`, kong hooks, and OS error branches in `Validate`,
`state.save`, `computeClusterKey`.

## Phase 5: review and update the codebase

Correctness issues found during the initial read (verify each, then fix):

- [x] `etchosts.movePreservePerms` nil `Logger` dereference in the rename
      fallback. Fixed in phase 4.
- [x] `etchosts.writeEntries` deletes from the caller's map as a side effect.
      Tracks written IPs in a local set instead; output now goes through a
      `bufio.Writer` so write errors are checked once on `Flush`.
- [x] `AgentCmd.Run` `Fatal`/`os.Exit` replaced with returned errors. Fixed in
      phase 4.
- [x] `Cluster.Update` installs the memberlist delegates after
      `memberlist.Create`; memberlist reads `Config.Delegate` during `Create`
      and on every gossip cycle, so this is a data race and the local node's
      metadata is only pushed by the `UpdateNode` call. Removed `Update`:
      the agent resolves the hostname, `wg.New` names the node, and
      `cluster.New` takes it and installs the delegates before `Create`.
      Local metadata never changes at runtime, so nothing needed re-announcing.
- [x] `Cluster.Name` dereferences `localNode`, nil until `Update` is called.
      Removed: it had no callers, and in production returned "" because
      `wg.New` never sets the node name.
- [x] `Cluster.Members` goroutine now stops on `Leave` (phase 4); data races
      with `Leave` on `state` and on the node slice fixed in phase 3. `Leave`
      now also waits for the goroutine to exit (it could still be mid-save).
- [x] The 100-slot events buffer remains a workaround for a memberlist
      deadlock (hashicorp/memberlist#23); check whether 0.6.0 still needs it.
      It did: memberlist 0.6.0 still calls the event delegate under its node
      write-lock, and `Members` took that lock via `ml.Members()`. Events now go
      to a forwarder that only logs and sets a one-slot "changed" signal;
      `Members` rebuilds the list from that signal. Buffer reduced to 16, only
      to absorb events in flight during shutdown.
- [x] `SetUpInterface` adds a route per peer but never removes routes for
      peers that left; stale `/32` routes accumulate until the interface goes
      down. `ReplacePeers: true` already handles the wireguard side. Now lists
      the main-table routes on the link and deletes host routes inside the
      overlay net that no current peer owns.
- [x] `--bind-iface` picks `addrs[0]` blindly, which may be IPv6 or link-local.
      Now prefers a global unicast IPv4, falls back to any IPv4 (loopback),
      and errors when the interface has none. The autodetect path uses the
      same helper with a public-address predicate, replacing
      `go-sockaddr.GetPublicIP` (direct dependency dropped; memberlist still
      pulls it in).
- [x] `computeClusterKey` prints the generated key only when stdout is a TTY,
      so a systemd-started first node never reveals its key (upstream TODO
      suggests a `showkey` subcommand). Minimal fix: off a terminal it now
      logs a warning naming the state file to grep. `showkey` stays a phase 6
      candidate; `computeClusterKey` is pure and reports whether it generated.
- [x] `common.Node.DecodeMeta` trusts peer metadata blindly (upstream TODO).
      `AgentCmd.validateNode` now rejects (log-and-skip) nodes with an empty
      name, an overlay address outside `--overlay-net`, or an unparseable
      public key. Validation lives in the agent, which knows the overlay net.
- [x] Join retry uses backoff defaults, which give up after 15 minutes. Decided
      2026-09-07: retry indefinitely (interval capped at 60s), SIGTERM/SIGINT
      is the way out. A node that gives up needs a manual restart, which is
      worse than a periodic error log.
- [x] `LogLevelFlag.AfterApply` calls `Fatal` instead of returning the error.
      Fixed as part of the logrus -> `log/slog` migration (2026-09-07); the
      level is parsed by `slog.Level.UnmarshalText`.

Hygiene:

- [x] Drop the pre-0.3 `/var/lib/wesher/state.json` read fallback
      (`deprecatedStatePath`); state has been keyed by interface name since
      2020-05. README pointed at the old path; now names the per-interface file.
- [x] logrus -> `log/slog` (logrus is in maintenance mode). memberlist logs
      through `slog.NewLogLogger` at debug; `etchosts.Logger` is a
      `*slog.Logger`; messages are structured key/value pairs.
- [x] Simplification pass (2026-09-07, one commit each): kong's built-in
      `VersionFlag`; `key` is a byte slice validated on parse;
      `wg.overlayAddr` is a pure function; `DownInterface` asks netlink only;
      `path` -> `path/filepath`; `Validate` bind selection as a switch;
      `loadState` returns the state.
- [x] Remove the hidden `--ip-as-name` flag (PoC-era local-testing aid that
      set the memberlist node name to the bind IP and broke `/etc/hosts`
      entries). The integration tests now name nodes via the
      `newMemberlistConfig` hook instead.
- [x] Replace `nolint: errcheck` sites with explicit logging where the error is
      useful (state save failures are worth a warning). Done: state save,
      memberlist leave/shutdown and the post-failure interface down all log a
      warning; test deferred closes use `_ =`.
- [x] Wire up `golangci-lint` with a modest config and fix what it reports.
      `.golangci.yml`: standard set plus misspell, unconvert, unparam,
      gocritic, govet shadow, gofmt. Nine findings fixed; the CI lint job is
      now blocking.
- [x] Update README: configuration table, CI badge, and the "future version"
      promises to reflect what we actually plan. Table and promises done; the
      badge and the release job's repository check follow the module-path
      DECISION below.
- [ ] **DECISION**: module path rename and README ownership (deferred from
      phase 0). README half done 2026-09-07: links, badge, release and clone
      URLs point at github.com/jdpanderson/wesher; the `go get` install path
      is gone until the module path matches. Still open: `go.mod` module path,
      the `import` comment in main.go, and the release job's
      `github.repository == 'costela/wesher'` gate in CI.

## Phase 6: features

Candidates, roughly by value-to-effort. Each is a **DECISION** to discuss
before starting; none are committed yet.

- [x] Configurable MTU (`--mtu`, default 1420). `wg.New` now takes a `wg.Config`.
- [x] `showkey` subcommand to print the persisted cluster key
      (`wesher showkey [--interface DEV]`, via `cluster.LoadKey`).
- [x] Persistent keepalive option for peers behind NAT
      (`--persistent-keepalive`, a duration in whole seconds, 0 = off).
- [x] Remove stale routes and hosts entries when a peer leaves (overlaps with
      the phase 5 route item; may fall out of that fix). It did: hosts entries
      were already rewritten on every update, routes are now pruned too.
- [ ] Extra `AllowedIPs` per node so a node can route a subnet into the mesh
      (advertised via node metadata).
- [ ] Static / seed nodes to mitigate split-brain (upstream roadmap item):
      periodically re-join configured addresses.
- [ ] Overlay IP collision detection: warn or refuse when two members hash to
      the same address (upstream roadmap item).
- [ ] Config file support (kong supports YAML/JSON loaders) alongside flags
      and env.
- [x] `status` subcommand listing peers, handshake age, and overlay addresses
      (`wesher status [--interface DEV] [--json]`; names come from the
      persisted cluster state). A health endpoint remains a separate candidate.
- [ ] systemd `sd_notify` readiness and a `Type=notify` unit file.
- [ ] Cluster key rotation (upstream roadmap item; largest effort, needs a
      protocol design).
- [ ] IPv6 underlay support and verification (memberlist and endpoint
      handling are IPv4-assumed in places).
