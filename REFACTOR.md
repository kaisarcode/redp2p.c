# REFACTOR.md

Working plan and task tracker for making the REDP2P index an agnostic, stateless, HTTP-based coordination service.

This document is a behavioral contract for the refactor. It describes the target architecture, the HTTP contract the index must expose, the concrete changes to the C implementation, and the task tracker.

## Goal

The index must become replicable in any language that can serve HTTP, so that an index can be created and hosted anywhere with an accessible address. The index is only a rendezvous:

* it coordinates peers through request-driven HTTP operations
* it keeps no open channel with publishers
* it maintains one `last_seen` timestamp per registered publisher
* it never carries application traffic

The C index inside `redp2p.c` is the reference implementation of the HTTP contract. Any other language implementation (PHP, Python, Go, ...) replicates the same contract and lives in a separate project. No PHP or other-language implementation is part of this refactor.

The transport is transparent: a client only talks HTTP to the index URL and does not care whether the endpoint is served by the C index, Apache, nginx, or any other server.

## Target model

* The index is an HTTP endpoint on a server.
* The C project keeps its own HTTP server on a configurable port, exactly like today's `redp2p idx <port>`.
* A PHP deployment may place the same endpoint behind Apache or any other web server.
* Every operation is one HTTP request; the index holds no persistent connection state.
* Publisher records live or die by TTL from `last_seen`, not by connection lifetime.
* The index is a presenter. It stores registrations and short-lived pending calls, and each peer takes what it needs by request. Once two peers have each other's candidates they communicate directly and the index steps aside.

## What the C index must stop doing

These C-isms must not survive the refactor:

* **Connection-tied peer lifetime.** Today a peer is removed when its TCP control connection closes (`redp2p_index_disconnect`, `src/libredp2p.c:4543`). Peer lifetime must be TTL from `last_seen` only.
* **Connection-keyed PoW challenge table.** Today the server stores issued challenges in `pow_challenges[]` keyed by the peer `(IP, port)` (`redp2p_find_pow_challenge`, `src/libredp2p.c:2938`). Verification must be stateless: recompute from the echoed fields.
* **Per-request inline eviction.** Today cleanup runs inline in the event loop (`redp2p_index_cleanup_stale_peers/challenges/punches`, `src/libredp2p.c:4573`). Reads must filter by TTL without writing; physical prune is an explicit `prune` operation for cron (or an internal timer in the C index).
* **Unauthenticated heartbeats.** Today the heartbeat re-sends `REGISTER` on the open connection and the connection itself is the authentication. Without a channel, heartbeats authenticate with the deregistration key only. PoW is paid at registration events, never on the 15 s heartbeat.
* **Key rotation on re-registration.** Today `redp2p_add_peer` regenerates the key when an existing id re-registers (`src/libredp2p.c:2866`). The key must be stable from registration onward so re-registration and heartbeats never orphan the local key file.
* **Punch relay over the held control channel.** Today the index relays `PUNCH_REQ2/CALL2/ACK2/OK2` over the publisher's held TCP connection and keeps `pending_punch` entries. This is replaced by request-driven pending calls: the consumer POSTs `punch_req` (a bounded record with a short TTL), the publisher retrieves it with `punch_poll`, and the two then exchange `PUNCH_PING/PONG` directly. No held channel; the index only presents them.
* **Connection machinery.** The `select()` control event loop, `HELLO` handshake, partial-line state machine, and `connection->registered` flag have no place in the request-driven model. The C index becomes a per-request HTTP server: accept, read one bounded request, respond, close.

## HTTP contract v1

Single endpoint. All operations are `POST` with a JSON body containing an `op` field. No URL rewriting, no routes: any language on any HTTP server can dispatch on `op` from one script.

Response is JSON. HTTP status is used for transport semantics; success and failure are also expressed in the body.

### Operations

| `op` | Request fields | Response |
| :--- | :--- | :--- |
| `challenge` | `id`, `pass?` | `nonce`, `bits` |
| `register` | `id`, `nonce`, `solution`, `proof`, `pass?`, `proto`, `udp_port`, `candidates[]` | `key` or error |
| `heartbeat` | `id`, `key`, `proto`, `udp_port`, `candidates[]` | `ok` or error |
| `lookup` | `id` | `id`, `proto`, `udp_port`, `candidates[]`, `last_seen` or `not_found` |
| `list` | - | `ids[]` |
| `deregister` | `id`, `key` | `ok` or `invalid_key` |
| `prune` | - | `pruned` (count) |
| `punch_req` | `self_id`, `target_id`, `session`, `candidates[]` | `ok` or error |
| `punch_poll` | `id` | `calls[]` (`self_id`, `session`, `candidates[]`) |

### Semantics

* **challenge** issues a random 8-byte nonce and a difficulty `bits`. The server stores nothing.
* **register** validates the id, validates the password token when configured, verifies the proof of work, enforces seats/VIP capacity, and upserts the publisher record. It never rotates an existing key. Returns the current key. A re-registration after expiry requires the same pass + PoW: the index no longer holds the key for the expired record.
* **heartbeat** verifies only the deregistration key, then refreshes `last_seen` and the endpoint fields (`proto`, `udp_port`, `candidates[]`). No proof of work: PoW is paid at registration events only. A heartbeat for an unknown or expired id fails and the publisher must `register` again.
* **lookup** and **list** filter out records whose `last_seen` is older than the TTL without writing.
* **prune** physically removes expired records. It is meant for cron or an internal timer. The C index also evicts expired records before rejecting a new registration with `table_full`.
* **deregister** requires the key stored at registration.
* **punch_req** stores a bounded pending call (`self_id`, `target_id`, `session`, `candidates[]`) with a short TTL. The consumer sends it after `lookup`. Unauthenticated, like today's `PUNCH_REQ2`.
* **punch_poll** returns and consumes the pending calls addressed to the requesting publisher id. The publisher polls while waiting (default cadence ~500 ms), then runs its normal `punch_select` / `open_session` / `PUNCH:server` flow toward the caller's candidates.

### Proof of work

* Client solves `HMAC-SHA256(pass, nonce_hex || id || solution_hex)` with `bits` leading zero bits.
* The server recomputes the same hash from the echoed fields and checks the leading zero bits.
* No server-side challenge state. This is the same math already used by `redp2p_hash_register_once`, `redp2p_solve_register_pow`, and `redp2p_verify_register_pow`.
* PoW applies only to `register`. `heartbeat` never carries nonce/solution/proof. If a record expired (TTL) or the index restarted, the publisher must `register` again (pass + PoW) before heartbeats resume.

### Errors

| Code | Meaning | Maps to |
| :--- | :--- | :--- |
| `ok` | success | `REDP2P_OK` |
| `bad_request` | malformed or oversized input | `REDP2P_EINVAL` |
| `invalid_id` | identifier rejected | `REDP2P_EINVAL` |
| `auth_failed` | password or proof of work rejected | `REDP2P_EAUTH` |
| `invalid_key` | deregistration key mismatch | `REDP2P_EAUTH` |
| `not_found` | unknown or expired id | `REDP2P_ENOENT` |
| `table_full` | capacity exhausted | `REDP2P_EFULL` |
| `busy` | index busy | `REDP2P_EPROTO` |
| `internal` | server failure | `REDP2P_ERROR` |

### Limits

* `id` <= `REDP2P_ID_MAX` (63)
* `candidates` bounded (<= 8), each candidate bounded and strictly parsed (`host`/`lan`/`public`/`srflx`)
* nonce, solution, proof, and key as fixed-width hex
* request body bounded; oversized or truncated requests are rejected cleanly
* malformed, duplicate, and partial input must fail clearly (protocol-change requirements from `AGENTS.md`)

## Changes to the C implementation

All changes stay inside the existing four-file layout (`src/libredp2p.c`, `src/libredp2p.h`, `src/redp2p.c`, `src/test.c`). No new source, header, or test files.

### Index server (`redp2p_serve_index`)

* Keep `redp2p_index_runtime_initialize` (bind/listen) and the same `idx <port>` CLI surface.
* Replace the control event loop with a per-request HTTP server: accept, read one bounded request, parse JSON, dispatch by `op`, write the JSON response, close.
* Publisher record in memory: `{id, key[33], proto, udp_port, candidates[8][...], last_seen}`.
* Remove: `HELLO` handshake, `connection->registered`, `pow_challenges[]` table, `pending_punch`, connection-tied peer removal.
* Preserve: id and password validation, seats/VIP capacity, `REDP2P_ETIMEOUT_SEC` TTL, `redp2p_stop` support.
* Reads filter expired records; `prune` and the table-full path evict physically.

### New internal primitives

* Minimal HTTP/1.1 client and server (bounded headers, `Content-Length` respected, `Connection: close`).
* Strict JSON parsing and writing via the vendored `parson` library under `lib/parson` (same `lib/` boundary as KCP and Monocypher).
* Both stay internal to `src/libredp2p.c`.

### Publisher

* Register via HTTP (`challenge` + `register`) and persist the deregistration key exactly as today.
* Heartbeat every `REDP2P_HEARTBEAT_S` (15 s) via HTTP with the key only, no PoW.
* On heartbeat failure (not registered, invalid key, expired) re-register with pass + PoW.
* Poll `punch_poll` (~500 ms cadence) while waiting; on a pending call, run the existing `redp2p_publisher_select_peer` / `punch_select` / `open_session` / `PUNCH:server` flow toward the caller's candidates.
* Continue replying `PUNCH_PONG` to unknown direct pings (`src/libredp2p.c:6840`).
* Deregister via HTTP with the key.

### Consumer

* `lookup` via HTTP returns the publisher record (proto, udp_port, candidates, last_seen).
* `punch_req` announces the consumer (its candidates + session) so the publisher can pick it up by polling and probe back.
* The consumer then runs `punch_select` against the publisher candidates; the direct `PUNCH_PING/PONG`, `PUNCH:server`, and the KCP-over-UDP stream are untouched.

### Index URL resolution

* New environment variable `REDP2P_INDEX_URL` is the canonical way to point clients at any index deployment (C, PHP behind Apache, etc.).
* Default derived from the existing `id@host[:port]` spec: `http://host[:port]/redp2p/`.
* Existing CLI syntax, flags, precedence, stdout/stderr, and exit behavior are preserved.

## Preserved compatibility

* Public API signatures (`redp2p_serve_index`, `redp2p_wait`, `redp2p_connect`, `redp2p_deregister`, `redp2p_list_publishers`, ...).
* CLI commands and flags (`idx`, `pub`, `con`, `del`, `--seats`, `--pow`, `--list`, `--sweep`, `--stun`).
* Local key files: scoped hashed filenames, mode `0600`, temporary-file replacement, rollback on failure.
* KCP/UDP data path, datagram preservation, sweep, optional STUN.

## Documented behavior changes

* **Key stability:** a re-registration no longer rotates the deregistration key. The key is minted once and remains valid across heartbeats and re-registrations.
* **Introduction latency:** the publisher learns about a caller through `punch_poll`, so its proactive probe is delayed by up to the poll cadence (~500 ms). The direct `PUNCH_PING/PONG` mechanics and bidirectional probing are otherwise unchanged.
* **Heartbeat authentication:** possession of the deregistration key (no PoW) replaces "owning the open connection". PoW is paid only at registration events.
* **Expiry is routine:** a publisher going quiet is an expired record, not a disconnection event. An expired record is never served by reads; `prune` or the `table_full` path removes it physically.

## Documentation to update

* `README.md`: document `REDP2P_INDEX_URL`, the HTTP endpoint model, and the transparent transport.
* `DESIGN.md`: replace the "TCP-only control service" architecture description with the HTTP stateless contract; document TTL/prune, request-driven punch introduction (`punch_req`/`punch_poll`), key stability, and heartbeats without PoW.
* `AGENTS.md`: update the core invariant "the index uses TCP as a control channel" to "the index exposes an HTTP control API"; keep all other invariants.

## Testing

* Migrate the index test harness in `src/test.c` from the raw control protocol (`test_control_connect`/`test_control_request`) to HTTP helpers against the local `idx` server.
* Cover: registration, registration rejection (id, password, weak proof of work), seats, VIP, lookup found/not found, list, deregister (wrong key fails, right key succeeds), heartbeat refresh and heartbeat without PoW, TTL expiry and prune, `punch_req`/`punch_poll` call delivery, malformed/oversized/truncated/duplicate input.
* Keep the tunnel tests (`wait`/`connect`, `tcp_stream`, `udp_tunnel`) running through the new direct-punch flow over loopback.
* Do not weaken existing tests.

## Validation

```bash
make
make test
kcs .
```

If Windows-affected platform code (sockets, select removal) is touched:

```bash
make x86_64/windows
make test wine
```

## Task tracker

> **Real state as of 2026-08-08:** Phases 1, 2, 3, 5, and 6 (core docs) are
> implemented and green (`make`, `make test` 29/29, `kcs .` clean). The index serves the
> HTTP contract; a real parser bug was fixed (the header loop started after the blank
> line, so `Content-Length` was never read and every body arrived empty). Publishers
> register, heartbeat, and poll `punch_poll` over HTTP; consumers `lookup`, send
> `punch_req`, and punch directly. Deregister and list operate over HTTP. The old
> control-channel client machinery, the `PUNCH_REQ2/CALL2/ACK2/OK2` tokens, and all
> `REDP2P_CTRTOK_*` tokens were removed; parse-level HTTP errors now return the uniform
> JSON error body. `src/test.c` was migrated to the HTTP contract (HTTP helpers, port-keyed
> HTTP readiness polling, JSON adversarial coverage for malformed, non-object,
> duplicate-field, overlong-header, truncated-body, and over-capacity candidate input).
> The duplicate-id test asserts the documented key-stability contract: a re-registration
> does not rotate the key, so the original registration's key still deregisters the
> record. Verified end-to-end on loopback: TCP tunnel, UDP tunnel, `idx --list`, and `del`
> all work over HTTP. Automatic prune runs every 60s in the index event loop. Remaining:
> Phase 4 (`REDP2P_INDEX_URL` + default URL resolution - not yet requested), and
> Phase 7 operator testing plus Windows/wine (pre-existing flaky test in `tcp_stream`).
> Phase 6 (README/DESIGN/AGENTS still describe the old contract; `AGENTS.md` still lists
> "the index uses TCP as a control channel"), and Phase 7 operator testing plus the
> Windows/wine run.

### Phase 1 - HTTP + JSON primitives

- [x] Minimal HTTP/1.1 server in `src/libredp2p.c` (request parser `redp2p_index_request_parse`, response writer `redp2p_http_write_response`, bounded headers/body/timeout)
- [x] Vendor `parson` under `lib/parson` and wire it into the build (CMakeLists, AGENTS.md)
- [x] Minimal HTTP/1.1 client in `src/libredp2p.c` (request build with `Content-Length`, bounded JSON response parse) - *blocked by Phase 3*
- [x] Adversarial tests for oversized/truncated/malformed HTTP input - *in Phase 5*

### Phase 2 - Index server over HTTP

- [x] Publisher record gains `proto`, `udp_port`, `candidates[]`
- [x] `redp2p_serve_index` dispatches on `op` over HTTP
- [x] `challenge` returns nonce + bits with no stored state
- [x] `register` verifies PoW by recomputation, enforces seats/VIP, upserts without key rotation
- [x] `heartbeat` verifies the key only (no PoW) and refreshes `last_seen`
- [x] `lookup` / `list` filter expired records without writing
- [x] `prune` physically removes expired records
- [x] `punch_req` stores a bounded pending call with a short TTL
- [x] `punch_poll` returns and consumes pending calls for a publisher id
- [x] `deregister` requires the stored key
- [x] Remove `HELLO` handshake, challenge table, `pending_punch`, connection-tied removal (server side)
- [x] Error codes map to existing `REDP2P_*` values - *client-side mapping in Phase 3*
- [x] Note: HTTP error body for malformed requests still sends the legacy `REDP2P_CTRTOK_ERROR:malformed` token as `text/plain`; replace with the JSON error body (Phase 3 cleanup)

### Phase 3 - Publisher and consumer over HTTP

- [x] Publisher registers via `challenge` + `register` over HTTP
- [x] Publisher heartbeats over HTTP with key only (no PoW); re-registers with PoW on failure
- [x] Publisher polls `punch_poll` (~500 ms) and runs `punch_select`/`open_session` on pending calls
- [x] Consumer `lookup` via HTTP, sends `punch_req`, and punches directly against publisher candidates
- [x] Remove `PUNCH_REQ2/CALL2/ACK2/OK2` from the control path
- [x] Deregister and list operate over HTTP
- [x] Remove dead legacy client machinery (`CTRTOK_*` tokens, `redp2p_control_connect`, `tcp_readline`, line parsers)

### Phase 4 - URL resolution and key stability

- [ ] `REDP2P_INDEX_URL` environment variable honored (not yet requested)
- [ ] Default URL derived from `id@host[:port]` (not yet requested)
- [x] Stable deregistration key across re-registration and heartbeats
- [x] Local key file storage preserved unchanged (scope, mode 0600, rollback)

### Phase 5 - Tests

- [x] Index harness migrated to HTTP helpers
- [x] Registration, rejection, seats, VIP, lookup, list, deregister, heartbeat, TTL/prune covered
- [x] Malformed/oversized/truncated/duplicate input covered
- [x] Tunnel tests pass through the direct-punch flow

### Phase 6 - Documentation

- [x] `README.md` documents vendor licenses (KCP, Monocypher, Parson)
- [x] `DESIGN.md` documents the stateless HTTP contract, TTL/prune, direct punch, key stability, NAT limitation
- [x] `AGENTS.md` core invariant updated from TCP control channel to HTTP control API
- [ ] `README.md` documents `REDP2P_INDEX_URL` and the HTTP endpoint model (future: Phase 4)

### Phase 7 - Validation

- [x] `make` passes
- [x] `make test` passes
- [x] `kcs .` passes
- [ ] Windows cross-compile and `make test wine` pass if platform code changed
- [ ] Operator testing completed
