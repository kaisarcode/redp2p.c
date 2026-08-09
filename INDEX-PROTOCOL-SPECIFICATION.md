# REDP2P Index Protocol Specification (v1)

## Introduction

The REDP2P Index is a stateless HTTP coordination service. It acts as a rendezvous point where publishers register their reachability metadata and consumers discover publishers and initiate NAT traversal.

The protocol is language-agnostic: any HTTP server that can accept JSON POST requests and keep records with a TTL can implement it. The reference implementation is the `redp2p idx <port>` command in C; deployments may use PHP, Python, Go, or any other language. This document is the behavioral contract an index must follow to interoperate with the REDP2P reference client.

**Key properties:**
- Transport: HTTP/1.0 or HTTP/1.1, one JSON POST request per connection
- One logical endpoint, dispatched by the `op` field; the request path is ignored
- No persistent connections; publisher lifetime = TTL from `last_seen`
- Proof-of-work only at registration; heartbeats authenticate with the deregistration key only
- Direct punch coordination via `punch_req` / `punch_poll` (no relay)
- The index does not carry application traffic and runs no UDP or tunnel logic

---

## Common Conventions

### Transport

- Requests use HTTP/1.0 or HTTP/1.1, method `POST`. Any other method is rejected with HTTP `405`.
- The request path is ignored by the server (the reference client sends `POST /redp2p/`; `POST /` also works).
- The request body is a JSON object. The server does not validate the `Content-Type` header, but clients should send `Content-Type: application/json`.
- Transfer-Encoding is not supported and is rejected with HTTP `501`.
- The server closes the connection after replying (`Connection: close`); each request uses a fresh connection.
- A connection that stays idle longer than the request timeout (5 seconds) is dropped without a reply.

### Request Limits

- Maximum request body: 4096 bytes. A `Content-Length` larger than 4095 is rejected with HTTP `413`.
- Maximum 32 header lines, each at most 256 bytes. Larger headers are rejected with HTTP `431`.
- Request timeout: 5 seconds.

### JSON Rules

- The request body must be a JSON object with a string `op` field.
- Duplicate field names are rejected with `bad_request`.
- Unknown fields are ignored (they are not rejected).
- Requests that parse as non-objects, have a missing `op`, or use an unknown `op` are rejected with `bad_request`.
- All string values are UTF-8. Identifiers, session tokens, and hex tokens are ASCII.

### Response Envelope

Every JSON response is an object with an `ok` boolean:

- Success: `{ "ok": true, ... }` with operation-specific fields.
- Error: `{ "ok": false, "error": "<code>" }`.

There is no `status`, `code`, or `message` field. Clients must dispatch on HTTP status and on the `error` code.

### HTTP-Level Errors

Requests that fail before JSON parsing (bad request line, wrong method, oversized headers or body, Transfer-Encoding) receive a plain-text body, not JSON. Relevant statuses: `400` (malformed request line), `405` (method not `POST`), `413` (body too large), `431` (headers too large), `501` (Transfer-Encoding). The JSON error bodies below apply only to well-formed HTTP requests with a parseable JSON body.

### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (1..63) | Publisher/consumer identifier, ASCII alphanumeric only |
| `self_id` | string (1..63) | Consumer identifier in `punch_req`, same rules as `id` |
| `target_id` | string (1..63) | Publisher identifier in `punch_req`, same rules as `id` |
| `session` | string (1..63) | Session identifier, ASCII alphanumeric only |
| `nonce` | hex string (16 chars) | 8-byte random challenge from server |
| `solution` | hex string (8 chars) | 4-byte client solution (decimal counter encoded as 8 lowercase hex digits) |
| `proof` | hex string (64 chars) | HMAC-SHA256(pass, nonce\|\|id\|\|solution), hex digest |
| `key` | hex string (16 chars) | 8-byte deregistration key minted by the server |
| `bits` | integer (0..32) | PoW difficulty, returned by `challenge` |
| `proto` | integer | 1 = TCP (KCP), 2 = UDP |
| `udp_port` | integer (1..65535) | Local UDP port for direct traffic |
| `candidates` | array | Up to 8 candidate objects; optional in `register`, `heartbeat`, and `punch_req` |
| `last_seen` | integer | Unix timestamp (seconds) of the last successful `register` or `heartbeat` |

Hex tokens accept lowercase or uppercase digits; the server echoes and compares hex text exactly.

### Candidate Object

Input and output candidates use the same shape:

```json
{
  "type": "host|lan|public|srflx",
  "addr": "x.x.x.x|xxxx:...",
  "port": 12345
}
```

- `type`: one of `host`, `lan`, `public`, `srflx`. Any other value is rejected.
- `addr`: literal IPv4 or IPv6 address (up to 47 characters), validated with `inet_pton`.
- `port`: UDP port in 1..65535.

There is no `priority` field on the wire. The server never reads a client-supplied priority: it assigns each candidate a local priority itself (lower is preferred). The server does not deduplicate candidates; duplicates are stored as received, up to the 8-entry bound.

`candidates` is optional. When it is omitted, or present with a value that is not an array, the request is accepted and the stored candidate set becomes empty (on `register` and `heartbeat` this replaces any previously stored set). A present-but-malformed array is rejected with `bad_request`.

---

## Shared Secret Model (Important)

The index may optionally require a shared secret for registration. This is **not a user account password**:

- The secret is **configured by the index operator** (global password, or per-identifier VIP reservations).
- The operator **distributes it out-of-band** to authorized publishers (e.g., in person, via a secure channel).
- The publisher **never sends the secret over the network**.
- The client computes `proof = HMAC-SHA256(secret, nonce_hex || id || solution_hex)` locally.
- The server verifies using its copy of the secret.
- This provides **registration authorization** and **DoS resistance** (via PoW), not user authentication.

There are **no user accounts**, no consumer authentication, no identity infrastructure. The index remains stateless and coordination-only.

---

## Proof of Work

- Algorithm: `proof = HMAC-SHA256(pass, nonce_hex || id || solution_hex)`, where the three inputs are the ASCII hex/text values concatenated in that order.
- `pass` is the per-identifier VIP password when the id has a VIP reservation, otherwise the global password; it is the empty string when no password is configured.
- The server recomputes the digest from the echoed request fields and requires:
    1. an exact match with the submitted `proof`, and
    2. at least `bits` leading zero bits in the digest.
- The `proof` is **always required** on `register`, regardless of `bits`. With `bits = 0` the digest must still be correct; the difficulty only gates the leading-zero count.
- `bits` is an integer in 0..32, default 0.
- The challenge is stateless: the server stores nothing between `challenge` and `register`. The `nonce` must simply be echoed; it is not checked against a stored value.

---

## Operations

### `challenge` - Request PoW challenge

**Request:**
```json
{ "op": "challenge", "id": "publisher1" }
```

**Response (HTTP 200):**
```json
{
  "ok": true,
  "nonce": "a1b2c3d4e5f67890",
  "bits": 16
}
```

The server stores nothing. The client solves `proof = HMAC-SHA256(secret, nonce_hex || id || solution_hex)` so that the digest has `bits` leading zero bits. The `secret` is the global shared secret or the per-identifier VIP secret; the client never sends it.

**Errors:** `bad_request`, `invalid_id`.

---

### `register` - Register or re-register publisher

**Request:**
```json
{
  "op": "register",
  "id": "publisher1",
  "nonce": "a1b2c3d4e5f67890",
  "solution": "00000001",
  "proof": "deadbeef...",
  "proto": 1,
  "udp_port": 40000,
  "candidates": [
    {"type": "host", "addr": "10.0.0.5", "port": 40000},
    {"type": "lan", "addr": "192.168.1.50", "port": 40000},
    {"type": "public", "addr": "203.0.113.10", "port": 40000}
  ]
}
```

The `pass` field is **never sent by the client**. The server uses its configured password: the global password or the per-identifier VIP password. The `solution` is the counter encoded as 8 lowercase hex digits (e.g. `00000001` for counter 1).

**Response (HTTP 200):**
```json
{
  "ok": true,
  "key": "a1b2c3d4e5f60708"
}
```

`key` is 16 hex characters (8 random bytes). It is **stable**: re-registration never rotates it, and the existing key is returned on re-registration.

**Error responses:**
- `bad_request` - malformed, oversized, or duplicate input; bad hex fields; bad `proto`/`udp_port`; malformed `candidates` array
- `invalid_id` - id not alphanumeric or longer than 63 chars
- `auth_failed` - proof mismatch or insufficient leading zero bits
- `table_full` - seats capacity exhausted (including inactive VIP reservations)

On success the server upserts the record with `last_seen = now`.

---

### `heartbeat` - Refresh publisher TTL and endpoints

**Request:**
```json
{
  "op": "heartbeat",
  "id": "publisher1",
  "key": "a1b2c3d4e5f60708",
  "proto": 1,
  "udp_port": 40000,
  "candidates": [...]
}
```

**Response (HTTP 200):**
```json
{ "ok": true }
```

**Error responses:**
- `not_found` - unknown or expired id
- `invalid_key` - key mismatch

No PoW. The server updates `last_seen`, `proto`, `udp_port`, and `candidates`. `candidates` is optional; when omitted it becomes empty. If the record expired, the client must `register` again.

---

### `lookup` - Get one publisher record

**Request:**
```json
{ "op": "lookup", "id": "publisher1" }
```

**Response (HTTP 200):**
```json
{
  "ok": true,
  "id": "publisher1",
  "proto": 1,
  "udp_port": 40000,
  "candidates": [...],
  "last_seen": 1700000000
}
```

**Error (HTTP 404):**
```json
{ "ok": false, "error": "not_found" }
```

Expired records are filtered without writing.

---

### `list` - List all active publisher IDs

**Request:**
```json
{ "op": "list" }
```

**Response (HTTP 200):**
```json
{ "ok": true, "ids": ["publisher1", "publisher2"] }
```

Returns only non-expired IDs, in no particular order.

---

### `deregister` - Remove publisher record

**Request:**
```json
{ "op": "deregister", "id": "publisher1", "key": "a1b2c3d4e5f60708" }
```

**Response (HTTP 200):**
```json
{ "ok": true }
```

**Error:**
- `invalid_key` - key mismatch, or unknown/expired id (both cases return `invalid_key`, not `not_found`)

The record is removed on success.

---

### `punch_req` - Consumer announces itself to publisher

**Request:**
```json
{
  "op": "punch_req",
  "self_id": "consumer1",
  "target_id": "publisher1",
  "session": "abc123",
  "candidates": [...]
}
```

**Response (HTTP 200):**
```json
{ "ok": true }
```

Stores one bounded pending call (queue capacity 32, TTL 30 seconds). The server does not require the target to be a registered publisher and applies no authentication here. The consumer typically sends this after a successful `lookup`.

**Errors:** `bad_request`, `invalid_id` (bad `self_id`/`target_id`/`session`), `busy` when the pending-call queue is full.

---

### `punch_poll` - Publisher retrieves pending calls

**Request:**
```json
{ "op": "punch_poll", "id": "publisher1" }
```

**Response (HTTP 200):**
```json
{
  "ok": true,
  "calls": [
    {
      "self_id": "consumer1",
      "session": "abc123",
      "candidates": [...]
    }
  ]
}
```

Returns and consumes all pending calls addressed to this id. Call objects contain `self_id`, `session`, and `candidates` only (no `target_id`). With no pending calls the response is `{ "ok": true, "calls": [] }`. The reference publisher polls at about 500 ms cadence.

---

## Error Codes

| Code | Meaning | HTTP Status |
|------|---------|-------------|
| `bad_request` | Malformed JSON, missing or wrong-typed fields, duplicate fields, bad hex/token limits, malformed `candidates`, unknown `op` | 400 |
| `invalid_id` | Identifier rejected (not alphanumeric, too long) | 400 |
| `auth_failed` | Proof-of-work mismatch or insufficient bits | 403 |
| `invalid_key` | Deregistration key mismatch (heartbeat); also unknown id on deregister | 403 |
| `not_found` | Unknown or expired id (lookup, heartbeat) | 404 |
| `busy` | Pending punch-call queue full | 503 |
| `table_full` | Seats capacity exhausted | 503 |
| `internal` | Server failure | 500 |

All JSON errors: `{ "ok": false, "error": "<code>" }`.

---

## Server Behavior

### Record Schema

```
PublisherRecord {
  id: string (1..63, alnum)
  key: hex string (16 chars, 8 random bytes)
  proto: 1|2
  udp_port: uint16
  candidates: Candidate[8]
  last_seen: unix_timestamp
}
```

### TTL

- Default TTL: 120 seconds, configurable through `REDP2P_ETIMEOUT_SEC` (range 1..86400).
- A record is expired when `now - last_seen > TTL`.
- Expired records are filtered from `lookup` and `list` and physically removed from the store on `register`, `heartbeat`, `deregister`, and `punch_req`, and periodically in the idle loop (default 60 s, `REDP2P_PRUNE_INTERVAL_S`).
- The protocol does not expose a prune endpoint; physical removal is an implementation detail of each deployment.

### Seats / Capacity

- Optional total publisher capacity configured through `--seats` or `REDP2P_SEATS`.
- Each VIP reservation (configured via `REDP2P_VIP` as `<id> <pass> ...`) occupies one seat even while inactive.
- Non-VIP publishers share the remaining seats.
- `table_full` is returned when no seat is available. Zero seats accepts no publishers.
- Without configured seats there is no application-level publisher limit.

### Proof of Work

- See the "Proof of Work" section above.
- The server recomputes the digest from the echoed request fields; no challenge state is stored.

### Pending Punch Calls

- Queue capacity: 32 entries, shared across all publishers.
- TTL: 30 seconds from creation.
- `punch_poll` takes all entries addressed to one id and removes them.
- When the queue is full, `punch_req` returns `busy` (HTTP 503).

### Punch Coordination

1. Consumer `lookup` → gets publisher candidates.
2. Consumer `punch_req` with its own candidates + session id.
3. Publisher `punch_poll` retrieves the pending call.
4. Both peers run direct UDP probes against each other's candidates.
5. On success, they establish KCP (TCP mode) or a UDP stream.

None of this traffic touches the index.

---

## Implementation Notes

- **No background daemons required**: pruning runs in the request path and the idle loop.
- **Storage**: any in-memory or TTL-capable K/V store (the reference index is fully in-memory).
- **No UDP/KCP/socket logic** in the index.
- **Key stability**: the registration key is minted once and never rotated.
- **Heartbeat auth**: the deregistration key only (possession proves ownership).
- **Candidate validation**: strict `type`/`addr`/`port` parsing; priority is server-computed; no deduplication.
- **Bounds**: all fields bounded; oversized, truncated, duplicate, or wrong-typed input is rejected with `bad_request`.
- **One request per connection**: no session or keep-alive support.

---

## Example Flow

```bash
# 1. Get challenge
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"challenge","id":"alice"}' http://index:8080/
# -> {"ok":true,"nonce":"...","bits":16}

# 2. Solve PoW locally, register (solution = 8 hex digits)
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"register","id":"alice","nonce":"...","solution":"00000001","proof":"...","proto":1,"udp_port":40000,"candidates":[{"type":"public","addr":"203.0.113.10","port":40000}]}' \
  http://index:8080/
# -> {"ok":true,"key":"<16 hex chars>"}  (store locally for heartbeat/deregister)

# 3. Heartbeat every 15s (key is 16 hex chars)
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"heartbeat","id":"alice","key":"<key>","proto":1,"udp_port":40000,"candidates":[...]}' \
  http://index:8080/
# -> {"ok":true}

# 4. Consumer looks up publisher
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"lookup","id":"alice"}' http://index:8080/

# 5. Consumer requests punch
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"punch_req","self_id":"bob","target_id":"alice","session":"s1","candidates":[...]}' \
  http://index:8080/

# 6. Publisher polls (500ms)
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"punch_poll","id":"alice"}' http://index:8080/
# -> {"ok":true,"calls":[{"self_id":"bob","session":"s1","candidates":[...]}]}

# 7. Both punch directly via UDP, establish KCP/TCP or UDP tunnel
```

---

## Versioning

This is protocol v1. Future versions may add optional fields but must not change the semantics of existing operations. Clients should ignore unknown response fields.
