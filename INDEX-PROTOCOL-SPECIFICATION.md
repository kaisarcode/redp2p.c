# REDP2P Index Protocol Specification (v1)

## Introduction

The REDP2P Index is a stateless HTTP coordination service. It acts as a rendezvous point where publishers register their reachability metadata and consumers discover publishers and initiate NAT traversal.

The protocol is language-agnostic: any HTTP server that can accept JSON POST requests and store records with TTL can implement it. The reference implementation is the `redp2p idx <port>` command in C, but deployments may use PHP, Python, Go, etc.

**Key properties:**
- Transport: HTTP/HTTPS, JSON request/response
- One endpoint, dispatched by `op` field
- No persistent connections; publisher lifetime = TTL from `last_seen`
- Proof-of-work only at registration; heartbeats use deregistration key only
- Direct punch coordination via `punch_req` / `punch_poll` (no relay)

---

## Common Conventions

- All requests: `POST /` with `Content-Type: application/json`
- All responses: JSON object with `status` field (`ok`, `error`, `challenge_required`, `not_found`)
- Error responses include `code` and `message`
- All string fields are UTF-8
- Maximum request body: 16 KiB
- Request timeout: 5 seconds

### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (1..63) | Publisher/consumer identifier, alnum only |
| `pass` | string (optional) | Shared registration password |
| `nonce` | hex string (16 chars) | 8-byte random challenge from server |
| `solution` | hex string (16 chars) | 8-byte client solution |
| `proof` | hex string (64 chars) | HMAC-SHA256(pass, nonce\|\|id\|\|solution) |
| `key` | hex string (64 chars) | 32-byte deregistration key from server |
| `proto` | integer | 1 = TCP (KCP), 2 = UDP |
| `udp_port` | integer (1..65535) | Local UDP port for direct traffic |
| `candidates` | array | Up to 8 candidate objects (see below) |

### Candidate Object

```json
{
  "type": "host|lan|public|srflx",
  "ip": "x.x.x.x|xxxx:...",
  "port": 12345,
  "priority": 100
}
```

- `type`: one of `host`, `lan`, `public`, `srflx`
- `ip`: literal IPv4 or IPv6 address
- `port`: UDP port
- `priority`: local priority (lower = preferred)

Server validates all candidates, deduplicates by (ip,port), recomputes local priority.

---

## Operations

### `challenge` - Request PoW challenge

**Request:**
```json
{ "op": "challenge", "id": "publisher1", "pass": "optional_password" }
```

**Response (challenge_required):**
```json
{
  "status": "challenge_required",
  "nonce": "a1b2c3d4e5f67890",
  "bits": 16
}
```

Server stores nothing. Client must solve `proof = HMAC-SHA256(pass, nonce_hex || id || solution_hex)` with `bits` leading zero bits.

---

### `register` - Register or re-register publisher

**Request:**
```json
{
  "op": "register",
  "id": "publisher1",
  "nonce": "a1b2c3d4e5f67890",
  "solution": "0000000000000001",
  "proof": "deadbeef...",
  "pass": "optional_password",
  "proto": 1,
  "udp_port": 40000,
  "candidates": [
    {"type": "host", "ip": "10.0.0.5", "port": 40000, "priority": 100},
    {"type": "lan", "ip": "192.168.1.50", "port": 40000, "priority": 110},
    {"type": "public", "ip": "203.0.113.10", "port": 40000, "priority": 120}
  ]
}
```

**Response (ok):**
```json
{
  "status": "ok",
  "key": "a1b2c3d4e5f6...(64 hex chars)"
}
```

**Error responses:**
- `bad_request` - malformed/oversized input
- `invalid_id` - id not alnum or >63 chars
- `auth_failed` - password mismatch or invalid PoW
- `table_full` - seats capacity exhausted (VIPs reserved)

Server verifies PoW by recomputing from echoed fields. On success, upserts record:
- `last_seen = now`
- `key` is **stable**: re-registration never rotates the key
- Returns existing key on re-registration

---

### `heartbeat` - Refresh publisher TTL and endpoints

**Request:**
```json
{
  "op": "heartbeat",
  "id": "publisher1",
  "key": "a1b2c3d4e5f6...",
  "proto": 1,
  "udp_port": 40000,
  "candidates": [...]
}
```

**Response (ok):**
```json
{ "status": "ok" }
```

**Error responses:**
- `not_found` - unknown or expired id
- `invalid_key` - key mismatch

No PoW. Updates `last_seen`, `proto`, `udp_port`, `candidates`. If record expired, client must `register` again.

---

### `lookup` - Get one publisher record

**Request:**
```json
{ "op": "lookup", "id": "publisher1" }
```

**Response (ok):**
```json
{
  "status": "ok",
  "id": "publisher1",
  "proto": 1,
  "udp_port": 40000,
  "candidates": [...],
  "last_seen": 1700000000
}
```

**Error (not_found):**
```json
{ "status": "not_found", "id": "publisher1" }
```

Filters expired records without writing.

---

### `list` - List all active publisher IDs

**Request:**
```json
{ "op": "list" }
```

**Response (ok):**
```json
{ "status": "ok", "ids": ["publisher1", "publisher2"] }
```

Returns only non-expired IDs.

---

### `deregister` - Remove publisher record

**Request:**
```json
{ "op": "deregister", "id": "publisher1", "key": "a1b2c3d4e5f6..." }
```

**Response (ok):**
```json
{ "status": "ok" }
```

**Error:**
- `not_found` - unknown id
- `invalid_key` - key mismatch

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

**Response (ok):**
```json
{ "status": "ok" }
```

Stores bounded pending call (TTL 30s). Consumer sends after `lookup`.

---

### `punch_poll` - Publisher retrieves pending calls

**Request:**
```json
{ "op": "punch_poll", "id": "publisher1" }
```

**Response (ok):**
```json
{
  "status": "ok",
  "calls": [
    {
      "self_id": "consumer1",
      "target_id": "publisher1",
      "session": "abc123",
      "candidates": [...]
    }
  ]
}
```

Returns and consumes calls for this publisher. Publisher polls at ~500ms cadence.

---

## Error Codes

| Code | Meaning | HTTP Status |
|------|---------|-------------|
| `bad_request` | Malformed, oversized, truncated, duplicate fields | 400 |
| `invalid_id` | Identifier rejected (not alnum, too long) | 400 |
| `auth_failed` | Password mismatch or invalid PoW | 403 |
| `invalid_key` | Deregistration key mismatch | 403 |
| `not_found` | Unknown or expired id | 404 |
| `table_full` | Seats capacity exhausted | 503 |
| `internal` | Server failure | 500 |

All errors: `{ "status": "error", "code": "...", "message": "..." }`

---

## Server Behavior

### Record Schema

```
PublisherRecord {
  id: string
  key: hex string (32 bytes)
  proto: 1|2
  udp_port: uint16
  candidates: Candidate[8]
  last_seen: unix_timestamp
}
```

### TTL

- Default TTL: 120 seconds (`REDP2P_ETIMEOUT_SEC`)
- Record expired if `now - last_seen > TTL`
- Expired records filtered from `lookup`/`list` (no write)
- Physical removal is an **implementation detail**: each deployment handles it as appropriate (cron job, internal timer, on-demand, etc.). The protocol does not expose a prune endpoint.

### Seats / Capacity

- Optional `max_seats` (via `--seats` or `REDP2P_SEATS`)
- Each VIP reservation occupies 1 seat (configured via `REDP2P_VIP`)
- Non-VIP publishers share remaining seats
- `table_full` when no seats available

### Proof of Work

- Algorithm: `HMAC-SHA256(pass, nonce_hex || id || solution_hex)`
- `pass`: global password (`REDP2P_PASS`) or per-VIP password; empty string if none
- Server recomputes from request fields; checks leading zero bits
- No server-side challenge storage (stateless)

### Punch Coordination

1. Consumer `lookup` → gets publisher candidates
2. Consumer `punch_req` with its own candidates + session id
3. Publisher `punch_poll` retrieves pending call
4. Both run direct `PUNCH_PING`/`PONG` probe against each other's candidates
5. On success, establish KCP (TCP mode) or UDP stream

---

## Implementation Notes

- **No background daemons required**: prune can run on a cron job or in the request path
- **Storage**: any K/V store with TTL support (files, SQLite, Redis, etc.)
- **No UDP/KCP/socket logic** in index
- **Key stability**: registration key minted once, never rotated
- **Heartbeat auth**: deregistration key only (possession proves ownership)
- **Candidate validation**: strict IP:port parsing, dedup, priority recompute
- **Bounds**: all fields bounded; reject oversized/truncated/duplicate input

---

## Example Flow

```bash
# 1. Get challenge
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"challenge","id":"alice"}' http://index:8080/

# 2. Solve PoW locally, register
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"register","id":"alice","nonce":"...","solution":"...","proof":"...","proto":1,"udp_port":40000,"candidates":[...]}' \
  http://index:8080/

# Returns key: store locally for heartbeat/deregister

# 3. Heartbeat every 15s
curl -X POST -H "Content-Type: application/json" \
  -d '{"op":"heartbeat","id":"alice","key":"...","proto":1,"udp_port":40000,"candidates":[...]}' \
  http://index:8080/

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

# 7. Both punch directly via UDP, establish KCP/TCP or UDP tunnel
```

---

## Versioning

This is protocol v1. Future versions may add optional fields but must not change the semantics of existing operations. Clients should ignore unknown response fields.
