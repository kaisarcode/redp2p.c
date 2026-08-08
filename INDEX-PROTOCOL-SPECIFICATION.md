# REDP2P Index Protocol Specification (v1)

## Introduction
The REDP2P Index is an architectural component designed as a stateless, decoupled coordination service. Its primary purpose is to function as a rendezvous point where peers register their reachability metadata and discover other peers.

It is important to note that while the original C-based project includes a built-in index feature, the index protocol itself can be implemented independently in other languages (such as PHP, Node.js, Python, or others). This separation applies exclusively to the index server, not to the clients. Clients require low-level networking capabilities-such as managing direct UDP sockets, handling NAT hole punching routines, and running the KCP protocol layer-which cannot be provided by restricted environments like typical shared hosting platforms. Because REDP2P is fundamentally designed to connect individual user machines, hosting the index on lightweight, accessible servers enables coordination without forcing users to rely solely on dedicated VPS infrastructure.

---

## API Endpoint Specification
- Transport: HTTP/HTTPS
- Method: POST
- Content-Type: application/json
- Payload: JSON object containing a mandatory "op" field. Unrecognized or missing "op" fields return HTTP 400 with a JSON error payload.

---

## Protocol Operations

### Operation: "publish"
Registers or updates peer reachability metadata.

#### Received Payload Fields
- `op`: String, value `"publish"`.
- `node_id`: String, unique identifier of the publishing peer.
- `endpoint`: String, transport address in `IP:PORT` format.
- `key`: String, local secret token for subsequent authentication.
- `challenge_id`: String, required when responding to a PoW challenge.
- `pow_nonce`: Unsigned integer, required when responding to a PoW challenge.
- `vip_token`: String, optional administrative authorization token.

#### Processing Logic
**Authorization & Anti-Abuse:**

- If `vip_token` matches the authorized store, PoW validation is skipped.
- If `vip_token` is absent or invalid, the `challenge_id` and `pow_nonce` are evaluated.
- If `challenge_id` and `pow_nonce` are missing or invalid/expired, the server generates a unique `challenge_id`, a random byte `seed`, and a system `difficulty` integer, stores the challenge state with an expiration timestamp, and returns a challenge requirement response.

If challenge parameters are present, the server computes a SHA-256 hash over the byte concatenation of the challenge seed, the `pow_nonce`, and the `node_id`. The resulting hash must satisfy the bitwise target defined by `difficulty`. If verification fails, the request is rejected.

**Capacity Management:**

The server evaluates active records against `max_seats`. Expired entries based on TTL are purged. If capacity remains exhausted after purging, registration is refused.

**Persistence:**

Stores or updates the record mapped to `node_id` with `endpoint`, `key`, a generation timestamp, and TTL expiration.

#### Server Responses
- **Challenge Required Response:**
{
    "status": "challenge_required",
    "challenge_id": "string",
    "seed": "string",
    "difficulty": integer
}
- **Success Response:**
{
    "status": "success",
    "node_id": "string",
    "ttl": integer,
    "assigned_seat": integer
}
- **Error Response (Capacity Exceeded):**
{
    "status": "error",
    "code": "capacity_exceeded",
    "message": "string"
}
- **Error Response (Invalid PoW):**
{
    "status": "error",
    "code": "invalid_pow",
    "message": "string"
}

---

### Operation: "lookup"
Retrieves routing metadata for a target peer.

#### Received Payload Fields
- `op`: String, value `"lookup"`.
- `target_id`: String, identifier of the target peer.

#### Processing Logic
1. Queries the storage backend for an active record matching `target_id`.
2. Evaluates the record's TTL timestamp against current system time. Expired records are treated as non-existent.
3. Retrieves the stored `endpoint` metadata if valid.

#### Server Responses
- **Success Response:**
{
    "status": "found",
    "target_id": "string",
    "endpoint": "string"
}
- **Error Response (Not Found / Expired):**
{
    "status": "not_found",
    "target_id": "string"
}

---

### Operation: "drop"
Removes a peer entry from the index upon graceful shutdown.

#### Received Payload Fields
- `op`: String, value `"drop"`.
- `node_id`: String, identifier of the peer.
- `key`: String, matching secret token established during publication.

#### Processing Logic
1. Locates the record associated with `node_id`.
2. Compares the provided `key` against the stored `key`.
3. Purges the record immediately if authorization succeeds.

#### Server Responses
- **Success Response:**
{
    "status": "success",
    "node_id": "string",
    "message": "dropped"
}
- **Error Response (Unauthorized / Not Found):**
{
    "status": "error",
    "code": "unauthorized",
    "message": "string"
}

---

## Architectural Constraints & System Lifecycle

- **Stateless Request-Response Cycle:** Each incoming HTTP request must be completely self-contained. The server must not rely on resident background daemons, persistent socket listeners, or in-memory process state.
- **Storage Agnosticism:** The underlying storage backend can be flat files, a lightweight SQL database, or a key-value store. It must support rapid read/write operations and automatic expiration of stale records.
- **Zero Transport Logic:** The index code must not contain UDP, KCP, or socket-binding logic for peer-to-peer data transmission.
- **Autonomous Server-Side Pruning:** No cleanup or prune operations are exposed to the clients or peers. Lifecycle management, such as the expiration of stale records based on time-to-live (TTL) and seat reclamation, is handled entirely and transparently by the server-side implementation.
