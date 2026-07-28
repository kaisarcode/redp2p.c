# rp2p.c Design

## Motivation

Modern networking software is commonly designed around managed cloud infrastructure, permanent hosted services, large organizations, and recurring operational payments. Those systems already have many mature tools available to them.

RP2P is intended for a different operating model.

Its users may be a neighborhood business, a social club, a community project, a group of friends, or one person operating personal infrastructure. They may need mobile and desktop applications to exchange data, expose a local service, interconnect a small user base, or run a game server without sharing a LAN or paying for a permanent traffic relay.

The project owner is also the operator and integrator. Deployments are known, concrete, and small. RP2P therefore does not need to anticipate every authentication model, trust relationship, storage design, or business rule that a future platform might require.

The only shared problem RP2P solves is connectivity: coordinating peers and transporting TCP streams or UDP datagrams directly between them.

Application-specific concerns remain with the application using the component. A club, business, game, or community system may define its own users, authentication, authorization, encryption, persistence, discovery, and trust model without forcing those choices into every other RP2P deployment.

This separation also preserves the project's economic and operational model. Because application traffic does not pass through the index, an index can remain inexpensive and replaceable. It may run on a modest VPS, a home system, a single-board computer, or even a smartphone whenever an accessible public address is available.

Small scale is not a temporary stage before enterprise growth. It is the intended destination. Limited resource use, low operational cost, direct ownership, and code that one person can inspect are product requirements.

Features must not be added merely because they are common in commercial networking platforms or might be useful someday. Functionality that belongs to one implementation should be built or composed outside RP2P.

## Purpose

`rp2p.c` is a small tunneling primitive for independently operated systems.

It allows one peer to publish a local TCP or UDP service and another peer to expose that service through a local port.

The project is intended for individuals, local communities, small businesses, home systems, workshops, cooperatives, local media, kiosks, events, and other modest deployments.

Small scale is the intended operating model.

The project is not designed as an enterprise networking platform, managed connectivity service, global overlay network, or universal NAT traversal system.

## Architecture

RP2P separates coordination from application transport.

The index is a TCP-only control service.

It handles:

* publisher registration
* deregistration
* publisher lookup
* publisher listing
* candidate exchange
* punch coordination
* temporary registration state

The index does not:

* bind UDP for peer traffic
* relay application payloads
* inspect application protocols
* provide application authentication
* provide consumer identity
* provide global accounts
* maintain a permanent network database
* act as a control plane for managed clients

Application traffic travels directly between peers through UDP.

## Transport Modes

### TCP mode

The local application communicates with RP2P through TCP.

RP2P transports the byte stream between peers using vendored KCP over UDP.

KCP provides:

* ordering
* acknowledgements
* retransmission
* congestion and window state
* stream reconstruction

RP2P adds only the session lifecycle envelope required around KCP:

* `HELLO`
* `HELLO_ACK`
* `KCP`
* `CLOSE`
* `CLOSE_ACK`
* `RESET`
* `KEEPALIVE`

RP2P must not implement a second reliable transport layer around KCP.

### UDP mode

UDP datagrams are transported directly between peers.

Datagram boundaries are preserved.

RP2P does not add:

* ordering
* retransmission
* duplication suppression guarantees
* fragmentation of oversized application datagrams

Applications using UDP remain responsible for their own delivery semantics.

## Direct Connectivity

RP2P attempts to establish a direct UDP path between peers.

Candidate sources may include:

* the UDP socket's loopback endpoint
* one LAN endpoint selected by the local IPv4 route
* an optional IPv4 STUN-discovered endpoint

STUN is optional.

STUN is used only to discover an externally visible endpoint. It does not carry application traffic and does not become part of an established tunnel.

RP2P does not implement TURN or any equivalent application traffic relay.

The current control protocol accepts only `host`, `lan`, `public`, and `srflx` candidate records. It validates literal IPv4 or IPv6 addresses, removes duplicate endpoints, recomputes local priority, and attempts candidates in deterministic priority order. The implementation does not currently generate `public`, peer-reflexive, predicted, or proxy candidate records.

When enabled, the bounded sweep probes neighboring IPv4 ports only around received `public` or `srflx` candidates. It is a direct-punch fallback, not a candidate service or relay.

When a direct path cannot be established, the session may fail.

This is an accepted operational result. It is not automatically missing functionality.

## Security Boundaries

RP2P transports application traffic without defining the application security model.

Application protocols remain responsible for:

* peer authentication
* user authentication
* authorization
* confidentiality
* payload integrity
* application identity
* trust establishment

Protocols such as SSH, HTTPS, TLS-enabled services, or application-specific secure protocols may run through RP2P without duplicating their security layer inside the tunnel.

Plaintext application protocols may also be transported when the operator deliberately accepts that model.

The index control protocol is not an application payload security layer.

`RP2P_PASS`, `RP2P_VIP`, and proof-of-work protect publisher registration and index capacity. They do not authenticate consumers, establish peer identity, or encrypt transported payloads.

## Registration Protection

A public index may allow open registration.

Optional controls include:

* global publisher password
* reserved publisher IDs with individual passwords
* proof-of-work registration cost
* optional operator-configured publisher capacity

Registration protection exists to control index use and resource occupation.

It must not expand into:

* user accounts
* consumer permissions
* organization management
* centralized authorization
* persistent identity infrastructure

## State

Index state is temporary.

The index stores only the state required to coordinate active publishers and pending sessions.

It must not become a permanent source of truth.

Publisher registration creates one narrow piece of local persistent state: a deregistration key under `$HOME/.local/share/rp2p/keys/`. Its filename is a SHA-256 scope over the index host, index port, and publisher ID. The key is written through a private temporary file, stored as mode `0600` on POSIX, and removed after successful deregistration. A publisher rolls back registration if the key cannot be stored.

The key authorizes `del` for one registration scope. It is not user identity, peer identity, application authentication, or durable index state. A legacy identifier-named key may be read for migration, but new keys use scoped hashed filenames.

The design should prefer:

* explicit bounds for protocol fields, candidates, pending punches, and proof challenges
* checked dynamic storage for active runtime state
* explicit timeouts
* automatic stale-state removal
* clean failure when configured capacity is exhausted

Databases, synchronized key stores, registration history, and persistent index state are outside the project scope.

## Composition

RP2P should compose with existing tools and protocols rather than absorb their responsibilities.

Examples:

* SSH provides authenticated encrypted remote access.
* HTTPS provides application transport security.
* DNS or local catalogs may provide human-facing discovery.
* systemd may supervise a process.
* an external proxy may expose a local bridge.
* separate applications may define users and permissions.

A feature should not be added to RP2P merely because it is commonly bundled into larger networking platforms.

## Portability

The implementation targets portable C11.

Supported build targets may include Linux, Windows, macOS, iOS, Android, and multiple CPU architectures.

Portability exists to support heterogeneous, inexpensive, locally available hardware.

It is not a claim that every target has received equal runtime validation.

Platform-specific behavior must preserve the same public API and protocol semantics.

## Resource Model

The project must remain suitable for modest systems.

Design choices should prefer:

* bounded protocol fields and datagrams
* bounded candidate, pending-punch, and proof-challenge tables
* checked dynamic publisher storage with optional operator-configured capacity
* bounded candidate lists
* bounded port sweeps
* explicit socket ownership
* deterministic cleanup
* limited background threads
* no mandatory external services

Publisher storage grows dynamically as publishers become active. When `--seats` or `RP2P_SEATS` is configured, seats is the total publisher capacity. Each VIP reservation occupies one seat even while inactive, and non-VIP publishers use the remaining seats. Without either setting, no application-level publisher limit applies. Removing an active publisher releases its occupancy, while a VIP reservation remains reserved for that VIP.

Active publisher and consumer session arrays and index control-connection storage grow with live descriptors and are constrained by `select()` representation rather than one fixed session count. They do not retain completed work. Unbounded queues, hidden history, and infrastructure-dependent behavior should be rejected.

## Inspectability

One person should be able to understand the complete connection path without learning a framework or navigating a distributed internal architecture.

The implementation intentionally keeps reusable library behavior in one compilation unit: `src/librp2p.c`.

This single-file structure is part of the kclib maintenance model. It keeps internal helpers `static`, avoids private cross-unit contracts, preserves local visibility of state and ownership, and allows the complete implementation path to be inspected in one place.

A large source file is not considered a design defect by itself. Line count, including a file size of several thousand lines, is not sufficient justification for modularization.

Inspectability is provided through:

* clear implementation sections
* concrete function names
* small static helpers
* explicit state transitions
* visible ownership and cleanup
* direct control flow
* removal of obsolete code
* avoidance of generic internal frameworks

The project must not introduce private headers, internal visibility annotations, or additional implementation units solely to distribute code across files.

Splitting index, peer coordination, punching, persistence, or tunnel transport into separate compilation units would require internal contracts between responsibilities that intentionally share state and primitives. Such a split is not an architectural improvement unless the project owner explicitly defines and requests the new boundary.

Internal organization should improve the single implementation file rather than replace it with a module graph.

Generic extensibility remains outside the project goals.

## Non-goals

RP2P is not intended to provide:

* enterprise network orchestration
* universal connectivity
* application traffic relay
* global peer identity
* user accounts
* organization management
* centralized authorization
* service mesh behavior
* remote fleet management
* hosted control infrastructure
* telemetry collection
* billing
* plugin ecosystems
* generic routing
* distributed consensus
* a permanent distributed network
* replacement application security

These are design exclusions, not an unfinished roadmap.

## Change Criteria

A proposed change should be evaluated with the following questions:

1. What concrete small-scale problem does it solve?
2. Is the problem part of tunneling, or does it belong to another component?
3. Can it be solved through composition with an existing small tool?
4. Does it introduce permanent infrastructure?
5. Does it move application responsibility into RP2P?
6. Does it increase hidden state or operator dependency?
7. Does it make the connection path harder for one person to inspect?
8. Does it preserve direct peer-to-peer application traffic?
9. Does it preserve bounded resource use?
10. Is the added complexity justified by an existing use case?
11. Does it preserve the intentional single-file kclib implementation model?

Changes justified mainly by hypothetical future scale, enterprise readiness, platform growth, managed operation, or ecosystem expectations should be rejected.

## Core Invariants

The following properties define the project:

* the index is coordination infrastructure
* application traffic does not pass through the index
* peer transport is direct UDP
* TCP mode uses KCP over UDP
* UDP mode preserves datagrams
* STUN remains optional
* no TURN-style relay is provided
* application security remains external
* index state remains temporary
* local persisted state is limited to scoped deregistration keys
* protocol and coordination resource limits remain explicit
* the implementation remains small and inspectable
* reusable library behavior remains in the single `src/librp2p.c` implementation unit unless the project owner explicitly changes the source-layout contract
* local operation does not require accounts or subscriptions

These constraints define the product.

They are not a roadmap.
