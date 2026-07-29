# AGENTS.md

## Project Context

`redp2p.c` is a small, composable C library and CLI for direct peer-to-peer service tunneling.

It is intended for independently operated, small-scale systems such as:

* local communities
* small businesses
* cooperatives
* workshops
* local media
* kiosks
* events
* home systems
* personal infrastructure
* modest VPS and SBC deployments

Small scale is the intended destination.

Do not interpret the project as an incomplete enterprise networking platform.

Read `README.md` for usage and `DESIGN.md` for architectural boundaries before modifying the project.

## Motivation

REDP2P exists because small, independently operated systems are poorly served by software designed around enterprise infrastructure, managed cloud services, permanent external dependencies, and recurring payments.

The project owner is also its primary operator, integrator, and maintainer. Intended deployments are concrete and modest: neighborhood businesses, social clubs, community projects, groups of friends, personal infrastructure, small game servers, local media, kiosks, workshops, and similar systems.

The index must remain simple enough to run wherever an accessible address is available, including an inexpensive VPS, a home system, a single-board computer, or a smartphone. It coordinates peers but does not carry application traffic.

REDP2P provides one reusable connectivity component: peer coordination and direct TCP or UDP service tunneling.

Applications built on top of REDP2P define their own users, authentication, authorization, encryption, persistence, discovery, data models, business rules, and trust relationships. These responsibilities vary by implementation and remain outside REDP2P.

Their absence is not unfinished work.

Do not evaluate REDP2P as a smaller version of an enterprise networking platform. Enterprise platforms, hosted control planes, relays, identity systems, telemetry, centralized administration, and generalized infrastructure already exist elsewhere.

REDP2P addresses a different need: software that one person can understand, deploy, operate, and maintain with limited hardware, limited money, and limited complexity.

When evaluating a change, ask whether it is required for direct peer coordination or transport in an existing small-scale use case. Do not add generalized functionality for hypothetical deployments or future consumers.

Unrequested generalization is architectural drift. When implementation-specific functionality is needed, build or compose it outside REDP2P.

## Required Mindset

Do not optimize the project toward:

* enterprise adoption
* hyperscale operation
* managed infrastructure
* platform growth
* cloud-native architecture
* global identity
* organization management
* centralized administration
* universal connectivity
* ecosystem extensibility

Do not assume that more abstraction, configurability, generality, observability, integration, or scalability is automatically an improvement.

Resolve the requested task while preserving the existing project model.

Do not invent a broader product roadmap.

## Core Invariants

The following invariants must be preserved unless the project owner explicitly instructs otherwise:

* the index uses TCP as a control channel
* the index does not relay application traffic
* peer application traffic travels directly over UDP
* TCP mode uses vendored KCP over the peer UDP path
* UDP mode preserves application datagram boundaries
* STUN remains optional
* no TURN-style relay is implemented
* application authentication remains outside REDP2P
* application authorization remains outside REDP2P
* application encryption remains outside REDP2P
* no global identity system is introduced
* no user account system is introduced
* index state remains temporary
* the index requires no persistent database
* publisher deregistration keys remain local, scoped, minimal persistent state
* protocol fields, candidate sets, pending punches, and proof challenges remain bounded
* configured index publisher capacity is enforced through seats, including inactive VIP reservations
* the project remains usable on modest hardware
* the code remains inspectable by one person

The absence of relay, accounts, persistent identity, telemetry, and enterprise control infrastructure is intentional. The local registration key files used by `pub` and `del` are a narrow operational exception, not an index database or identity system.

These are not missing features.

## Forbidden Default Recommendations

Do not recommend or implement the following unless explicitly requested:

* TURN or relay servers
* application traffic fallback through the index
* hosted control planes
* cloud service dependencies
* mandatory STUN infrastructure
* user registration systems
* OAuth
* SSO
* organization or tenant models
* centralized authorization
* API gateways
* service meshes
* distributed databases
* persistent index storage
* telemetry collection
* analytics
* remote configuration
* fleet management
* dashboards
* billing systems
* plugin architectures
* generic transport abstractions
* dependency injection frameworks
* Kubernetes integration
* enterprise observability stacks
* automatic update infrastructure
* splitting `src/libredp2p.c` or introducing private implementation modules because of file size

Do not justify changes through enterprise readiness, market growth, adoption, or hypothetical future scale.

## Scope Discipline

REDP2P coordinates peers and transports TCP streams or UDP datagrams.

Responsibilities belonging to transported applications must remain outside the library.

Do not move the following into REDP2P without explicit instruction:

* user authentication
* application authorization
* payload encryption
* certificate management
* application discovery semantics
* business rules
* protocol-specific trust
* content catalogs
* application persistence

Prefer composition with another small tool over absorbing unrelated responsibilities.

## Local Key State

Successful publisher registration stores one index-host, index-port, and publisher-scoped deregistration key below `$HOME/.local/share/redp2p/keys/`. The key authorizes later deregistration; it does not identify a user or authenticate application traffic.

Preserve these properties:

* key files remain local to the operator
* scoped filenames do not expose the index or publisher text
* POSIX key files remain mode `0600`
* writes remain temporary-file replacements with durability checks
* reads reject malformed files, non-regular files, and links where the platform permits
* failed publication key storage rolls back index registration
* failed deregistration preserves the key for retry
* successful deregistration removes only the key value that was actually used
* legacy identifier-named keys remain read-only migration input

Do not expand this narrow state into accounts, identity stores, history, synchronization, remote custody, or a general persistence layer.

## Change Evaluation

Before implementing a change, determine:

* the concrete existing problem
* the smallest code path that solves it
* which invariant may be affected
* whether the problem belongs to REDP2P
* whether existing code can be simplified instead
* whether the change introduces hidden state
* whether it introduces an external operational dependency
* whether it increases resource use without a strict bound
* whether it makes behavior harder to inspect
* whether it changes the wire protocol
* whether it changes public API compatibility

Reject speculative architecture added only to support possible future requirements.

Do not add extension points without an existing caller.

Do not add configuration without a concrete operational requirement.

Do not add abstraction merely to reduce repeated code when the abstraction hides protocol behavior.

## Implementation Preferences

Prefer:

* direct C11 code
* explicit state transitions
* bounded arrays and queues
* checked parsing
* strict field limits
* deterministic cleanup
* clear socket ownership
* small functions with concrete responsibilities
* static internal helpers
* stable public API
* explicit error codes
* context-owned error details
* portable system abstractions
* removal of obsolete code
* documented limitations
* clean failure modes

Avoid:

* speculative generalization
* invisible global state
* unbounded allocations
* recursive protocol processing
* implicit ownership
* duplicated reliability logic around KCP
* platform behavior differences hidden behind the same API
* large dependency additions
* framework-style internal architecture
* callbacks or interfaces with only one hypothetical future implementation
* private cross-unit APIs
* internal symbol visibility macros
* modularization motivated only by line count
* additional compilation units for tightly coupled implementation details

Session and control-connection tables currently grow with active local work and are ultimately constrained by descriptors and `select()` representation rather than one fixed application-level session maximum. Do not claim every allocation has a strict static bound. Prefer explicit limits when changing these paths, and never add unbounded queues or retained history.

Publisher storage grows dynamically. Without configured seats, it has no application-level publisher capacity limit. When seats is configured through `--seats`, `REDP2P_SEATS`, or `redp2p_set_seats()`, treat it as the total publisher capacity. Each VIP reservation occupies one seat even while inactive, and non-VIP publishers use the remainder. Zero accepts no publishers. Keep allocation arithmetic checked without presenting implementation safety checks as product capacity limits.

## Source Layout

Preserve the existing four-file `src/` layout:

* `src/redp2p.c` owns CLI parsing, environment precedence, messages, and process exit behavior.
* `src/libredp2p.c` owns all reusable protocol, socket, persistence, punching, index, peer coordination, and transport behavior.
* `src/libredp2p.h` is the only library header and defines the public API, limits, result codes, and ownership contract.
* `src/test.c` contains all project tests.

The single-file implementation of `src/libredp2p.c` is an intentional project-wide kclib convention, not a temporary limitation or a refactoring opportunity.

Do not recommend, request, or implement splitting `src/libredp2p.c` merely because of its line count, number of internal responsibilities, or perceived maintainability. File size alone is not considered a defect in this project, including when the file exceeds several thousand lines.

Do not create:

* private project headers
* additional implementation units
* `internal.h`, `core.h`, `common.h`, or similar headers
* internal visibility macros
* cross-unit private APIs
* source subdirectories for implementation concerns
* separate files for index, peer, publisher, consumer, tunnel, transport, persistence, platform, or protocol helpers

Keep internal helpers `static` inside `src/libredp2p.c`.

Organize the implementation using clear sections, concrete functions, explicit ownership, and local static helpers rather than additional compilation units.

Extend the existing files instead of creating new project source, header, or test files.

Vendored KCP and Monocypher remain under `lib/`; they are external implementations and are the only intended exception to the four-file project source layout.

A source-layout change is allowed only when the project owner explicitly requests that exact structural change. Do not infer permission from a request to clean up, simplify, reorganize, review, reduce complexity, or improve maintainability.

If a requested change can be completed inside the existing files, it must be completed there.

## Protocol Changes

Treat the wire protocol as a compatibility boundary.

Protocol changes must:

* have a concrete requirement
* define parsing and serialization limits
* reject malformed input cleanly
* preserve bounded memory use
* define behavior for partial input
* define behavior for duplicate messages
* define timeout and cleanup behavior
* consider old and mismatched versions
* include tests for malformed and adversarial input

Do not add fields for hypothetical future use.

Do not silently reinterpret existing fields.

## Security Review

Security work must remain aligned with project scope.

Focus on:

* memory safety
* parser correctness
* spoofed control messages
* stale session state
* resource exhaustion
* socket ownership
* session isolation
* random value generation
* proof validation
* timeout handling
* malformed STUN responses
* malformed candidate data
* cleanup after failed punching
* KCP session separation

Do not treat bundling application encryption or identity into REDP2P as the default security solution.

The correct security fix may be stricter validation, clearer trust boundaries, or documentation.

## Testing

Every behavioral change should update or add tests.

Tests should prefer real local sockets and public API behavior.

Relevant areas include:

* API validation
* index registration
* registration rejection
* publisher capacity
* VIP handling
* proof-of-work handling
* lookup
* publisher listing
* deregistration
* TCP tunnel behavior
* UDP tunnel behavior
* concurrent sessions
* large TCP streams
* datagram limits
* packet loss
* packet reordering
* reconnect behavior
* malformed protocol input
* timeout cleanup
* stop behavior
* IPv4 and IPv6 behavior
* shared library use

Do not weaken tests to accommodate an implementation change.

Fix the implementation or explicitly revise the intended contract.

## Build and Validation

Use the repository build system.

Typical validation:

```bash
make
make test
```

When Windows behavior is affected:

```bash
make x86_64/windows
make test wine
```

Treat compiler warnings as failures.

Do not claim portability based only on successful cross-compilation when runtime behavior has not been tested.

## Documentation

Keep `README.md` concise and operational.

Use:

* `README.md` for CLI, API, build, tests, requirements, beta status, and license
* `DESIGN.md` for architecture, invariants, boundaries, accepted limitations, and non-goals
* `AGENTS.md` for implementation constraints and agent behavior

Do not expand the README to argue against every possible misinterpretation.

Do not describe deliberate exclusions as missing features.

Do not present enterprise evolution as the natural future of the project.

## Completion Standard

A task is complete when:

* the requested behavior is implemented
* existing invariants remain intact
* ownership and cleanup are correct
* failure behavior is explicit
* relevant tests pass
* documentation matches actual behavior
* no unrelated platform or enterprise architecture was introduced

The goal is not to make REDP2P larger.

The goal is to keep it useful, direct, bounded, understandable, portable, and locally operable.
