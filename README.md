# redp2p.c - peer-to-peer service tunneling

`redp2p.c` is a small C library and CLI for exposing local TCP and UDP services through direct peer-to-peer tunnels.

A temporary TCP index coordinates registration, lookup, candidate exchange, and UDP hole punching. Application traffic travels directly between peers.

TCP services are transported through vendored KCP over the direct UDP path. UDP services preserve datagram boundaries.

REDP2P is intended for small, independently operated systems that need direct connectivity without depending on managed cloud infrastructure, permanent hosted services, or recurring payments. Application-specific concerns such as users, authentication, authorization, encryption, persistence, and business rules remain outside the library.

See `DESIGN.md` for the project motivation, architectural boundaries, and non-goals.

---

## CLI

### Examples

Start an index server:

```bash
redp2p idx 9876
```

Start an index with publisher seats:

```bash
redp2p idx 9876 --seats 128
```

Start an index with proof-of-work registration cost:

```bash
redp2p idx 9876 --pow 20
```

List active publishers from a local index:

```bash
redp2p idx 9876 --list
redp2p idx 9876 -l
```

Publish a local TCP service:

```bash
redp2p pub web@idx.example.com:9876 --tcp 8080
```

Expose the remote TCP service locally:

```bash
redp2p con web@idx.example.com:9876 --tcp 9000
```

Use the service through the local bridge:

```bash
printf 'ping' | socat - TCP:127.0.0.1:9000
```

Publish and consume a UDP service:

```bash
redp2p pub game@idx.example.com:9876 --udp 7777
redp2p con game@idx.example.com:9876 --udp 9000
```

Enable optional STUN discovery:

```bash
redp2p pub web@idx.example.com:9876 --tcp 8080 \
  --stun stun:stun.cloudflare.com:3478
```

Remove a published service from the index:

```bash
redp2p del web@idx.example.com:9876
```

---

### Parameters

| Command/Flag                           | Description                                   |
| :------------------------------------- | :-------------------------------------------- |
| `idx <port>`                           | Start an index server                         |
| `idx <port> --seats <N>`               | Set total publisher seats to `N`               |
| `idx <port> --pow <N>`                 | Set publisher registration proof-of-work cost |
| `idx <port> --list`, `idx <port> -l`   | List active publishers from the local index   |
| `pub <id>@<index[:port]> --tcp <port>` | Publish a local TCP service                   |
| `pub <id>@<index[:port]> --udp <port>` | Publish a local UDP service                   |
| `con <id>@<index[:port]> --tcp <port>` | Expose a remote TCP service locally           |
| `con <id>@<index[:port]> --udp <port>` | Expose a remote UDP service locally           |
| `del <id>@<index[:port]>`              | Remove a published service                    |
| `--sweep <N>`                          | Set the bounded UDP port sweep range          |
| `--stun <url>`                         | Enable optional STUN endpoint discovery       |
| `-h`, `--help`                         | Show help and usage                           |
| `-v`, `--version`                      | Show build version                            |

The identifier before `@` is an arbitrary service label registered in the selected index.

IDs may contain ASCII letters and digits.

Index list mode connects to `127.0.0.1:<port>` without starting a server and prints one active publisher ID per line. It cannot be combined with server options such as `--seats` or `--pow`.

CLI flags override environment variables, which override built-in defaults.

Supported environment variables:

```text
REDP2P_PASS
REDP2P_VIP
REDP2P_POW
REDP2P_SEATS
REDP2P_SWEEP
REDP2P_STUN
```

`REDP2P_PASS`, `REDP2P_VIP`, and proof-of-work protect publisher registration and index capacity.

`REDP2P_SEATS=N` is equivalent to `idx --seats N`. Without either setting, the index has no publisher limit. When configured, `N` is the total number of publisher seats. Each VIP reservation occupies one seat even while that VIP is inactive; non-VIP publishers use the remaining seats. A value of `0` accepts no publishers. When both are present, `--seats` takes precedence.

---

## Public API

Start an index:

```c
#include "libredp2p.h"

redp2p_t *ctx = NULL;

if (redp2p_open(&ctx) == REDP2P_OK) {
    redp2p_set_pow(ctx, 0);
    redp2p_serve_index(ctx, "0.0.0.0", 9876);
    redp2p_close(ctx);
}
```

Publish a local service:

```c
#include "libredp2p.h"

redp2p_t *ctx = NULL;

if (redp2p_open(&ctx) == REDP2P_OK) {
    redp2p_set_protocol(ctx, REDP2P_PROTO_TCP);
    redp2p_set_port(ctx, 8080);
    redp2p_wait(ctx, "idx.example.com", 9876, "web", 0);
    redp2p_close(ctx);
}
```

Expose a remote service locally:

```c
#include "libredp2p.h"

redp2p_t *ctx = NULL;

if (redp2p_open(&ctx) == REDP2P_OK) {
    redp2p_set_protocol(ctx, REDP2P_PROTO_TCP);
    redp2p_set_port(ctx, 9000);
    redp2p_connect(
        ctx,
        "idx.example.com",
        9876,
        "consumer1",
        "web",
        0
    );
    redp2p_close(ctx);
}
```

List active publishers:

```c
#include "libredp2p.h"

#include <stdio.h>

static void on_publisher(const char *id, void *userdata) {
    (void)userdata;
    printf("%s\n", id);
}

redp2p_t *ctx = NULL;

if (redp2p_open(&ctx) == REDP2P_OK) {
    redp2p_list_publishers(
        ctx,
        "idx.example.com",
        9876,
        on_publisher,
        NULL
    );
    redp2p_close(ctx);
}
```

---

## Lifecycle

* `redp2p_options_default()` returns initialized runtime options.
* `redp2p_options_load_env()` loads supported environment values.
* `redp2p_options_free()` releases option-owned allocations.
* `redp2p_open()` allocates a caller-owned context.
* `redp2p_serve_index()` runs an index server.
* `redp2p_wait()` publishes a local service and accepts peer sessions.
* `redp2p_connect()` exposes a remote service through a local bridge.
* `redp2p_deregister()` removes one published service.
* `redp2p_list_publishers()` lists active publisher IDs.
* `redp2p_stop()` requests termination of a blocking operation.
* `redp2p_close()` releases the context and associated resources.

See `DESIGN.md` for protocol boundaries and architectural invariants.

---

## Build

Compiled artifacts are generated under:

```text
bin/{arch}/{platform}/
```

Build for the current host:

```bash
make
```

Clean and rebuild:

```bash
make clean && make
```

`make clean` removes both `.build/` and `bin/`.

### Tests

Build the project before running tests:

```bash
make
make test
```

Run Windows tests through Wine:

```bash
make x86_64/windows
make test wine
```

The portable test source is:

```text
src/test.c
```

Test executables link dynamically against the generated shared library and run through CTest.

### Multiarch Builds

```bash
make all
make x86_64/linux
make x86_64/windows
make x86_64/macos
make x86_64/iossim
make i686/linux
make i686/windows
make aarch64/linux
make aarch64/android
make aarch64/macos
make aarch64/ios
make aarch64/iossim
make armv7/linux
make armv7/android
make armv7hf/linux
make riscv64/linux
make powerpc64le/linux
make mips/linux
make mipsel/linux
make mips64el/linux
make s390x/linux
make loongarch64/linux
```

---

## Development Requirements

### Build Tools

* GNU Make
* CMake 3.14 or newer
* Ninja
* GCC or Clang with C11 support

### System Libraries

Linux:

* pthread
* libm

Windows:

* ws2_32
* bcrypt

macOS and iOS:

* no additional system libraries

### Optional Cross-Compilation SDKs

* MinGW for Windows builds
* Wine for running Windows tests on Linux
* osxcross for macOS and iOS targets
* Android NDK for Android targets

### Test Dependencies

* CTest

---

## Beta Notice

This is a beta project tested primarily on Debian x86_64.

It was created for independently operated, small-scale systems. No guarantees are provided regarding stability or future support.

You are free to test, use, and modify it.

Pull requests are not accepted. The project avoids long-term dependency on GitHub and does not rely on fixed hosted infrastructure.

Contact:

```text
kaisar@kaisarcode.com
```

---

## License

[![GPLv3](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

This project is distributed under the **GNU General Public License version 3 (GPLv3)**.

Vendored third-party source retains its own license:

- KCP, Copyright (c) 2017 Lin Wei, is distributed under the MIT License in `lib/kcp/LICENSE`.
- Monocypher is distributed under BSD-2-Clause or CC0-1.0 terms in `lib/monocypher/LICENSE`.
- Parson, Copyright (c) 2012–2022 Krzysztof Gabis, is distributed under the MIT License in `lib/parson/LICENSE`.
