# REDP2P index server (PHP)

A PHP 8 implementation of the REDP2P index protocol, faithful to the C reference server (`redp2p idx <port>`) and to [INDEX-PROTOCOL-SPECIFICATION.md](../../INDEX-PROTOCOL-SPECIFICATION.md).

It is a single class, `KaisarCode\Redp2pIndex`, with no dependencies beyond the PHP core and PDO. Index state is stored in any PDO database using only portable SQL: SQLite for local deployments, MySQL for shared hosting.

The index coordinates peers over HTTP and carries no application traffic. Publisher records expire by TTL. Registration keys are generated locally per publisher and authorize heartbeat and deregister operations.

## Requirements

* PHP 8.0 or newer (strict types, `match`, `str_ends_with`).
* PDO with the `pdo_sqlite` driver, or `pdo_mysql` for MySQL.
* A web SAPI for `serve()` (`php -S`, Apache, nginx+FPM). The CLI SAPI does not populate `php://input`.

## Usage

Construct the index with a PDO connection and pass each HTTP request to `handle()`:

```php
<?php
declare(strict_types=1);

use KaisarCode\Redp2pIndex;

$pdo = new PDO('sqlite:var/redp2p.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$index = new Redp2pIndex($pdo, ['seats' => 128, 'pow' => 16]);

$res = $index->handle(
    $_SERVER['REQUEST_METHOD'],
    file_get_contents('php://input'),
    function_exists('getallheaders') ? getallheaders() : []
);

foreach ($res['headers'] as $name => $value) {
    header("$name: $value");
}
header('HTTP/1.1 ' . $res['status'] . ' ' . $res['reason'], true, $res['status']);
echo $res['body'];
```

`handle()` returns an array with `status` (int), `reason` (string), `headers` (string map), and `body` (string). The request path is ignored; only the JSON `op` field dispatches the operation.

`serve()` is a standalone front-controller helper that reads the current request and emits the response:

```php
<?php
use KaisarCode\Redp2pIndex;

Redp2pIndex::serve(
    ['dsn' => 'sqlite:var/redp2p.sqlite'],
    ['seats' => 128]
);
```

A full deployment route example lives in the `www` project as `src/controllers/redp2p.php`.

## Configuration

Options are applied in this order: constructor options, then `REDP2P_*` environment variables, then protocol defaults.

| Option | Environment | Default | Meaning |
| :----- | :---------- | :------ | :------ |
| `pass` | `REDP2P_PASS` | empty | Shared registration password |
| `vip` | `REDP2P_VIP` | none | Reserved id/pass pairs, array or `"id pass ..."` string |
| `seats` | `REDP2P_SEATS` | none | Total publisher seats; each VIP occupies one |
| `pow` | `REDP2P_POW` | `0` | Proof-of-work difficulty in leading zero bits |
| `ttl` | `REDP2P_ETIMEOUT_SEC` | `120` | Publisher eviction TTL in seconds |

The class also exposes public setters: `setPass()`, `setVips()`, `setSeats()`, `setPow()`, and `setTtl()`. `setSeats()` accepts zero (rejects all publishers) and treats an unset value as no limit. Each VIP reservation occupies one seat even while inactive; non-VIP publishers share the remainder.

## Operations

The class implements all eight protocol operations:

* `challenge` - issues a stateless nonce and difficulty.
* `register` - validates id, proof of work, and optional password, enforces seats/VIP capacity, and upserts a record with a stable deregistration key.
* `heartbeat` - key-only refresh of `last_seen` and endpoint fields.
* `lookup` and `list` - return fresh records, filtering expired ones.
* `deregister` - removes a record only when the stored key matches.
* `punch_req` - stores a bounded pending call for a target publisher.
* `punch_poll` - returns and consumes pending calls addressed to a publisher.

Successful responses use the envelope `{"ok": true, ...}`. Errors use `{"ok": false, "error": "<code>"}`. HTTP-level failures before JSON parsing (non-`POST`, `Transfer-Encoding`, oversized body) return a plain-text body, matching the reference server.

## Limits

The class enforces the protocol bounds:

* id and session tokens: 1..63 ASCII alphanumeric characters.
* registration key: 16 hex characters, minted once and stable across re-registration.
* nonce, solution, proof: 16, 8, and 64 hex characters.
* candidate list: up to 8 candidates of type `host`, `lan`, `public`, or `srflx`, literal IPv4/IPv6 address up to 47 characters, port 1..65535.
* request body: up to 4096 bytes, else HTTP 413.
* pending punch queue: 32 entries, 30-second TTL, `busy` when full.
* duplicate top-level JSON keys are rejected; nested duplicates are accepted.

Header count/size limits and the 5-second request timeout are enforced by the web server, not by this class.

## Storage

The schema is created automatically on construction and uses portable SQL (no `AUTO_INCREMENT`, no driver-specific syntax):

* `redp2p_publishers` - id, key, proto, udp_port, candidates, last_seen.
* `redp2p_pending_calls` - id, self_id, target_id, session, candidates, ts.
* `redp2p_meta` - reserved for future metadata.

Expired records are filtered from `lookup` and `list` without writing, and physically removed lazily on register, heartbeat, deregister, and punch_req.

`prune()` is the standalone cleanup entry point. It removes expired publisher records and pending punch calls. The class never schedules it by itself; the deployment operator runs it from their own script, for example a cron job:

```php
<?php
use KaisarCode\Redp2pIndex;

$pdo = new PDO('sqlite:var/redp2p.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$index = new Redp2pIndex($pdo);
$index->prune();
```

## License

GPL-3.0, matching the `redp2p.c` project.
