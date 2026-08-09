# REDP2P index protocol implementations

Alternate implementations of the REDP2P index protocol server.

The wire contract is defined in [INDEX-PROTOCOL-SPECIFICATION.md](../INDEX-PROTOCOL-SPECIFICATION.md). The C reference implementation is `redp2p idx <port>`. These directories provide drop-in index servers for deployments that cannot run the C binary.

Contents:

* `php/` - PHP 8 index server backed by PDO (SQLite or MySQL).
