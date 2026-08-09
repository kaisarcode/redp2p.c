<?php
/**
 * Summary: REDP2P index protocol server (PHP)
 *
 * Author: KaisarCode
 * Website: https://kaisarcode.com
 * License: GPL-3.0
 */
declare(strict_types=1);
namespace KaisarCode;

use PDO;

/**
 * Class Redp2pIndex
 *
 * Server-side implementation of the REDP2P index protocol over HTTP/JSON.
 *
 * Faithful to the C reference behavior in libredp2p.c: same HTTP status codes,
 * same JSON error and success payloads, same proof-of-work construction, same
 * candidate rules, same seat/VIP semantics, and the same pending punch queue
 * limits. Index state is stored in any PDO database (SQLite locally, MySQL on
 * shared hosting) using only portable SQL.
 *
 * The index coordinates peers and carries no application traffic. Publisher
 * records expire by TTL. Registration keys are generated locally per publisher
 * and authorize heartbeat and deregister operations.
 *
 * Design constraints:
 * - Zero dependencies beyond the PHP core and PDO.
 * - Portable SQL: no AUTO_INCREMENT, no driver-specific syntax.
 * - Configurable by constructor options, then REDP2P_* environment variables,
 *   then protocol defaults that match the C implementation.
 * - Explicit validation mirrors the C limits (id 63, candidates 8, body 4096).
 *
 * Usage:
 * Construct with a PDO to the index database, then pass each HTTP request to
 * the handle method.
 */
class Redp2pIndex
{
    public const ID_MAX = 63;
    public const SESSION_MAX = 63;
    public const ADDR_MAX = 47;
    public const KEY_SZ = 16;
    public const PASS_MAX = 255;
    public const CANDIDATES_MAX = 8;
    public const PENDING_MAX = 32;
    public const PENDING_TTL_S = 30;
    public const BODY_MAX = 4096;
    public const DEFAULT_TTL_S = 120;

    public const CANDIDATE_TYPES = ['host', 'lan', 'public', 'srflx'];

    private const ERROR_MALFORMED = 'REDP2P_CTRTOK_ERROR:malformed';

    private PDO $db;
    private string $pass = '';
    private array $vips = [];
    private ?int $seats = null;
    private int $pow = 0;
    private int $ttl = self::DEFAULT_TTL_S;

    /**
     * Initializes the index with a database connection and configuration.
     *
     * @param PDO $db Open database connection (SQLite or MySQL).
     * @param array<string, mixed> $options Optional index options.
     * @return void
     */
    public function __construct(PDO $db, array $options = [])
    {
        $this->db = $db;
        $this->applyOptions($options);
        $this->ensureSchema();
    }

    /**
     * Processes one HTTP request and returns the full HTTP response.
     *
     * @param string $method HTTP method.
     * @param string $body Raw JSON request body.
     * @param array<string, mixed> $headers Request headers.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    public function handle(string $method, string $body, array $headers = []): array
    {
        if ($method !== 'POST') {
            return $this->httpError(405, 'Method Not Allowed');
        }
        if ($this->hasHeader($headers, 'Transfer-Encoding')) {
            return $this->httpError(501, 'Not Implemented');
        }
        if (strlen($body) > self::BODY_MAX) {
            return $this->httpError(413, 'Payload Too Large');
        }

        $req = json_decode($body);
        if (!($req instanceof \stdClass)) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($this->hasDuplicateTopKeys($body)) {
            return $this->jsonError(400, 'bad_request');
        }
        if (!$this->hasString($req, 'op')) {
            return $this->jsonError(400, 'bad_request');
        }

        try {
            switch ($req->op) {
                case 'challenge':
                    return $this->handleChallenge($req);
                case 'register':
                    return $this->handleRegister($req);
                case 'heartbeat':
                    return $this->handleHeartbeat($req);
                case 'lookup':
                    return $this->handleLookup($req);
                case 'list':
                    return $this->handleList();
                case 'deregister':
                    return $this->handleDeregister($req);
                case 'punch_req':
                    return $this->handlePunchReq($req);
                case 'punch_poll':
                    return $this->handlePunchPoll($req);
                default:
                    return $this->jsonError(400, 'bad_request');
            }
        } catch (\PDOException $e) {
            return $this->jsonError(500, 'internal');
        }
    }

    /**
     * Serves one request from the web server globals and emits the response.
     *
     * Standalone front-controller helper: reads the request method, raw body,
     * and headers from the current request and prints the index response.
     *
     * @param array{
     *     dsn: string,
     *     user?: string,
     *     pass?: string
     * } $db Database connection settings.
     * @param array<string, mixed> $options Optional index options.
     * @return void
     */
    public static function serve(array $db, array $options = []): void
    {
        $pdo = new PDO($db['dsn'], $db['user'] ?? null, $db['pass'] ?? null);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $index = new self($pdo, $options);

        $headers = function_exists('getallheaders') ? getallheaders() : [];
        $res = $index->handle(
            $_SERVER['REQUEST_METHOD'],
            file_get_contents('php://input'),
            $headers
        );

        header(sprintf('HTTP/1.1 %d %s', $res['status'], $res['reason']), true, $res['status']);
        foreach ($res['headers'] as $name => $value) {
            header("$name: $value");
        }
        echo $res['body'];
    }

    /**
     * Removes expired publisher records and pending punch calls.
     *
     * Called externally on a schedule by the deployment operator, for example
     * from a cron job. Request handling also removes expired records lazily;
     * this method is the standalone cleanup entry point.
     *
     * @return void
     */
    public function prune(): void
    {
        $this->evictStale();
        $this->evictPending();
    }

    /**
     * Sets the shared registration password.
     *
     * @param string $pass Shared password, or an empty string for none.
     * @return void
     */
    public function setPass(string $pass): void
    {
        if ($pass !== '' && !$this->isValidPassToken($pass)) {
            throw new \InvalidArgumentException('REDP2P_PASS contains invalid bytes');
        }
        $this->pass = $pass;
    }

    /**
     * Sets reserved VIP seats as identifier/password pairs.
     *
     * @param array<int|string, mixed>|string|null $vips VIP map, list of
     *   id/pass pairs, or the C-style whitespace-separated "<id> <pass> ..."
     *   string.
     * @return void
     */
    public function setVips($vips): void
    {
        $map = [];
        if (is_string($vips)) {
            $tokens = preg_split('/\s+/', trim($vips), -1, PREG_SPLIT_NO_EMPTY);
            $tokens = $tokens === false ? [] : $tokens;
            if (count($tokens) % 2 !== 0) {
                throw new \InvalidArgumentException('REDP2P_VIP has odd token count');
            }
            for ($i = 0; $i < count($tokens); $i += 2) {
                if (isset($map[$tokens[$i]])) {
                    throw new \InvalidArgumentException("REDP2P_VIP redefines reserved id '{$tokens[$i]}'");
                }
                $map[$tokens[$i]] = $tokens[$i + 1];
            }
        } elseif (is_array($vips)) {
            foreach ($vips as $key => $value) {
                if (is_int($key)) {
                    if (!is_array($value) || !isset($value['id'], $value['pass'])) {
                        throw new \InvalidArgumentException('REDP2P_VIP pair must provide id and pass');
                    }
                    $map[(string)$value['id']] = (string)$value['pass'];
                } else {
                    $map[(string)$key] = (string)$value;
                }
            }
        } elseif ($vips !== null) {
            throw new \InvalidArgumentException('REDP2P_VIP must be a string or an array');
        }
        foreach ($map as $id => $pass) {
            if (!$this->isValidId($id)) {
                throw new \InvalidArgumentException("REDP2P_VIP invalid id '$id'");
            }
            if (!$this->isValidPassToken($pass)) {
                throw new \InvalidArgumentException("REDP2P_VIP invalid password for id '$id'");
            }
        }
        $this->vips = $map;
    }

    /**
     * Sets the configured publisher seat capacity.
     *
     * @param int $seats Total publisher capacity. Zero rejects all publishers
     *   when explicitly configured; leaving seats unset means no limit.
     * @return void
     */
    public function setSeats(int $seats): void
    {
        if ($seats < 0) {
            throw new \InvalidArgumentException('REDP2P_SEATS must be zero or positive');
        }
        $this->seats = $seats;
    }

    /**
     * Sets the proof-of-work difficulty in leading zero bits.
     *
     * @param int $bits Difficulty target, 0..32.
     * @return void
     */
    public function setPow(int $bits): void
    {
        if ($bits < 0 || $bits > 32) {
            throw new \InvalidArgumentException('REDP2P_POW must be between 0 and 32');
        }
        $this->pow = $bits;
    }

    /**
     * Sets the publisher eviction TTL in seconds.
     *
     * @param int $ttl TTL seconds, 1..86400.
     * @return void
     */
    public function setTtl(int $ttl): void
    {
        if ($ttl < 1 || $ttl > 86400) {
            throw new \InvalidArgumentException('REDP2P_ETIMEOUT_SEC must be between 1 and 86400');
        }
        $this->ttl = $ttl;
    }

    /**
     * Applies constructor options with environment fallback.
     *
     * @param array $options Option overrides for pass, vip, seats, pow and ttl.
     *   Falls back to REDP2P_* environment variables.
     * @return void
     */
    private function applyOptions(array $options): void
    {
        $pass = $options['pass'] ?? $this->env('REDP2P_PASS') ?? '';
        $vip = $options['vip'] ?? $this->env('REDP2P_VIP');
        $seats = $options['seats'] ?? $this->env('REDP2P_SEATS');
        $pow = $options['pow'] ?? $this->env('REDP2P_POW') ?? 0;
        $ttl = $options['ttl'] ?? $this->env('REDP2P_ETIMEOUT_SEC') ?? self::DEFAULT_TTL_S;

        $this->setPass((string)$pass);
        if ($vip !== null) {
            $this->setVips($vip);
        }
        if ($seats !== null) {
            $this->setSeats((int)$seats);
        }
        $this->setPow((int)$pow);
        $this->setTtl((int)$ttl);
    }

    /**
     * Reads an environment variable.
     *
     * @param string $name Variable name.
     * @return string|null Value, or null when unset.
     */
    private function env(string $name): ?string
    {
        $value = getenv($name);
        return $value === false ? null : $value;
    }

    /**
     * Handles the challenge operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handleChallenge(\stdClass $req): array
    {
        [$result, $id] = $this->requireId($req, 'id');
        if ($result === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($result < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $nonce = bin2hex(random_bytes(8));
        return $this->jsonOk(['nonce' => $nonce, 'bits' => $this->pow]);
    }

    /**
     * Handles the register operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handleRegister(\stdClass $req): array
    {
        [$result, $id] = $this->requireId($req, 'id');
        if ($result === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($result < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $nonce = $this->requireHex($req, 'nonce', 16);
        $solution = $this->requireHex($req, 'solution', 8);
        $proof = $this->requireHex($req, 'proof', 64);
        if ($nonce === null || $solution === null || $proof === null) {
            return $this->jsonError(400, 'bad_request');
        }
        [$proto, $udpPort] = $this->requireProtoPort($req);
        if ($proto === null) {
            return $this->jsonError(400, 'bad_request');
        }
        [$candOk, $candidates] = $this->parseCandidates($req, 'candidates');
        if (!$candOk) {
            return $this->jsonError(400, 'bad_request');
        }

        $pass = $this->getPass($id);
        if (!$this->verifyPow($pass, $nonce, $id, $solution, $proof)) {
            return $this->jsonError(403, 'auth_failed');
        }

        $this->evictStale();
        $added = $this->addPublisher($id);
        if ($added === 'full') {
            return $this->jsonError(503, 'table_full');
        }
        if ($added !== 'ok') {
            return $this->jsonError(500, 'internal');
        }
        $key = $this->setPublisher($id, $proto, $udpPort, $candidates);
        return $this->jsonOk(['key' => $key]);
    }

    /**
     * Handles the heartbeat operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handleHeartbeat(\stdClass $req): array
    {
        [$result, $id] = $this->requireId($req, 'id');
        if ($result === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($result < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $key = $this->requireHex($req, 'key', self::KEY_SZ);
        if ($key === null) {
            return $this->jsonError(400, 'bad_request');
        }
        [$proto, $udpPort] = $this->requireProtoPort($req);
        if ($proto === null) {
            return $this->jsonError(400, 'bad_request');
        }
        [$candOk, $candidates] = $this->parseCandidates($req, 'candidates');
        if (!$candOk) {
            return $this->jsonError(400, 'bad_request');
        }

        $this->evictStale();
        $stored = $this->findKey($id);
        if ($stored === null) {
            return $this->jsonError(404, 'not_found');
        }
        if (!hash_equals($stored, $key)) {
            return $this->jsonError(403, 'invalid_key');
        }
        $this->setPublisher($id, $proto, $udpPort, $candidates);
        return $this->jsonOk();
    }

    /**
     * Handles the lookup operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handleLookup(\stdClass $req): array
    {
        [$result, $id] = $this->requireId($req, 'id');
        if ($result === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($result < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $row = $this->findPublisher($id);
        if ($row === null) {
            return $this->jsonError(404, 'not_found');
        }
        if ((int)$row['last_seen'] < time() - $this->ttl) {
            return $this->jsonError(404, 'not_found');
        }
        return $this->jsonOk([
            'id' => $id,
            'proto' => (int)$row['proto'],
            'udp_port' => (int)$row['udp_port'],
            'candidates' => $this->decodeCandidates((string)$row['candidates']),
            'last_seen' => (int)$row['last_seen'],
        ]);
    }

    /**
     * Handles the list operation.
     *
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handleList(): array
    {
        $cutoff = time() - $this->ttl;
        $st = $this->db->prepare('SELECT id FROM redp2p_publishers WHERE last_seen >= ?');
        $st->execute([$cutoff]);
        $ids = $st->fetchAll(PDO::FETCH_COLUMN);
        return $this->jsonOk(['ids' => array_map('strval', $ids)], false);
    }

    /**
     * Handles the deregister operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handleDeregister(\stdClass $req): array
    {
        [$result, $id] = $this->requireId($req, 'id');
        if ($result === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($result < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $key = $this->requireHex($req, 'key', self::KEY_SZ);
        if ($key === null) {
            return $this->jsonError(400, 'bad_request');
        }
        $this->evictStale();
        $stored = $this->findKey($id);
        if ($stored === null || !hash_equals($stored, $key)) {
            return $this->jsonError(403, 'invalid_key');
        }
        $st = $this->db->prepare('DELETE FROM redp2p_publishers WHERE id = ?');
        $st->execute([$id]);
        return $this->jsonOk();
    }

    /**
     * Handles the punch_req operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handlePunchReq(\stdClass $req): array
    {
        [$selfResult, $selfId] = $this->requireId($req, 'self_id');
        [$targetResult, $targetId] = $this->requireId($req, 'target_id');
        if ($selfResult === 0 || $targetResult === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($selfResult < 0 || $targetResult < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $session = $this->getString($req, 'session');
        if ($session === null || !$this->isSessionToken($session)) {
            return $this->jsonError(400, 'bad_request');
        }
        [$candOk, $candidates] = $this->parseCandidates($req, 'candidates');
        if (!$candOk) {
            return $this->jsonError(400, 'bad_request');
        }

        $this->evictPending();
        $st = $this->db->query('SELECT COUNT(*) FROM redp2p_pending_calls');
        if ((int)$st->fetchColumn() >= self::PENDING_MAX) {
            return $this->jsonError(503, 'busy');
        }
        $ins = $this->db->prepare(
            'INSERT INTO redp2p_pending_calls (id, self_id, target_id, session, candidates, ts)'
            . ' VALUES (?, ?, ?, ?, ?, ?)'
        );
        $ins->execute([
            bin2hex(random_bytes(8)),
            $selfId,
            $targetId,
            $session,
            json_encode($candidates),
            time(),
        ]);
        return $this->jsonOk();
    }

    /**
     * Handles the punch_poll operation.
     *
     * @param \stdClass $req Parsed request object.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function handlePunchPoll(\stdClass $req): array
    {
        [$result, $id] = $this->requireId($req, 'id');
        if ($result === 0) {
            return $this->jsonError(400, 'bad_request');
        }
        if ($result < 0) {
            return $this->jsonError(400, 'invalid_id');
        }
        $this->evictPending();
        $st = $this->db->prepare(
            'SELECT self_id, session, candidates FROM redp2p_pending_calls WHERE target_id = ?'
        );
        $st->execute([$id]);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC);
        $calls = [];
        foreach ($rows as $row) {
            $calls[] = [
                'self_id' => (string)$row['self_id'],
                'session' => (string)$row['session'],
                'candidates' => $this->decodeCandidates((string)$row['candidates']),
            ];
        }
        $del = $this->db->prepare('DELETE FROM redp2p_pending_calls WHERE target_id = ?');
        $del->execute([$id]);
        return $this->jsonOk(['calls' => $calls], false);
    }

    /**
     * Adds a publisher seat when capacity allows.
     *
     * @param string $id Publisher id.
     * @return string 'ok', or 'full' when at capacity.
     */
    private function addPublisher(string $id): string
    {
        $now = time();
        $st = $this->db->prepare('SELECT 1 FROM redp2p_publishers WHERE id = ?');
        $st->execute([$id]);
        if ($st->fetch()) {
            return 'ok';
        }

        if ($this->seats !== null) {
            $st = $this->db->query('SELECT COUNT(*) FROM redp2p_publishers');
            if ((int)$st->fetchColumn() >= $this->seats) {
                return 'full';
            }
            if (!isset($this->vips[$id])) {
                $nonVip = $this->countNonVip();
                $cap = $this->seats - count($this->vips);
                if ($cap < 0) {
                    $cap = 0;
                }
                if ($nonVip >= $cap) {
                    return 'full';
                }
            }
        }

        $ins = $this->db->prepare(
            'INSERT INTO redp2p_publishers (id, key, proto, udp_port, candidates, last_seen)'
            . ' VALUES (?, ?, 0, 0, NULL, ?)'
        );
        $ins->execute([$id, bin2hex(random_bytes(8)), $now]);
        return 'ok';
    }

    /**
     * Stores a publisher record and returns its registration key.
     *
     * @param string $id Publisher id.
     * @param int $proto Protocol version (1 or 2).
     * @param int $udpPort Publisher UDP port.
     * @param array<int, array<string, mixed>> $candidates
     *   Candidate endpoints.
     * @return string Registration key.
     */
    private function setPublisher(string $id, int $proto, int $udpPort, array $candidates): string
    {
        $st = $this->db->prepare('SELECT key FROM redp2p_publishers WHERE id = ?');
        $st->execute([$id]);
        $key = (string)$st->fetchColumn();
        $up = $this->db->prepare(
            'UPDATE redp2p_publishers SET proto = ?, udp_port = ?, candidates = ?, last_seen = ? WHERE id = ?'
        );
        $up->execute([$proto, $udpPort, json_encode($candidates), time(), $id]);
        return $key;
    }

    /**
     * Counts publishers not reserved as VIP.
     *
     * @return int Publisher count.
     */
    private function countNonVip(): int
    {
        if ($this->vips === []) {
            $st = $this->db->query('SELECT COUNT(*) FROM redp2p_publishers');
            return (int)$st->fetchColumn();
        }
        $ids = array_keys($this->vips);
        $ph = implode(',', array_fill(0, count($ids), '?'));
        $st = $this->db->prepare("SELECT COUNT(*) FROM redp2p_publishers WHERE id NOT IN ($ph)");
        $st->execute($ids);
        return (int)$st->fetchColumn();
    }

    /**
     * Finds the registration key for a publisher.
     *
     * @param string $id Publisher id.
     * @return string|null Key, or null when unknown.
     */
    private function findKey(string $id): ?string
    {
        $st = $this->db->prepare('SELECT key FROM redp2p_publishers WHERE id = ?');
        $st->execute([$id]);
        $value = $st->fetchColumn();
        return $value === false ? null : (string)$value;
    }

    /**
     * Finds the live record for a publisher.
     *
     * @param string $id Publisher id.
     * @return array<string, mixed>|null Record, or null when unknown.
     */
    private function findPublisher(string $id): ?array
    {
        $st = $this->db->prepare(
            'SELECT proto, udp_port, candidates, last_seen FROM redp2p_publishers WHERE id = ?'
        );
        $st->execute([$id]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * Deletes publisher records past the TTL.
     *
     * @return void
     */
    private function evictStale(): void
    {
        $st = $this->db->prepare('DELETE FROM redp2p_publishers WHERE last_seen < ?');
        $st->execute([time() - $this->ttl]);
    }

    /**
     * Deletes pending punch calls past the TTL.
     *
     * @return void
     */
    private function evictPending(): void
    {
        $st = $this->db->prepare('DELETE FROM redp2p_pending_calls WHERE ts < ?');
        $st->execute([time() - self::PENDING_TTL_S]);
    }

    /**
     * Creates the index tables when missing.
     *
     * @return void
     */
    private function ensureSchema(): void
    {
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS redp2p_publishers ('
            . ' id VARCHAR(63) NOT NULL PRIMARY KEY'
            . ', key CHAR(16) NOT NULL'
            . ', proto INTEGER NOT NULL'
            . ', udp_port INTEGER NOT NULL'
            . ', candidates TEXT NULL'
            . ', last_seen INTEGER NOT NULL'
            . ')'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS redp2p_pending_calls ('
            . ' id VARCHAR(32) NOT NULL PRIMARY KEY'
            . ', self_id VARCHAR(63) NOT NULL'
            . ', target_id VARCHAR(63) NOT NULL'
            . ', session VARCHAR(63) NOT NULL'
            . ', candidates TEXT NULL'
            . ', ts INTEGER NOT NULL'
            . ')'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS redp2p_meta ('
            . ' name VARCHAR(32) NOT NULL PRIMARY KEY'
            . ', value TEXT NULL'
            . ')'
        );
        try {
            $this->db->exec(
                'CREATE INDEX IF NOT EXISTS redp2p_pending_calls_target ON redp2p_pending_calls (target_id)'
            );
        } catch (\PDOException $e) {
        }
    }

    /**
     * Requires a valid id field on the request.
     *
     * @param \stdClass $o Parsed request object.
     * @param string $field Field name holding the id.
     * @return array{int, string|null} [1, id], [0, null] when missing,
     *   [-1, null] when invalid.
     */
    private function requireId(\stdClass $o, string $field): array
    {
        if (!$this->hasString($o, $field)) {
            return [0, null];
        }
        $id = $o->$field;
        if (!$this->isValidId($id)) {
            return [-1, null];
        }
        return [1, $id];
    }

    /**
     * Requires a hex token of the exact length.
     *
     * @param \stdClass $o Parsed request object.
     * @param string $field Field name holding the token.
     * @param int $len Expected token length.
     * @return string|null Token, or null when absent or invalid.
     */
    private function requireHex(\stdClass $o, string $field, int $len): ?string
    {
        if (!$this->hasString($o, $field)) {
            return null;
        }
        $value = $o->$field;
        return $this->isHexToken($value, $len) ? $value : null;
    }

    /**
     * Requires the proto and udp_port fields.
     *
     * @param \stdClass $o Parsed request object.
     * @return array{int|null, int|null} [proto, udp_port], or [null, null] when
     *   absent or invalid.
     */
    private function requireProtoPort(\stdClass $o): array
    {
        if (!property_exists($o, 'proto') || !property_exists($o, 'udp_port')) {
            return [null, null];
        }
        $proto = $o->proto;
        $udpPort = $o->udp_port;
        if (!is_int($proto) && !is_float($proto)) {
            return [null, null];
        }
        if (!is_int($udpPort) && !is_float($udpPort)) {
            return [null, null];
        }
        $proto = (float)$proto;
        $udpPort = (float)$udpPort;
        if ($proto !== 1.0 && $proto !== 2.0) {
            return [null, null];
        }
        if ($udpPort < 1.0 || $udpPort > 65535.0) {
            return [null, null];
        }
        return [(int)$proto, (int)$udpPort];
    }

    /**
     * Parses and validates the candidate list.
     *
     * @param \stdClass $o Parsed request object.
     * @param string $field Field name holding the candidate list.
     * @return array{
     *     bool,
     *     array<int, array{type: string, addr: string, port: int}>
     * } [ok, candidates], [true, []] when absent.
     */
    private function parseCandidates(\stdClass $o, string $field): array
    {
        if (!property_exists($o, $field)) {
            return [true, []];
        }
        $value = $o->$field;
        if (!is_array($value)) {
            return [true, []];
        }
        if (count($value) > self::CANDIDATES_MAX) {
            return [false, []];
        }
        $out = [];
        foreach ($value as $item) {
            if (!($item instanceof \stdClass)) {
                return [false, []];
            }
            $type = $this->getString($item, 'type');
            $addr = $this->getString($item, 'addr');
            if ($type === null || $addr === null) {
                return [false, []];
            }
            if (strlen($addr) > self::ADDR_MAX) {
                return [false, []];
            }
            if (!in_array($type, self::CANDIDATE_TYPES, true)) {
                return [false, []];
            }
            if (!filter_var($addr, FILTER_VALIDATE_IP)) {
                return [false, []];
            }
            if (!property_exists($item, 'port')) {
                return [false, []];
            }
            $port = $item->port;
            if (!is_int($port) && !is_float($port)) {
                return [false, []];
            }
            $port = (float)$port;
            if ($port < 1.0 || $port > 65535.0) {
                return [false, []];
            }
            $out[] = ['type' => $type, 'addr' => $addr, 'port' => (int)$port];
        }
        return [true, $out];
    }

    /**
     * Verifies a proof-of-work solution against the difficulty target.
     *
     * @param string $pass Shared or VIP password.
     * @param string $nonce Challenge nonce in hex.
     * @param string $id Publisher id.
     * @param string $solution Client solution in hex.
     * @param string $proof Expected HMAC proof in hex.
     * @return bool True when the proof matches and passes the difficulty.
     */
    private function verifyPow(string $pass, string $nonce, string $id, string $solution, string $proof): bool
    {
        $digest = hash_hmac('sha256', $nonce . $id . $solution, $pass, true);
        if (!hash_equals(bin2hex($digest), $proof)) {
            return false;
        }
        return $this->leadingZeroBits($digest) >= $this->pow;
    }

    /**
     * Counts leading zero bits of a binary string.
     *
     * @param string $bin Raw binary digest.
     * @return int Leading zero bit count.
     */
    private function leadingZeroBits(string $bin): int
    {
        $total = 0;
        $len = strlen($bin);
        for ($i = 0; $i < $len; $i++) {
            if ($bin[$i] === "\x00") {
                $total += 8;
                continue;
            }
            $byte = ord($bin[$i]);
            while (($byte & 0x80) === 0) {
                $total++;
                $byte <<= 1;
            }
            break;
        }
        return $total;
    }

    /**
     * Returns the password for a publisher id.
     *
     * @param string $id Publisher id.
     * @return string VIP password when reserved, else the shared password.
     */
    private function getPass(string $id): string
    {
        return $this->vips[$id] ?? $this->pass;
    }

    /**
     * Decodes a stored candidate JSON list.
     *
     * @param string $text Stored JSON.
     * @return array<int, array{type: string, addr: string, port: int}>
     *   Candidates, or [] when invalid.
     */
    private function decodeCandidates(string $text): array
    {
        $decoded = json_decode($text, true);
        return is_array($decoded) ? array_values($decoded) : [];
    }

    /**
     * Checks a publisher id token.
     *
     * @param string $id Id token.
     * @return bool True when alphanumeric and at most ID_MAX.
     */
    private function isValidId(string $id): bool
    {
        return $id !== '' && strlen($id) <= self::ID_MAX && ctype_alnum($id);
    }

    /**
     * Checks a session token.
     *
     * @param string $token Session token.
     * @return bool True when alphanumeric and at most SESSION_MAX.
     */
    private function isSessionToken(string $token): bool
    {
        return $token !== '' && strlen($token) <= self::SESSION_MAX && ctype_alnum($token);
    }

    /**
     * Checks a hex token of the exact length.
     *
     * @param string $token Hex token.
     * @param int $len Expected length.
     * @return bool True when the token has exactly $len hex digits.
     */
    private function isHexToken(string $token, int $len): bool
    {
        return strlen($token) === $len && ctype_xdigit($token);
    }

    /**
     * Checks a shared password token.
     *
     * @param string $pass Password token.
     * @return bool True when non-empty, short, and printable.
     */
    private function isValidPassToken(string $pass): bool
    {
        if ($pass === '' || strlen($pass) > self::PASS_MAX) {
            return false;
        }
        return preg_match('/^[A-Za-z0-9._\-+=,:@%\/]+$/', $pass) === 1;
    }

    /**
     * Checks that a field exists and holds a string.
     *
     * @param \stdClass $o Parsed request object.
     * @param string $field Field name.
     * @return bool True when the field holds a string.
     */
    private function hasString(\stdClass $o, string $field): bool
    {
        return property_exists($o, $field) && is_string($o->$field);
    }

    /**
     * Returns a string field, or null when absent.
     *
     * @param \stdClass $o Parsed request object.
     * @param string $field Field name.
     * @return string|null Field value, or null when absent.
     */
    private function getString(\stdClass $o, string $field): ?string
    {
        return $this->hasString($o, $field) ? $o->$field : null;
    }

    /**
     * Checks headers for a name, case-insensitively.
     *
     * @param array<string, string> $headers Header map.
     * @param string $name Header name.
     * @return bool True when present.
     */
    private function hasHeader(array $headers, string $name): bool
    {
        $name = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower((string)$key) === $name) {
                return true;
            }
        }
        return false;
    }

    /**
     * Detects duplicate keys at the top level of a JSON body.
     *
     * @param string $json Raw JSON body.
     * @return bool True when a duplicate top-level key exists.
     */
    private function hasDuplicateTopKeys(string $json): bool
    {
        $keys = [];
        $len = strlen($json);
        $depth = 0;
        $i = 0;
        while ($i < $len) {
            $c = $json[$i];
            if ($c === '"') {
                $start = $i + 1;
                $j = $i + 1;
                while ($j < $len) {
                    if ($json[$j] === '\\') {
                        $j += 2;
                        continue;
                    }
                    if ($json[$j] === '"') {
                        break;
                    }
                    $j++;
                }
                $k = $j + 1;
                while ($k < $len && ($json[$k] === ' ' || $json[$k] === "\t")) {
                    $k++;
                }
                if ($depth === 1 && $k < $len && $json[$k] === ':') {
                    $key = json_decode('"' . substr($json, $start, $j - $start) . '"');
                    if (!is_string($key)) {
                        $key = substr($json, $start, $j - $start);
                    }
                    if (isset($keys[$key])) {
                        return true;
                    }
                    $keys[$key] = 1;
                }
                $i = $j + 1;
                continue;
            }
            if ($c === '{' || $c === '[') {
                $depth++;
            } elseif ($c === '}' || $c === ']') {
                $depth--;
            }
            $i++;
        }
        return false;
    }

    /**
     * Builds a JSON success response.
     *
     * @param array<string, mixed> $fields Extra payload fields.
     * @param bool $okFirst Place 'ok' before the fields.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function jsonOk(array $fields = [], bool $okFirst = true): array
    {
        $data = $okFirst
            ? array_merge(['ok' => true], $fields)
            : array_merge($fields, ['ok' => true]);
        return $this->response(200, 'OK', 'application/json', json_encode($data));
    }

    /**
     * Builds a JSON error response.
     *
     * @param int $status HTTP status code.
     * @param string $code Machine-readable error code.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function jsonError(int $status, string $code): array
    {
        $body = '{"ok":false,"error":"' . $code . '"}';
        return $this->response($status, $this->statusReason($status), 'application/json', $body);
    }

    /**
     * Builds a plain-text error response.
     *
     * @param int $status HTTP status code.
     * @param string $reason HTTP reason phrase.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function httpError(int $status, string $reason): array
    {
        return $this->response($status, $reason, 'text/plain', self::ERROR_MALFORMED);
    }

    /**
     * Builds a full HTTP response array.
     *
     * @param int $status HTTP status code.
     * @param string $reason HTTP reason phrase.
     * @param string $contentType Response Content-Type.
     * @param string $body Response body.
     * @return array{
     *     status: int,
     *     reason: string,
     *     headers: array<string, string>,
     *     body: string
     * }
     */
    private function response(int $status, string $reason, string $contentType, string $body): array
    {
        return [
            'status' => $status,
            'reason' => $reason,
            'headers' => [
                'Content-Type' => $contentType,
                'Content-Length' => (string)strlen($body),
                'Connection' => 'close',
            ],
            'body' => $body,
        ];
    }

    /**
     * Maps an HTTP status code to its reason phrase.
     *
     * @param int $status HTTP status code.
     * @return string Reason phrase, or 'Error' when unknown.
     */
    private function statusReason(int $status): string
    {
        return match ($status) {
            200 => 'OK',
            400 => 'Bad Request',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            413 => 'Payload Too Large',
            500 => 'Internal Server Error',
            501 => 'Not Implemented',
            503 => 'Service Unavailable',
            default => 'Error',
        };
    }
}
