/**
 * librp2p.c - RedP2P.
 * Summary: Core shared library. TCP rendezvous control and direct peer transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "librp2p.h"
#include "ikcp.h"
#include "monocypher.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdatomic.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <io.h>
#  include <direct.h>
#  include <windows.h>
#  include <bcrypt.h>
#  include <process.h>
#  ifndef read
#  define read(fd,buf,sz)  _read(fd,buf,sz)
#  endif
#  ifndef write
#  define write(fd,buf,sz) _write(fd,buf,sz)
#  endif
typedef SOCKET rp2p_fd_t;
#  define RP2P_FD_INVALID  INVALID_SOCKET
#  define RP2P_FD_CLOSE(f) closesocket(f)
#  define RP2P_ISERR(f)    ((f) == INVALID_SOCKET)
#  define RP2P_LASTERR()   ((int)WSAGetLastError())
#  define RP2P_EWOULD      WSAEWOULDBLOCK
#else
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/wait.h>
#  include <sys/stat.h>
#  include <pthread.h>
#  include <sys/types.h>
typedef int rp2p_fd_t;
#  define RP2P_FD_INVALID  (-1)
#  define RP2P_FD_CLOSE(f) close(f)
#  define RP2P_ISERR(f)    ((f) < 0)
#  define RP2P_LASTERR()   errno
#  define RP2P_EWOULD      EAGAIN
#  define INVALID_SOCKET     (-1)
#  define SOCKET_ERROR       (-1)
#endif

#define RP2P_SWEEP_MAX   1024
#define RP2P_POW_MAX      32
#define RP2P_PORT_MIN      1
#define RP2P_PORT_MAX      65535
#define RP2P_POW_CHALLENGE_TTL_S 120

/**
 * Parses one strict unsigned decimal integer.
 * Summary: Rejects NULL, empty, leading/trailing garbage, signs, and overflow.
 * @param text    Input text to parse.
 * @param min     Inclusive lower bound.
 * @param max     Inclusive upper bound.
 * @param out     Output parsed value.
 * @return 1 on valid parse within bounds, 0 otherwise.
 */
static int rp2p_parse_u(const char *text, long min, long max, long *out) {
    unsigned long value;
    unsigned long limit;
    size_t i;

    if (!text || !text[0] || !out || min < 0 || max < min) return 0;
    value = 0;
    limit = (unsigned long)max;
    for (i = 0; text[i] != '\0'; i++) {
        unsigned long digit;

        if (text[i] < '0' || text[i] > '9') return 0;
        digit = (unsigned long)(text[i] - '0');
        if (digit > limit) return 0;
        if (value > (limit - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    if (value < (unsigned long)min) return 0;
    *out = (long)value;
    return 1;
}

/**
 * Parses one strict environment numeric option.
 * Summary: Applies the same validation as CLI parsing.
 * @param text    Input text to parse.
 * @param min     Inclusive lower bound.
 * @param max     Inclusive upper bound.
 * @param out     Output parsed value.
 * @return 1 on valid parse within bounds, 0 otherwise.
 */
static int rp2p_parse_env(const char *text, long min, long max, long *out) {
    if (!text || text[0] == '\0') return 0;
    return rp2p_parse_u(text, min, max, out);
}

/**
 * Parses one strict unsigned decimal size value.
 * @param text Input text to parse.
 * @param out Output parsed value.
 * @return 1 on success, 0 on invalid input or overflow.
 */
static int rp2p_parse_size(const char *text, size_t *out) {
    size_t value;
    size_t i;

    if (!text || !text[0] || !out) return 0;
    value = 0;
    for (i = 0; text[i] != '\0'; i++) {
        size_t digit;

        if (text[i] < '0' || text[i] > '9') return 0;
        digit = (size_t)(text[i] - '0');
        if (value > (SIZE_MAX - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    *out = value;
    return 1;
}

#define RP2P_ETIMEOUT_SEC     15
#define RP2P_DISCONNECT_S     10
#define RP2P_KEEPALIVE_S       3
#define RP2P_PUNCH_ATTEMPTS   10
#define RP2P_PUNCH_INTERVAL_MS 200
#define RP2P_CANDIDATES_MAX       16
#define RP2P_MAX_PENDING_PUNCHES  32
#define RP2P_POW_CHALLENGES_MAX 256
#define RP2P_STREAM_MAGIC             0x50434b52u
#define RP2P_STREAM_VERSION           2u
#define RP2P_STREAM_SESSION_ID_SZ     16
#define RP2P_STREAM_ENVELOPE_SZ       24
#define RP2P_STREAM_KCP_MTU           1400
#define RP2P_STREAM_MAX_FRAME         (RP2P_STREAM_ENVELOPE_SZ + RP2P_STREAM_KCP_MTU)
#define RP2P_STREAM_SEND_WINDOW       64
#define RP2P_STREAM_RECV_WINDOW       128
#define RP2P_STREAM_KCP_INTERVAL_MS   20
#define RP2P_STREAM_KCP_FAST_RESEND   2
#define RP2P_STREAM_MAX_WAIT_SEND     128
#define RP2P_STREAM_HELLO_MS          500
#define RP2P_STREAM_CLOSE_MS          500
#define RP2P_LINK_MTU                 1500
#define RP2P_IPV4_UDP_OVERHEAD        (20 + 8)
#define RP2P_IPV6_UDP_OVERHEAD        (40 + 8)
#define RP2P_IPV4_LOOPBACK             0x7f000001u
#define RP2P_MAX_DATAGRAM_V4          (RP2P_LINK_MTU - RP2P_IPV4_UDP_OVERHEAD)
#define RP2P_MAX_DATAGRAM_V6          (RP2P_LINK_MTU - RP2P_IPV6_UDP_OVERHEAD)
#define RP2P_PUNCH_DIRECT_ROUNDS 3
#define RP2P_PUNCH_DIRECT_WAIT_MS 500
#define RP2P_PUNCH_SWEEP_WAIT_MS 20
#define RP2P_PUNCH_TOTAL_MS 4000
#define RP2P_CTRL_LINE_MAX     1024
#define RP2P_CTRL_FIELD_MAX     256
#define RP2P_CTRL_SESSION_MAX    63
#define RP2P_CTRTOK_HELLO        "RP2P_CTRTOK_HELLO RP2P/1"
#define RP2P_CTRTOK_HELLO_OK     "RP2P_CTRTOK_HELLO_OK"
#define RP2P_CTRTOK_ERROR_VERSION_MISMATCH "RP2P_CTRTOK_ERROR:version mismatch"

#define RP2P_CTRTOK_REGISTER     "RP2P_CTRTOK_REGISTER:"
#define RP2P_CTRTOK_DEREGISTER   "RP2P_CTRTOK_DEREGISTER:"
#define RP2P_CTRTOK_LOOKUP       "RP2P_CTRTOK_LOOKUP:"
#define RP2P_CTRTOK_LIST_PUBLISHERS "RP2P_CTRTOK_LIST_PUBLISHERS"
#define RP2P_CTRTOK_PUBLISHER    "RP2P_CTRTOK_PUBLISHER:"
#define RP2P_CTRTOK_END          "RP2P_CTRTOK_END"
#define RP2P_CTRTOK_CHALLENGE    "RP2P_CTRTOK_CHALLENGE:"
#define RP2P_CTRTOK_OK           "RP2P_CTRTOK_OK"
#define RP2P_CTRTOK_OK_KEY       "RP2P_CTRTOK_OK:RP2P_CTRTOK_KEY:"
#define RP2P_CTRTOK_SOLUTION     "RP2P_CTRTOK_SOLUTION:"
#define RP2P_CTRTOK_PROOF        "RP2P_CTRTOK_PROOF:"
#define RP2P_CTRTOK_KEY          "RP2P_CTRTOK_KEY:"
#define RP2P_CTRTOK_AUTH_FAILED  "RP2P_CTRTOK_AUTH_FAILED"
#define RP2P_CTRTOK_NOT_FOUND    "RP2P_CTRTOK_NOT_FOUND"
#define RP2P_CTRTOK_PUNCH_REQ2   "RP2P_CTRTOK_PUNCH_REQ2:"
#define RP2P_CTRTOK_PUNCH_ACK2   "RP2P_CTRTOK_PUNCH_ACK2:"
#define RP2P_CTRTOK_PUNCH_CALL2  "RP2P_CTRTOK_PUNCH_CALL2:"
#define RP2P_CTRTOK_PUNCH_OK2    "RP2P_CTRTOK_PUNCH_OK2:"
#define RP2P_CTRTOK_CAND         "RP2P_CTRTOK_CAND:"
#define RP2P_CTRTOK_PUNCH        "RP2P_CTRTOK_PUNCH:"
#define RP2P_CTRTOK_PUNCH_SERVER "RP2P_CTRTOK_PUNCH:server"
#define RP2P_CTRTOK_PUNCH_PING   "RP2P_CTRTOK_PUNCH_PING:"
#define RP2P_CTRTOK_PUNCH_PONG   "RP2P_CTRTOK_PUNCH_PONG:"
#define RP2P_CTRTOK_KA           "RP2P_CTRTOK_KA:"

#define RP2P_CTRCMD_REGISTER     "RP2P_CTRTOK_REGISTER"
#define RP2P_CTRCMD_DEREGISTER   "RP2P_CTRTOK_DEREGISTER"
#define RP2P_CTRCMD_LOOKUP       "RP2P_CTRTOK_LOOKUP"
#define RP2P_CTRCMD_LIST_PUBLISHERS "RP2P_CTRTOK_LIST_PUBLISHERS"
#define RP2P_CTRCMD_PUNCH_REQ2   "RP2P_CTRTOK_PUNCH_REQ2"
#define RP2P_CTRCMD_PUNCH_ACK2   "RP2P_CTRTOK_PUNCH_ACK2"

#define RP2P_CTRTOK_ERROR_MALFORMED "RP2P_CTRTOK_ERROR:malformed"
#define RP2P_CTRTOK_ERROR_INVALID_ID "RP2P_CTRTOK_ERROR:invalid id"
#define RP2P_CTRTOK_ERROR_PEER_TABLE_FULL "RP2P_CTRTOK_ERROR:peer table full"
#define RP2P_CTRTOK_ERROR_NOT_REGISTERED "RP2P_CTRTOK_ERROR:not registered"
#define RP2P_CTRTOK_ERROR_BUSY "RP2P_CTRTOK_ERROR:busy"
#define RP2P_CTRTOK_ERROR_RANDOM "RP2P_CTRTOK_ERROR:random"
#define RP2P_CTRTOK_ERROR_OFFLINE "RP2P_CTRTOK_ERROR:offline"
#define RP2P_CTRTOK_ERROR_INVALID_KEY "RP2P_CTRTOK_ERROR:invalid key"
#define RP2P_CTRTOK_ERROR_UNKNOWN_COMMAND "RP2P_CTRTOK_ERROR:unknown command"

#define RP2P_STREAM_TYPE_HELLO      1u
#define RP2P_STREAM_TYPE_HELLO_ACK  2u
#define RP2P_STREAM_TYPE_KCP        3u
#define RP2P_STREAM_TYPE_CLOSE      4u
#define RP2P_STREAM_TYPE_CLOSE_ACK  5u
#define RP2P_STREAM_TYPE_RESET      6u
#define RP2P_STREAM_TYPE_KEEPALIVE  7u
#define RP2P_STREAM_ROLE_INITIATOR 1u
#define RP2P_STREAM_ROLE_RESPONDER 2u

typedef struct {
    uint8_t type;
    uint8_t role;
    uint8_t protocol;
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
    const unsigned char *payload;
    size_t payload_len;
} rp2p_stream_envelope_t;

typedef struct {
    rp2p_t *ctx;
    rp2p_fd_t fd;
    struct sockaddr_storage peer_addr;
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
    uint8_t role;
    uint8_t protocol;
    int send_error;
    int fault_pending_used;
    size_t fault_pending_len;
    unsigned char fault_pending[RP2P_STREAM_MAX_FRAME];
} rp2p_stream_adapter_t;

#ifndef RP2P_BUILD_VERSION
#define RP2P_BUILD_VERSION 0
#endif

_Static_assert(RP2P_STREAM_MAX_FRAME <= RP2P_MAX_DATAGRAM_V4,
    "Stream frame exceeds IPv4 datagram limit");
_Static_assert(RP2P_STREAM_MAX_FRAME <= RP2P_MAX_DATAGRAM_V6,
    "Stream frame exceeds IPv6 datagram limit");

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t rp2p_version(void) {
    return (uint64_t)RP2P_BUILD_VERSION;
}

typedef struct {
    int enabled;
    int initiator;
    int ready;
    int hello_sent;
    int reset_sent;
    int reset_received;
    int local_eof;
    int close_sent;
    int close_acked;
    int remote_close;
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
    char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    uint8_t transport_protocol;
    ikcpcb *kcp;
    rp2p_stream_adapter_t *adapter;
    uint64_t last_tx_ms;
    uint64_t last_hello_ms;
    uint64_t last_close_ms;
    uint64_t last_keepalive_ms;
    uint32_t next_update_ms;
} rp2p_stream_state_t;

#ifdef _WIN32
static SRWLOCK g_key_mutex = SRWLOCK_INIT;
#else
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static int rp2p_is_stop_requested(rp2p_t *ctx);
static int rp2p_fdset_add(rp2p_fd_t fd, fd_set *set, int *maxfd);
static void rp2p_set_error(rp2p_t *ctx, const char *fmt, ...);
static int rp2p_sockaddr_equal(const struct sockaddr_storage *a,
    const struct sockaddr_storage *b);
static int rp2p_sendto_addr(rp2p_fd_t fd, const void *buf, size_t len,
    const struct sockaddr_storage *addr);

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buf[64];
} rp2p_sha256_t;

static const uint32_t rp2p_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define RP2P_SHA256_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define RP2P_SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define RP2P_SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define RP2P_SHA256_S0(x) (RP2P_SHA256_ROR(x, 2) ^ RP2P_SHA256_ROR(x, 13) ^ RP2P_SHA256_ROR(x, 22))
#define RP2P_SHA256_S1(x) (RP2P_SHA256_ROR(x, 6) ^ RP2P_SHA256_ROR(x, 11) ^ RP2P_SHA256_ROR(x, 25))
#define RP2P_SHA256_s0(x) (RP2P_SHA256_ROR(x, 7) ^ RP2P_SHA256_ROR(x, 18) ^ ((x) >> 3))
#define RP2P_SHA256_s1(x) (RP2P_SHA256_ROR(x, 17) ^ RP2P_SHA256_ROR(x, 19) ^ ((x) >> 10))

/**
 * Sha256 transform.
 * @return Status code.
 */
static void rp2p_sha256_transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int t;
    for (t = 0; t < 16; t++)
        W[t] = ((uint32_t)block[t*4]) << 24 |
            ((uint32_t)block[t*4+1]) << 16 |
            ((uint32_t)block[t*4+2]) << 8 |
            block[t*4+3];
    for (t = 16; t < 64; t++)
        W[t] = RP2P_SHA256_s1(W[t-2]) + W[t-7] + RP2P_SHA256_s0(W[t-15]) + W[t-16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (t = 0; t < 64; t++) {
        T1 = h + RP2P_SHA256_S1(e) + RP2P_SHA256_CH(e, f, g) + rp2p_sha256_k[t] + W[t];
        T2 = RP2P_SHA256_S0(a) + RP2P_SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    crypto_wipe(W, sizeof(W));
    crypto_wipe(&a, sizeof(a));
    crypto_wipe(&b, sizeof(b));
    crypto_wipe(&c, sizeof(c));
    crypto_wipe(&d, sizeof(d));
    crypto_wipe(&e, sizeof(e));
    crypto_wipe(&f, sizeof(f));
    crypto_wipe(&g, sizeof(g));
    crypto_wipe(&h, sizeof(h));
    crypto_wipe(&T1, sizeof(T1));
    crypto_wipe(&T2, sizeof(T2));
}

/**
 * Sha256 init.
 * @return Status code.
 */
static void rp2p_sha256_init(rp2p_sha256_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

/**
 * Sha256 update.
 * @return Status code.
 */
static void rp2p_sha256_update(rp2p_sha256_t *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count & 63] = data[i];
        ctx->count++;
        if ((ctx->count & 63) == 0)
            rp2p_sha256_transform(ctx->state, ctx->buf);
    }
}

/**
 * Sha256 final.
 * @return Status code.
 */
static void rp2p_sha256_final(rp2p_sha256_t *ctx, unsigned char hash[32]) {
    uint64_t bits = ctx->count * 8;
    int idx = (int)(ctx->count & 63);
    int i;

    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buf[idx++] = 0;
        rp2p_sha256_transform(ctx->state, ctx->buf);
        idx = 0;
    }
    while (idx < 56) ctx->buf[idx++] = 0;
    ctx->buf[56] = (unsigned char)(bits >> 56);
    ctx->buf[57] = (unsigned char)(bits >> 48);
    ctx->buf[58] = (unsigned char)(bits >> 40);
    ctx->buf[59] = (unsigned char)(bits >> 32);
    ctx->buf[60] = (unsigned char)(bits >> 24);
    ctx->buf[61] = (unsigned char)(bits >> 16);
    ctx->buf[62] = (unsigned char)(bits >> 8);
    ctx->buf[63] = (unsigned char)(bits);
    rp2p_sha256_transform(ctx->state, ctx->buf);
    for (i = 0; i < 8; i++) {
        hash[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (unsigned char)ctx->state[i];
    }
}

typedef struct {
    char nonce_hex[17];
    char id[RP2P_ID_MAX + 1];
    struct sockaddr_storage addr;
    uint64_t issued_at;
    uint64_t expires_at;
} rp2p_pow_challenge_t;

/**
 * Computes one HMAC-SHA256 digest.
 * @param key     Shared password material.
 * @param msg     Input message bytes.
 * @param msg_len Input message length.
 * @param hash    Output digest buffer.
 * @return None.
 */
static void rp2p_hmac_sha256(const char *key, const unsigned char *msg,
    size_t msg_len, unsigned char hash[32])
{
    rp2p_sha256_t ctx;
    unsigned char key_block[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[32];
    size_t key_len;
    size_t i;

    memset(key_block, 0, sizeof(key_block));
    key_len = key ? strlen(key) : 0;
    if (key_len > sizeof(key_block)) {
        rp2p_sha256_init(&ctx);
        rp2p_sha256_update(&ctx, (const unsigned char *)key, key_len);
        rp2p_sha256_final(&ctx, key_block);
    } else if (key_len > 0) {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < sizeof(key_block); i++) {
        ipad[i] = (unsigned char)(key_block[i] ^ 0x36);
        opad[i] = (unsigned char)(key_block[i] ^ 0x5c);
    }
    rp2p_sha256_init(&ctx);
    rp2p_sha256_update(&ctx, ipad, sizeof(ipad));
    rp2p_sha256_update(&ctx, msg, msg_len);
    rp2p_sha256_final(&ctx, inner);
    rp2p_sha256_init(&ctx);
    rp2p_sha256_update(&ctx, opad, sizeof(opad));
    rp2p_sha256_update(&ctx, inner, sizeof(inner));
    rp2p_sha256_final(&ctx, hash);
}

/**
 * Computes one register proof digest.
 * @param pass         Shared password material.
 * @param nonce_hex    Challenge nonce in hex.
 * @param id           Service identifier.
 * @param solution_hex Candidate solution in hex.
 * @param hash         Output digest buffer.
 * @return None.
 */
static void rp2p_hash_register_once(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, unsigned char hash[32])
{
    unsigned char msg[RP2P_ID_MAX + 33];
    size_t nonce_len;
    size_t id_len;
    size_t solution_len;
    size_t pos;

    nonce_len = strlen(nonce_hex);
    id_len = strlen(id);
    solution_len = strlen(solution_hex);
    pos = 0;
    if (nonce_len > sizeof(msg) - pos) nonce_len = sizeof(msg) - pos;
    memcpy(msg + pos, nonce_hex, nonce_len);
    pos += nonce_len;
    if (id_len > sizeof(msg) - pos) id_len = sizeof(msg) - pos;
    memcpy(msg + pos, id, id_len);
    pos += id_len;
    if (solution_len > sizeof(msg) - pos) solution_len = sizeof(msg) - pos;
    memcpy(msg + pos, solution_hex, solution_len);
    pos += solution_len;
    rp2p_hmac_sha256(pass ? pass : "", msg, pos, hash);
}

/**
 * Encodes a digest as lowercase hex.
 * @param hash     Input digest bytes.
 * @param hash_len Digest length in bytes.
 * @param out      Output hex buffer.
 * @param out_cap  Output buffer capacity.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_hex_encode(const unsigned char *hash, size_t hash_len,
    char *out, size_t out_cap)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!hash || !out || out_cap < hash_len * 2 + 1) return 0;
    for (i = 0; i < hash_len; i++) {
        out[i * 2] = hex[(hash[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    out[hash_len * 2] = '\0';
    return 1;
}

/**
 * Counts leading zero bits in one digest.
 * @param hash Input digest bytes.
 * @return Count of leading zero bits.
 */
static int rp2p_count_leading_zero_bits(const unsigned char hash[32]);

/**
 * Solves one register proof challenge.
 * @param pass         Shared password material.
 * @param nonce_hex    Challenge nonce in hex.
 * @param id           Service identifier.
 * @param bits         Difficulty target.
 * @param solution_hex Output solution buffer.
 * @param sol_cap      Output solution capacity.
 * @param proof_hex    Output proof buffer.
 * @param proof_cap    Output proof capacity.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_solve_register_pow(rp2p_t *ctx, const char *pass, const char *nonce_hex,
    const char *id, int bits, char *solution_hex, size_t sol_cap,
    char *proof_hex, size_t proof_cap)
{
    uint32_t counter;
    unsigned char hash[32];
    char buf[17];

    if (sol_cap < sizeof(buf) || proof_cap < 65) return 0;
    counter = 0;
    for (;;) {
        snprintf(buf, sizeof(buf), "%08x", counter);
        rp2p_hash_register_once(pass, nonce_hex, id, buf, hash);
        if (rp2p_count_leading_zero_bits(hash) >= bits) {
            memcpy(solution_hex, buf, sizeof(buf));
            return rp2p_hex_encode(hash, sizeof(hash), proof_hex, proof_cap);
        }
        counter++;
        if (counter == 0) break;
        if ((counter & 0xfffff) == 0 && rp2p_is_stop_requested(ctx)) break;
    }
    return 0;
}

/**
 * Verifies one register proof challenge.
 * @param pass         Shared password material.
 * @param nonce_hex    Challenge nonce in hex.
 * @param id           Service identifier.
 * @param solution_hex Candidate solution in hex.
 * @param proof_hex    Candidate proof in hex.
 * @param bits         Difficulty target.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_verify_register_pow(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, const char *proof_hex, int bits)
{
    unsigned char hash[32];
    char expected[65];
    int diff, k;

    if (!proof_hex || strlen(proof_hex) != 64) return 0;
    rp2p_hash_register_once(pass, nonce_hex, id, solution_hex, hash);
    if (!rp2p_hex_encode(hash, sizeof(hash), expected, sizeof(expected))) return 0;
    diff = 0;
    for (k = 0; k < 64; k++)
        diff |= (proof_hex[k] ^ expected[k]);
    if (diff != 0) return 0;
    return rp2p_count_leading_zero_bits(hash) >= bits;
}

/**
 * Counts leading zero bits in one digest.
 * @param hash Input digest bytes.
 * @return Count of leading zero bits.
 */
static int rp2p_count_leading_zero_bits(const unsigned char hash[32]) {
    int total = 0, i;
    for (i = 0; i < 32; i++) {
        if (hash[i] == 0) {
            total += 8;
        } else {
            unsigned char b = hash[i];
            int j;
            for (j = 0; j < 8; j++) {
                if ((b & 0x80) == 0) total++;
                else break;
                b <<= 1;
            }
            break;
        }
    }
    return total;
}

typedef struct {
    rp2p_fd_t fd;
    char buf[RP2P_BUF];
    int buf_len;
    char id[RP2P_ID_MAX + 1];
    int registered;
    int hello_ok;
} rp2p_tcp_conn_t;

typedef struct {
    char id[RP2P_ID_MAX + 1];
    char pass[RP2P_PASS_MAX + 1];
} rp2p_vip_entry_t;

/**
 * Pending punch.
 * Summary: Tracks a two-round punch request awaiting ACK2 from publisher.
 */
typedef struct {
    char self_id[RP2P_ID_MAX + 1];
    char target_id[RP2P_ID_MAX + 1];
    char sess_id[64];
    rp2p_fd_t consumer_fd;
    uint64_t ts;
} rp2p_pending_punch_t;

struct rp2p {
    rp2p_peer_t *peers;
    size_t n_peers;
    size_t peers_alloc;
    size_t n_peers_cap;
    size_t nonvip_cap;
    int seats_set;
    rp2p_tcp_conn_t *conns;
    int n_conns;
    int conns_cap;
    rp2p_vip_entry_t *vips;
    size_t n_vips;
    size_t vips_cap;
    char key[RP2P_KEY_STR_SZ];
    char pass[RP2P_PASS_MAX + 1];
    int pow_bits;
    unsigned short bind_port;
    int explicit_port;
    int proto;
    int sweep;
    rp2p_pow_challenge_t pow_challenges[RP2P_POW_CHALLENGES_MAX];
    int n_pow_challenges;
#ifdef _WIN32
    CRITICAL_SECTION mutex;
#else
    pthread_mutex_t mutex;
#endif
    char stun_url[512];
    char err_buf[256];
    int fault_drop_counter;
    int fault_reorder_counter;
    rp2p_pending_punch_t pending_punches[RP2P_MAX_PENDING_PUNCHES];
    int n_pending_punches;
    _Atomic int stop_requested;
};

/**
 * Returns whether one context requested stop.
 * @param ctx Context to inspect.
 * @return 1 when stop was requested, 0 otherwise.
 */
static int rp2p_is_stop_requested(rp2p_t *ctx) {
    return ctx && atomic_load(&ctx->stop_requested);
}

typedef struct rp2p_udp_consumer_session {
    rp2p_fd_t fd;
    rp2p_fd_t tcp_fd;
    struct sockaddr_storage client_addr;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    rp2p_stream_state_t stream;
} rp2p_udp_consumer_session_t;

typedef struct {
    rp2p_t *ctx;
    const char *index_host;
    const char *self_id;
    const char *target_id;
    const char *udp_any_host;
    unsigned short index_port;
    rp2p_fd_t local_fd;
    rp2p_fd_t tcp_listen_fd;
    rp2p_udp_consumer_session_t *sessions;
    int n_sessions;
    int cap_sessions;
    int platform_initialized;
} rp2p_consumer_runtime_t;

typedef struct rp2p_udp_server_session {
    rp2p_fd_t backend_fd;
    rp2p_fd_t tcp_fd;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    rp2p_stream_state_t stream;
} rp2p_udp_server_session_t;

typedef struct {
    rp2p_t *borrowed_ctx;
    const char *borrowed_index_host;
    const char *borrowed_self_id;
    const char *borrowed_udp_any_host;
    unsigned short index_port;
    rp2p_fd_t owned_control_fd;
    rp2p_fd_t owned_udp_fd;
    rp2p_udp_server_session_t *owned_sessions;
    int session_count;
    int session_capacity;
    uint64_t last_heartbeat;
} rp2p_publisher_runtime_t;

#ifdef _WIN32
typedef HANDLE rp2p_thread_t;
#define RP2P_THREAD_RET unsigned __stdcall
#else
typedef pthread_t rp2p_thread_t;
#define RP2P_THREAD_RET void *
#endif

static int rp2p_sock_read(rp2p_fd_t fd, char *buf, int len);
static int rp2p_write_all(rp2p_fd_t fd, const char *buf, int len);
static void rp2p_shutdown_write(rp2p_fd_t fd);
static socklen_t rp2p_sockaddr_len(const struct sockaddr_storage *addr);
static int rp2p_candidate_sockaddr(const rp2p_candidate_t *candidate,
    struct sockaddr_storage *out);
static int rp2p_is_space(char ch);
static char *rp2p_trim(char *text);
static size_t rp2p_find_vip(rp2p_t *ctx, const char *id);
static int rp2p_add_vip(rp2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap);
static const char *rp2p_get_register_pass(rp2p_t *ctx, const char *id);
static uint32_t rp2p_load_u32_le(const unsigned char *p);

/**
 * Reports whether detailed stream logs are enabled.
 * @return 1 when stream debug logging is enabled, 0 otherwise.
 */
static int rp2p_stream_debug_enabled(void) {
    const char *env;

    env = getenv("RP2P_DEBUG_STREAM");
    return env && env[0] != '\0' && strcmp(env, "0") != 0;
}

/**
 * Emits one conditional debug log line for stream internals.
 * @return None.
 */
static void rp2p_stream_log(const char *fmt, ...) {
    va_list ap;

    if (!rp2p_stream_debug_enabled()) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/**
 * Returns the configured debug drop cadence for KCP datagrams.
 * @return Drop cadence, or 0 when disabled.
 */
static int rp2p_stream_debug_drop_every(void) {
    const char *env;
    long every;

    env = getenv("RP2P_DEBUG_STREAM_DROP_EVERY");
    if (!rp2p_parse_u(env, 1, 1000000, &every)) return 0;
    return (int)every;
}

/**
 * Returns the configured debug reorder cadence for KCP datagrams.
 * @return Reorder cadence, or 0 when disabled.
 */
static int rp2p_stream_debug_reorder_every(void) {
    const char *env;
    long every;

    env = getenv("RP2P_DEBUG_STREAM_REORDER_EVERY");
    if (!rp2p_parse_u(env, 1, 1000000, &every)) return 0;
    return (int)every;
}

/**
 * Decides whether to drop one complete outgoing KCP datagram for testing.
 * @param ctx Context containing the fault counter.
 * @return 1 when the datagram should be dropped, 0 otherwise.
 */
static int rp2p_stream_should_drop(rp2p_t *ctx) {
    int every;

    every = rp2p_stream_debug_drop_every();
    if (every <= 0) return 0;
    ctx->fault_drop_counter++;
    return (ctx->fault_drop_counter % every) == 0;
}

/**
 * Decides whether to delay one complete KCP datagram for reordering tests.
 * @param ctx Context containing the fault counter.
 * @return 1 when the datagram should be delayed, 0 otherwise.
 */
static int rp2p_stream_should_reorder(rp2p_t *ctx) {
    int every;

    every = rp2p_stream_debug_reorder_every();
    if (every <= 0) return 0;
    ctx->fault_reorder_counter++;
    return (ctx->fault_reorder_counter % every) == 0;
}

/**
 * Lock.
 * @return Status code.
 */
static void rp2p_lock(rp2p_t *ctx) {
#ifdef _WIN32
    EnterCriticalSection(&ctx->mutex);
#else
    pthread_mutex_lock(&ctx->mutex);
#endif
}

/**
 * Unlock.
 * @return Status code.
 */
static void rp2p_unlock(rp2p_t *ctx) {
#ifdef _WIN32
    LeaveCriticalSection(&ctx->mutex);
#else
    pthread_mutex_unlock(&ctx->mutex);
#endif
}

/**
 * Loads one little-endian u32.
 * @return Decoded value.
 */
static uint32_t rp2p_load_u32_le(const unsigned char *p) {
    return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) |
        ((uint32_t)p[3] << 24);
}

/**
 * Stores one little-endian u32.
 * @return None.
 */
static void rp2p_store_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/**
 * Returns a millisecond timestamp.
 * @return Monotonic-ish timestamp in milliseconds.
 */
static uint64_t rp2p_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/**
 * Returns a second timestamp.
 * Summary: Used for elapsed-time logic to avoid wall-clock jumps.
 * @return Monotonic-ish timestamp in seconds.
 */
static uint64_t rp2p_now_s(void) {
    return rp2p_now_ms() / 1000;
}

#ifdef RP2P_TEST_RANDOM
static unsigned char rp2p_test_random_bytes[256];
static size_t rp2p_test_random_len;
static size_t rp2p_test_random_pos;
static int rp2p_test_random_fail;
#endif

/**
 * Fills a buffer with secure random bytes.
 * @return 0 on success, -1 on error.
 */
static int rp2p_fill_random(unsigned char *buf, size_t len) {
#ifdef RP2P_TEST_RANDOM
    if (rp2p_test_random_fail) return -1;
    if (rp2p_test_random_len > 0) {
        size_t i;
        for (i = 0; i < len; i++) {
            buf[i] = rp2p_test_random_bytes[rp2p_test_random_pos %
                rp2p_test_random_len];
            rp2p_test_random_pos++;
        }
        return 0;
    }
#endif
#ifdef _WIN32
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    size_t off = 0;
    int fd;
    ssize_t n;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (off < len) {
        n = read(fd, buf + off, len - off);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

#ifdef RP2P_TEST_RANDOM
/**
 * Configures deterministic random bytes for test builds.
 * @param bytes Byte stream to repeat.
 * @param len   Byte stream length.
 * @return None.
 */
void rp2p_test_random_set(const unsigned char *bytes, size_t len) {
    if (!bytes || len == 0) {
        rp2p_test_random_len = 0;
        rp2p_test_random_pos = 0;
        return;
    }
    if (len > sizeof(rp2p_test_random_bytes))
        len = sizeof(rp2p_test_random_bytes);
    memcpy(rp2p_test_random_bytes, bytes, len);
    rp2p_test_random_len = len;
    rp2p_test_random_pos = 0;
    rp2p_test_random_fail = 0;
}

/**
 * Configures random-source failure for test builds.
 * @param fail Non-zero forces failure.
 * @return None.
 */
void rp2p_test_random_set_fail(int fail) {
    rp2p_test_random_fail = fail ? 1 : 0;
}
#endif

/**
 * Decodes one hex nibble.
 * @return Nibble value, or -1 on error.
 */
static int rp2p_hex_decode_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Decodes a fixed-size hex string.
 * @return 1 on success, 0 on error.
 */
static int rp2p_hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;

    if (!hex || !out) return 0;
    for (i = 0; i < out_len; i++) {
        int hi = rp2p_hex_decode_nibble(hex[i * 2]);
        int lo = rp2p_hex_decode_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/**
 * Generates one secure stream session identifier.
 * @return 1 on success, 0 on error.
 */
static int rp2p_stream_make_session_id(unsigned char out[RP2P_STREAM_SESSION_ID_SZ],
    char hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1])
{
    if (rp2p_fill_random(out, RP2P_STREAM_SESSION_ID_SZ) != 0) return 0;
    return rp2p_hex_encode(out, RP2P_STREAM_SESSION_ID_SZ, hex,
        RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
}

/**
 * Encodes one RP2P TCP envelope around an optional KCP datagram.
 * @return Encoded byte length, or 0 when the payload is too large.
 */
static size_t rp2p_stream_pack(uint8_t type, uint8_t role, uint8_t protocol,
    const unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ],
    const void *payload, size_t payload_len, unsigned char *out)
{
    if (payload_len > RP2P_STREAM_KCP_MTU) return 0;
    rp2p_store_u32_le(out, RP2P_STREAM_MAGIC);
    out[4] = RP2P_STREAM_VERSION;
    out[5] = type;
    out[6] = role;
    out[7] = protocol;
    memcpy(out + 8, session_id, RP2P_STREAM_SESSION_ID_SZ);
    if (payload_len > 0) memcpy(out + RP2P_STREAM_ENVELOPE_SZ, payload,
        payload_len);
    return RP2P_STREAM_ENVELOPE_SZ + payload_len;
}

/**
 * Decodes and validates one RP2P TCP envelope.
 * @return 1 on success, 0 when the datagram is not a valid envelope.
 */
static int rp2p_stream_unpack(const unsigned char *buf, size_t len,
    rp2p_stream_envelope_t *envelope)
{
    if (!buf || !envelope || len < RP2P_STREAM_ENVELOPE_SZ ||
        len > RP2P_STREAM_MAX_FRAME)
        return 0;
    if (rp2p_load_u32_le(buf) != RP2P_STREAM_MAGIC ||
        buf[4] != RP2P_STREAM_VERSION ||
        buf[5] < RP2P_STREAM_TYPE_HELLO ||
        buf[5] > RP2P_STREAM_TYPE_KEEPALIVE ||
        (buf[6] != RP2P_STREAM_ROLE_INITIATOR &&
        buf[6] != RP2P_STREAM_ROLE_RESPONDER) ||
        buf[7] != RP2P_PROTO_TCP)
        return 0;
    envelope->type = buf[5];
    envelope->role = buf[6];
    envelope->protocol = buf[7];
    memcpy(envelope->session_id, buf + 8, RP2P_STREAM_SESSION_ID_SZ);
    envelope->payload = buf + RP2P_STREAM_ENVELOPE_SZ;
    envelope->payload_len = len - RP2P_STREAM_ENVELOPE_SZ;
    if (envelope->type != RP2P_STREAM_TYPE_KCP && envelope->payload_len != 0)
        return 0;
    return 1;
}

/**
 * Sends one already encoded stream datagram.
 * @return 0 on success, -1 on socket failure.
 */
static int rp2p_stream_send_datagram(rp2p_stream_adapter_t *adapter,
    const unsigned char *frame, size_t frame_len)
{
    socklen_t peer_len;

    peer_len = rp2p_sockaddr_len(&adapter->peer_addr);
    if (peer_len == 0 || sendto(adapter->fd, (const char *)frame, frame_len, 0,
        (const struct sockaddr *)&adapter->peer_addr, peer_len) < 0)
        return -1;
    return 0;
}

/**
 * Emits one complete KCP datagram through the RP2P session envelope.
 * @return 0 on success, -1 after a transport failure.
 */
static int rp2p_stream_kcp_output(const char *buf, int len, ikcpcb *kcp,
    void *user)
{
    rp2p_stream_adapter_t *adapter;
    unsigned char frame[RP2P_STREAM_MAX_FRAME];
    size_t frame_len;

    (void)kcp;
    adapter = (rp2p_stream_adapter_t *)user;
    if (!adapter || len <= 0 || len > RP2P_STREAM_KCP_MTU) return -1;
    frame_len = rp2p_stream_pack(RP2P_STREAM_TYPE_KCP, adapter->role,
        adapter->protocol, adapter->session_id, buf, (size_t)len, frame);
    if (frame_len == 0) return -1;
    if (rp2p_stream_should_drop(adapter->ctx)) {
        rp2p_stream_log("rp2p: stream dropped one KCP datagram\n");
        return 0;
    }
    if (!adapter->fault_pending_used &&
        rp2p_stream_should_reorder(adapter->ctx))
    {
        rp2p_stream_log("rp2p: stream delayed one KCP datagram\n");
        memcpy(adapter->fault_pending, frame, frame_len);
        adapter->fault_pending_len = frame_len;
        adapter->fault_pending_used = 1;
        return 0;
    }
    if (rp2p_stream_send_datagram(adapter, frame, frame_len) != 0 ||
        (adapter->fault_pending_used &&
        rp2p_stream_send_datagram(adapter, adapter->fault_pending,
            adapter->fault_pending_len) != 0))
    {
        adapter->send_error = 1;
        return -1;
    }
    adapter->fault_pending_used = 0;
    return 0;
}

/**
 * Derives the session-local KCP routing value from the full RP2P identifier.
 * @return Deterministic 32-bit KCP conversation value.
 */
static uint32_t rp2p_stream_conv(
    const unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ])
{
    return rp2p_load_u32_le(session_id) ^ rp2p_load_u32_le(session_id + 4) ^
        rp2p_load_u32_le(session_id + 8) ^
        rp2p_load_u32_le(session_id + 12);
}

/**
 * Initializes one conservative stream-mode KCP session and RP2P adapter.
 * @return 0 on success, -1 on allocation or KCP configuration failure.
 */
static int rp2p_stream_init(rp2p_t *ctx, rp2p_stream_state_t *st,
    int initiator, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    const unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ],
    const char *session_hex, uint8_t transport_protocol)
{
    uint64_t now;

    memset(st, 0, sizeof(*st));
    st->adapter = (rp2p_stream_adapter_t *)calloc(1, sizeof(*st->adapter));
    if (!st->adapter) {
        rp2p_set_error(ctx, "stream: KCP adapter allocation failed");
        return -1;
    }
    st->adapter->ctx = ctx;
    st->adapter->fd = fd;
    st->adapter->peer_addr = *peer_addr;
    st->adapter->role = initiator ? RP2P_STREAM_ROLE_INITIATOR :
        RP2P_STREAM_ROLE_RESPONDER;
    st->adapter->protocol = transport_protocol;
    memcpy(st->adapter->session_id, session_id, RP2P_STREAM_SESSION_ID_SZ);
    st->kcp = ikcp_create(rp2p_stream_conv(session_id), st->adapter);
    if (!st->kcp || ikcp_setmtu(st->kcp, RP2P_STREAM_KCP_MTU) != 0 ||
        ikcp_wndsize(st->kcp, RP2P_STREAM_SEND_WINDOW,
            RP2P_STREAM_RECV_WINDOW) != 0 ||
        ikcp_nodelay(st->kcp, 0, RP2P_STREAM_KCP_INTERVAL_MS,
            RP2P_STREAM_KCP_FAST_RESEND, 0) != 0)
    {
        if (st->kcp) ikcp_release(st->kcp);
        free(st->adapter);
        memset(st, 0, sizeof(*st));
        rp2p_set_error(ctx, "stream: KCP initialization failed");
        return -1;
    }
    st->kcp->stream = 1;
    ikcp_setoutput(st->kcp, rp2p_stream_kcp_output);
    st->enabled = 1;
    st->initiator = initiator;
    st->transport_protocol = transport_protocol;
    memcpy(st->session_id, session_id, RP2P_STREAM_SESSION_ID_SZ);
    if (session_hex) memcpy(st->session_hex, session_hex,
        RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
    now = rp2p_now_ms();
    st->last_tx_ms = now;
    st->last_keepalive_ms = now;
    st->next_update_ms = (uint32_t)now;
    return 0;
}

/**
 * Reports whether the local TCP side may queue more bytes in KCP.
 * @return 1 when local TCP reads may continue, 0 otherwise.
 */
static int rp2p_stream_can_send_data(const rp2p_stream_state_t *st) {
    return st->ready && !st->local_eof && st->kcp &&
        ikcp_waitsnd(st->kcp) < RP2P_STREAM_MAX_WAIT_SEND;
}

/**
 * Sends one RP2P tunnel control envelope outside KCP.
 * @return 0 on success, -1 on socket failure.
 */
static int rp2p_stream_send_control(rp2p_t *ctx, rp2p_stream_state_t *st,
    uint8_t type)
{
    unsigned char frame[RP2P_STREAM_ENVELOPE_SZ];
    size_t frame_len;

    frame_len = rp2p_stream_pack(type, st->adapter->role,
        st->transport_protocol, st->session_id, NULL, 0, frame);
    if (frame_len == 0 ||
        rp2p_stream_send_datagram(st->adapter, frame, frame_len) != 0)
    {
        rp2p_set_error(ctx, "stream: UDP control send failed");
        return -1;
    }
    st->last_tx_ms = rp2p_now_ms();
    return 0;
}

/**
 * Notifies an established peer of terminal stream failure once.
 * @return None.
 */
static void rp2p_stream_fail(rp2p_t *ctx, rp2p_stream_state_t *st) {
    if (!st || !st->ready || st->reset_sent || st->reset_received) return;
    st->reset_sent = 1;
    rp2p_stream_send_control(ctx, st, RP2P_STREAM_TYPE_RESET);
}

/**
 * Drains all currently reconstructed KCP bytes into the local TCP socket.
 * @return 0 on success, -1 on KCP or local socket failure.
 */
static int rp2p_stream_drain(rp2p_t *ctx, rp2p_stream_state_t *st,
    rp2p_fd_t tcp_fd)
{
    unsigned char buf[RP2P_BUF];
    int available;
    int received;

    for (;;) {
        available = ikcp_peeksize(st->kcp);
        if (available < 0) return 0;
        if (available > (int)sizeof(buf)) {
            rp2p_set_error(ctx, "stream: KCP receive chunk exceeds buffer");
            return -1;
        }
        received = ikcp_recv(st->kcp, (char *)buf, (int)sizeof(buf));
        if (received < 0) {
            rp2p_set_error(ctx, "stream: KCP receive failed");
            return -1;
        }
        if (received > 0 && rp2p_write_all(tcp_fd, (const char *)buf,
            received) != 0)
        {
            rp2p_set_error(ctx, "stream: local TCP write failed");
            return -1;
        }
    }
}

/**
 * Dispatches one validated session datagram through handshake or KCP.
 * @return 0 on success, -1 on protocol, transport, or local socket failure.
 */
static int rp2p_stream_process_packet(rp2p_t *ctx,
    rp2p_stream_state_t *st, rp2p_fd_t tcp_fd,
    const unsigned char *buf, size_t len)
{
    rp2p_stream_envelope_t envelope;
    uint8_t expected_role;
    int input_result;

    if (!rp2p_stream_unpack(buf, len, &envelope)) return 0;
    expected_role = st->initiator ? RP2P_STREAM_ROLE_RESPONDER :
        RP2P_STREAM_ROLE_INITIATOR;
    if (envelope.role != expected_role ||
        envelope.protocol != st->transport_protocol ||
        memcmp(envelope.session_id, st->session_id,
            RP2P_STREAM_SESSION_ID_SZ) != 0)
        return 0;
    if (envelope.type == RP2P_STREAM_TYPE_HELLO && !st->initiator) {
        if (rp2p_stream_send_control(ctx, st,
            RP2P_STREAM_TYPE_HELLO_ACK) != 0)
            return -1;
        st->ready = 1;
        rp2p_stream_log("rp2p: tcp session %s KCP ready\n",
            st->session_hex);
        return 0;
    }
    if (envelope.type == RP2P_STREAM_TYPE_HELLO_ACK && st->initiator) {
        st->ready = 1;
        rp2p_stream_log("rp2p: tcp session %s KCP ready\n",
            st->session_hex);
        return 0;
    }
    if (!st->ready) return 0;
    if (envelope.type == RP2P_STREAM_TYPE_KCP) {
        input_result = ikcp_input(st->kcp, (const char *)envelope.payload,
            (long)envelope.payload_len);
        if (input_result != 0) {
            rp2p_set_error(ctx, "stream: KCP input failed (%d)", input_result);
            return -1;
        }
        st->next_update_ms = (uint32_t)rp2p_now_ms();
        return rp2p_stream_drain(ctx, st, tcp_fd);
    }
    if (envelope.type == RP2P_STREAM_TYPE_CLOSE) {
        if (rp2p_stream_drain(ctx, st, tcp_fd) != 0) return -1;
        if (!st->remote_close) rp2p_shutdown_write(tcp_fd);
        st->remote_close = 1;
        return rp2p_stream_send_control(ctx, st,
            RP2P_STREAM_TYPE_CLOSE_ACK);
    }
    if (envelope.type == RP2P_STREAM_TYPE_CLOSE_ACK) {
        st->close_acked = 1;
        return 0;
    }
    if (envelope.type == RP2P_STREAM_TYPE_RESET) {
        st->reset_received = 1;
        rp2p_set_error(ctx, "stream: peer reset");
        return -1;
    }
    return 0;
}

/**
 * Reads one local TCP chunk and queues its bytes in KCP stream mode.
 * @return 0 on success, -1 on local socket or KCP failure.
 */
static int rp2p_stream_pump_tcp(rp2p_t *ctx,
    rp2p_stream_state_t *st, rp2p_fd_t tcp_fd)
{
    unsigned char buf[RP2P_BUF];
    int n;
    int sent;

    if (!rp2p_stream_can_send_data(st)) return 0;
    n = rp2p_sock_read(tcp_fd, (char *)buf, (int)sizeof(buf));
    if (n < 0) {
        if (RP2P_LASTERR() == RP2P_EWOULD) return 0;
        rp2p_set_error(ctx, "stream: local TCP read failed");
        return -1;
    }
    if (n == 0) {
        st->local_eof = 1;
        return 0;
    }
    sent = ikcp_send(st->kcp, (const char *)buf, n);
    if (sent != n) {
        rp2p_set_error(ctx, "stream: KCP send failed");
        return -1;
    }
    st->next_update_ms = (uint32_t)rp2p_now_ms();
    return 0;
}

/**
 * Advances one KCP session and RP2P tunnel lifecycle when due.
 * @return 0 on success, -1 on transport failure.
 */
static int rp2p_stream_tick(rp2p_t *ctx, rp2p_stream_state_t *st)
{
    uint64_t now;
    uint32_t current;

    if (!st->enabled) return 0;
    now = rp2p_now_ms();
    current = (uint32_t)now;
    if (st->initiator && !st->ready &&
        (!st->hello_sent || now - st->last_hello_ms >= RP2P_STREAM_HELLO_MS))
    {
        if (rp2p_stream_send_control(ctx, st,
            RP2P_STREAM_TYPE_HELLO) != 0)
            return -1;
        st->hello_sent = 1;
        st->last_hello_ms = now;
    }
    if (st->ready && (int32_t)(current - st->next_update_ms) >= 0) {
        ikcp_update(st->kcp, current);
        st->next_update_ms = ikcp_check(st->kcp, current);
    }
    if (st->adapter->send_error) {
        rp2p_set_error(ctx, "stream: KCP UDP output failed");
        return -1;
    }
    if (st->ready && st->local_eof && !st->close_acked &&
        ikcp_waitsnd(st->kcp) == 0 &&
        (!st->close_sent || now - st->last_close_ms >= RP2P_STREAM_CLOSE_MS))
    {
        if (rp2p_stream_send_control(ctx, st, RP2P_STREAM_TYPE_CLOSE) != 0)
            return -1;
        st->close_sent = 1;
        st->last_close_ms = now;
    }
    if (st->ready && now - st->last_keepalive_ms >=
        (uint64_t)RP2P_KEEPALIVE_S * 1000u)
    {
        if (rp2p_stream_send_control(ctx, st,
            RP2P_STREAM_TYPE_KEEPALIVE) != 0)
            return -1;
        st->last_keepalive_ms = now;
    }
    return 0;
}

/**
 * Returns the next KCP update delay for select scheduling.
 * @return Milliseconds until work is due, capped at one second.
 */
static uint32_t rp2p_stream_wait_ms(const rp2p_stream_state_t *st,
    uint64_t now)
{
    uint32_t current;
    int32_t difference;

    if (!st || !st->enabled) return 1000;
    if (!st->ready) {
        if (!st->initiator) return 1000;
        if (!st->hello_sent ||
            now - st->last_hello_ms >= RP2P_STREAM_HELLO_MS)
            return 0;
        return (uint32_t)(RP2P_STREAM_HELLO_MS -
            (now - st->last_hello_ms));
    }
    current = (uint32_t)now;
    difference = (int32_t)(st->next_update_ms - current);
    if (difference <= 0) return 0;
    if (difference > 1000) return 1000;
    return (uint32_t)difference;
}

/**
 * Reports whether one TCP stream is fully closed on both sides.
 * @return 1 when the stream may be cleaned up, 0 otherwise.
 */
static int rp2p_stream_is_done(const rp2p_stream_state_t *st) {
    return st->local_eof && st->close_acked && st->remote_close && st->kcp &&
        ikcp_waitsnd(st->kcp) == 0;
}

/**
 * Releases KCP and wipes all per-session stream material.
 * @return None.
 */
static void rp2p_stream_wipe(rp2p_stream_state_t *st) {
    if (!st) return;
    if (st->kcp) ikcp_release(st->kcp);
    if (st->adapter) {
        crypto_wipe(st->adapter, sizeof(*st->adapter));
        free(st->adapter);
    }
    crypto_wipe(st, sizeof(*st));
}

/**
 * Closes one publisher-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void rp2p_server_session_close(rp2p_udp_server_session_t *sess) {
    if (!sess) return;
    if (sess->backend_fd != RP2P_FD_INVALID) {
        RP2P_FD_CLOSE(sess->backend_fd);
        sess->backend_fd = RP2P_FD_INVALID;
    }
    if (sess->tcp_fd != RP2P_FD_INVALID) {
        RP2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = RP2P_FD_INVALID;
    }
    if (sess->is_tcp) rp2p_stream_wipe(&sess->stream);
    sess->active = 0;
}

/**
 * Closes one consumer-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void rp2p_consumer_session_close(rp2p_udp_consumer_session_t *sess) {
    if (!sess) return;
    if (sess->tcp_fd != RP2P_FD_INVALID) {
        RP2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = RP2P_FD_INVALID;
    }
    if (!RP2P_ISERR(sess->fd)) {
        RP2P_FD_CLOSE(sess->fd);
        sess->fd = RP2P_FD_INVALID;
    }
    if (sess->is_tcp) rp2p_stream_wipe(&sess->stream);
    sess->active = 0;
}

#ifdef _WIN32

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int rp2p_platform_init(void) {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0 ? 0 : -1;
}

/**
 * Platform cleanup.
 * @return None.
 */
void rp2p_platform_cleanup(void) { WSACleanup(); }

#else

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int rp2p_platform_init(void) { return 0; }

/**
 * Platform cleanup.
 * @return None.
 */
void rp2p_platform_cleanup(void) {}

#endif

/**
 * Set nonblock.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_nonblock(rp2p_fd_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/**
 * Set block.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_block(rp2p_fd_t fd) {
#ifdef _WIN32
    u_long mode = 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

/**
 * Resolve.
 * @return 0 on success, -1 on error.
 */
int rp2p_resolve(
    const char *host,
    unsigned short port,
    int socktype,
    struct sockaddr_storage *out,
    socklen_t *out_len)
{
    struct addrinfo hints;
    struct addrinfo *ai;
    char port_str[16];

    if (!out || !out_len) return -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = host ? AF_UNSPEC : AF_INET6;
    hints.ai_socktype = socktype;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &ai) != 0) return -1;

    if ((size_t)ai->ai_addrlen > sizeof(*out)) {
        freeaddrinfo(ai);
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, ai->ai_addr, ai->ai_addrlen);
    *out_len = (socklen_t)ai->ai_addrlen;
    freeaddrinfo(ai);
    return 0;
}

/**
 * Returns the socket address length for a stored address family.
 * @param addr Stored socket address.
 * @return Socket address length, or 0 for unsupported families.
 */
static socklen_t rp2p_sockaddr_len(const struct sockaddr_storage *addr) {
    if (!addr) return 0;
    if (addr->ss_family == AF_INET) return sizeof(struct sockaddr_in);
    if (addr->ss_family == AF_INET6) return sizeof(struct sockaddr_in6);
    return 0;
}

/**
 * Returns the UDP or TCP port from a stored socket address.
 * @param addr Stored socket address.
 * @return Host-order port, or 0 for unsupported families.
 */
static unsigned short rp2p_sockaddr_port(
    const struct sockaddr_storage *addr)
{
    if (!addr) return 0;
    if (addr->ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)addr)->sin_port);
    if (addr->ss_family == AF_INET6)
        return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    return 0;
}

/**
 * Sets the UDP or TCP port in a stored socket address.
 * @param addr Stored socket address.
 * @param port Host-order port.
 * @return 1 on success, 0 for unsupported families.
 */
static int rp2p_sockaddr_set_port(struct sockaddr_storage *addr,
    unsigned short port)
{
    if (!addr) return 0;
    if (addr->ss_family == AF_INET) {
        ((struct sockaddr_in *)addr)->sin_port = htons(port);
        return 1;
    }
    if (addr->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
        return 1;
    }
    return 0;
}

/**
 * Compares stored socket endpoints by family, address, and port.
 * @param a First address.
 * @param b Second address.
 * @return 1 when endpoints match, 0 otherwise.
 */
static int rp2p_sockaddr_equal(const struct sockaddr_storage *a,
    const struct sockaddr_storage *b)
{
    if (!a || !b || a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *aa = (const struct sockaddr_in *)a;
        const struct sockaddr_in *bb = (const struct sockaddr_in *)b;
        return aa->sin_port == bb->sin_port &&
            aa->sin_addr.s_addr == bb->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)b;
        return aa->sin6_port == bb->sin6_port &&
            memcmp(&aa->sin6_addr, &bb->sin6_addr,
                sizeof(aa->sin6_addr)) == 0;
    }
    return 0;
}

/**
 * Sends bytes to one stored socket address.
 * @param fd   UDP socket.
 * @param buf  Bytes to send.
 * @param len  Byte count.
 * @param addr Destination address.
 * @return sendto result, or -1 for unsupported address families.
 */
static int rp2p_sendto_addr(rp2p_fd_t fd, const void *buf, size_t len,
    const struct sockaddr_storage *addr)
{
    socklen_t addr_len;

    addr_len = rp2p_sockaddr_len(addr);
    if (addr_len == 0) return -1;
    return (int)sendto(fd, buf, len, 0, (const struct sockaddr *)addr,
        addr_len);
}

/**
 * Reports whether a host string is an IPv6 literal.
 * @param host Host string.
 * @return 1 for IPv6 literals, 0 otherwise.
 */
static int rp2p_host_is_ipv6_literal(const char *host) {
    struct in6_addr addr;

    return host && inet_pton(AF_INET6, host, &addr) == 1;
}

/**
 * Extract addr.
 * @return None.
 */
void rp2p_extract_addr(
    const struct sockaddr_in *from,
    char *out,
    size_t out_cap,
    unsigned short *port)
{
#ifdef _WIN32
    const char *p = inet_ntoa(from->sin_addr);
    strncpy(out, p, out_cap - 1);
    out[out_cap - 1] = '\0';
#else
    inet_ntop(AF_INET, &from->sin_addr, out, (socklen_t)out_cap);
#endif
    *port = ntohs(from->sin_port);
}

/**
 * Send reply.
 * @return 0 on success, -1 on error.
 */
int rp2p_send_reply(
    rp2p_fd_t fd,
    const struct sockaddr_in *to,
    socklen_t tolen,
    const char *msg)
{
    return sendto(fd, msg, strlen(msg), 0,
        (const struct sockaddr *)to, tolen) > 0
        ? RP2P_OK : RP2P_ENET;
}

/**
 * Send recv.
 * @return 0 on success, -1 on error.
 */
int rp2p_send_recv(
    rp2p_fd_t fd,
    const char *srv_host,
    unsigned short srv_port,
    const char *send_msg,
    char *recv_buf,
    size_t recv_cap,
    int timeout_sec)
{
    struct sockaddr_storage srv;
    socklen_t srv_len;
    socklen_t srclen;
    fd_set fds;
    struct timeval tv;
    int n;
    struct sockaddr_storage from;
    uint64_t deadline;

    if (rp2p_resolve(srv_host, srv_port, SOCK_DGRAM, &srv, &srv_len) != 0)
        return RP2P_ENET;

    if (sendto(fd, send_msg, strlen(send_msg), 0,
        (const struct sockaddr *)&srv, srv_len) < 0)
        return RP2P_ENET;

    if (!recv_buf || recv_cap == 0) return RP2P_OK;

    deadline = rp2p_now_ms() + (uint64_t)timeout_sec * 1000u;
    while (rp2p_now_ms() < deadline) {
        uint64_t remaining = deadline - rp2p_now_ms();

        FD_ZERO(&fds);
        if (!rp2p_fdset_add(fd, &fds, NULL)) return RP2P_ENET;
        tv.tv_sec = (long)(remaining / 1000u);
        tv.tv_usec = (long)((remaining % 1000u) * 1000u);
        n = select((int)(fd + 1), &fds, NULL, NULL, &tv);
        if (n <= 0) return RP2P_ETIMEOUT;
        srclen = sizeof(from);
        n = (int)recvfrom(fd, recv_buf, (int)(recv_cap - 1), 0,
            (struct sockaddr *)&from, &srclen);
        if (n < 0) return RP2P_ENET;
        if (!rp2p_sockaddr_equal(&from, &srv)) continue;
        recv_buf[n] = '\0';
        return RP2P_OK;
    }
    return RP2P_ETIMEOUT;
}

/**
 * Adds one descriptor to one select set with descriptor-range validation.
 * Summary: Rejects descriptors that cannot be represented by fd_set.
 * @param fd    Descriptor to add.
 * @param set   Select set to update.
 * @param maxfd Current maximum descriptor, updated on success.
 * @return 1 when added, 0 when rejected.
 */
static int rp2p_fdset_add(rp2p_fd_t fd, fd_set *set, int *maxfd) {
#ifdef _WIN32
    (void)maxfd;
    if (fd == INVALID_SOCKET) return 0;
    if ((int)set->fd_count >= FD_SETSIZE) return 0;
#else
    if (fd < 0) return 0;
    if (fd >= FD_SETSIZE) return 0;
    if (maxfd && (int)fd > *maxfd) *maxfd = (int)fd;
#endif
    FD_SET(fd, set);
    return 1;
}

/**
 * Creates one UDP or TCP socket bound to one local address.
 * @return Valid descriptor, or RP2P_FD_INVALID on failure.
 */
rp2p_fd_t rp2p_create_socket(
    const char *bind_host,
    unsigned short bind_port)
{
    rp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    if (rp2p_platform_init() != 0) return RP2P_FD_INVALID;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)bind_port);
    if (getaddrinfo(bind_host, port_str, &hints, &ai) != 0)
        return RP2P_FD_INVALID;

    fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(fd)) continue;
        {
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                (void *)&reuse, sizeof(reuse));
        }
#ifdef IPV6_V6ONLY
        if (it->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                (void *)&v6only, sizeof(v6only));
        }
#endif
        if (bind(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0)
            break;
        RP2P_FD_CLOSE(fd);
        fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Create tcp listener.
 * @return 0 on success, -1 on error.
 */
static rp2p_fd_t rp2p_create_tcp_listener(
    const char *bind_host,
    unsigned short bind_port)
{
    rp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)bind_port);
    if (getaddrinfo(bind_host, port_str, &hints, &ai) != 0)
        return RP2P_FD_INVALID;
    fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(fd)) continue;
        {
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                (void *)&reuse, sizeof(reuse));
        }
#ifdef IPV6_V6ONLY
        if (it->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                (void *)&v6only, sizeof(v6only));
        }
#endif
        if (bind(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0 &&
            listen(fd, 32) == 0)
            break;
        RP2P_FD_CLOSE(fd);
        fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Connect local tcp.
 * @return 0 on success, -1 on error.
 */
static rp2p_fd_t rp2p_connect_local_tcp(unsigned short port) {
    rp2p_fd_t fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (RP2P_ISERR(fd)) return RP2P_FD_INVALID;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    return fd;
}

/**
 * Sock read.
 * @return 0 on success, -1 on error.
 */
static int rp2p_sock_read(rp2p_fd_t fd, char *buf, int len) {
#ifdef _WIN32
    return recv(fd, buf, len, 0);
#else
    return (int)read(fd, buf, (size_t)len);
#endif
}

/**
 * Sock write.
 * @return 0 on success, -1 on error.
 */
static int rp2p_sock_write(rp2p_fd_t fd, const char *buf, int len) {
#ifdef _WIN32
    return send(fd, buf, len, 0);
#else
    return (int)write(fd, buf, (size_t)len);
#endif
}

/**
 * Write all.
 * @return 0 on success, -1 on error.
 */
static int rp2p_write_all(rp2p_fd_t fd, const char *buf, int len) {
    int off;
    int n;

    off = 0;
    while (off < len) {
        n = rp2p_sock_write(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += n;
    }
    return 0;
}

/**
 * Shuts down the local write side of one TCP socket.
 * @return None.
 */
static void rp2p_shutdown_write(rp2p_fd_t fd) {
#ifdef _WIN32
    shutdown(fd, SD_SEND);
#else
    shutdown(fd, SHUT_WR);
#endif
}

/**
 * Tcp connect.
 * @return 0 on success, -1 on error.
 */
static rp2p_fd_t rp2p_tcp_connect(const char *host, unsigned short port) {
    rp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &ai) != 0)
        return RP2P_FD_INVALID;
    fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(fd)) continue;
        if (connect(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0)
            break;
        RP2P_FD_CLOSE(fd);
        fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Tcp send.
 * @return 0 on success, -1 on error.
 */
static int rp2p_tcp_send(rp2p_fd_t fd, const char *msg) {
    int len = (int)strlen(msg);

    if (rp2p_write_all(fd, msg, len) != 0) return RP2P_ENET;
    if (rp2p_write_all(fd, "\n", 1) != 0) return RP2P_ENET;
    return RP2P_OK;
}

/**
 * Reports whether raw control bytes are safe for C-string parsing.
 * @param data Raw control bytes.
 * @param len  Byte count.
 * @return 1 when safe, 0 when a prohibited control byte is present.
 */
static int rp2p_control_bytes_valid(const char *data, size_t len) {
    size_t i;

    if (!data) return 0;
    for (i = 0; i < len; i++) {
        unsigned char byte = (unsigned char)data[i];

        if (byte == '\r') continue;
        if (byte < 0x20 || byte == 0x7f) return 0;
    }
    return 1;
}

/**
 * Tcp readline.
 * @return Complete line length, or a negative value on timeout, EOF, invalid
 * bytes, or capacity exhaustion.
 */
static int rp2p_tcp_readline(rp2p_fd_t fd, char *buf, int cap, int timeout_sec) {
    int total = 0;
    int n;
    char byte;

    if (cap < 1) return -1;

    for (;;) {
        fd_set fds;
        struct timeval tv;

        FD_ZERO(&fds);
        if (!rp2p_fdset_add(fd, &fds, NULL)) return -1;
        tv.tv_sec = (timeout_sec > 0 && total == 0) ? timeout_sec : 1;
        tv.tv_usec = 0;

        n = select(fd + 1, &fds, NULL, NULL, &tv);
        if (n <= 0) return -1;

        n = rp2p_sock_read(fd, &byte, 1);
        if (n <= 0) return -2;

        if (byte == '\n') {
            buf[total] = '\0';
            return total;
        }
        if (byte == '\r') continue;
        if (!rp2p_control_bytes_valid(&byte, 1)) return -3;
        if (total >= cap - 1) return -4;
        buf[total++] = byte;
    }
}

/**
 * Opens a TCP control connection and validates the control protocol version.
 * @param index_host Index host.
 * @param index_port Index port.
 * @return Connected fd on success, invalid fd on failure.
 */
static rp2p_fd_t rp2p_control_connect(rp2p_t *ctx, const char *phase,
    const char *index_host, unsigned short index_port, int *result)
{
    rp2p_fd_t fd;
    char reply[RP2P_BUF];
    int line_result;

    if (result) *result = RP2P_ENET;
    fd = rp2p_tcp_connect(index_host, index_port);
    if (RP2P_ISERR(fd)) {
        rp2p_set_error(ctx, "%s: control connect %s:%u failed", phase,
            index_host, (unsigned)index_port);
        return fd;
    }
    if (rp2p_tcp_send(fd, RP2P_CTRTOK_HELLO) != RP2P_OK) {
        rp2p_set_error(ctx, "%s: control version write failed", phase);
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    line_result = rp2p_tcp_readline(fd, reply, (int)sizeof(reply), 5);
    if (line_result < 0) {
        if (line_result == -1) {
            if (result) *result = RP2P_ETIMEOUT;
            rp2p_set_error(ctx, "%s: control version response timed out",
                phase);
        } else if (line_result == -3 || line_result == -4) {
            if (result) *result = RP2P_EPROTO;
            rp2p_set_error(ctx, "%s: malformed control version response",
                phase);
        } else {
            rp2p_set_error(ctx, "%s: control version response failed", phase);
        }
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    if (strcmp(reply, RP2P_CTRTOK_ERROR_VERSION_MISMATCH) == 0) {
        if (result) *result = RP2P_EVERSION;
        rp2p_set_error(ctx, "%s: index control version mismatch", phase);
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    if (strcmp(reply, RP2P_CTRTOK_HELLO_OK) != 0) {
        if (result) *result = RP2P_EPROTO;
        rp2p_set_error(ctx, "%s: malformed control version response: %s",
            phase, reply);
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    if (result) *result = RP2P_OK;
    return fd;
}

/**
 * Returns whether the byte is ASCII whitespace.
 * @param ch Input byte.
 * @return 1 when whitespace, 0 otherwise.
 */
static int rp2p_is_space(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
        ch == '\f' || ch == '\v';
}

/**
 * Returns whether the identifier contains only alphanumeric characters.
 * @param id Identifier to validate.
 * @return 1 when valid, 0 otherwise.
 */
int rp2p_is_valid_id(const char *id) {
    size_t i;

    if (!id || !id[0]) return 0;
    for (i = 0; id[i]; i++) {
        if (i >= RP2P_ID_MAX) return 0;
        if (!((id[i] >= 'a' && id[i] <= 'z') ||
            (id[i] >= 'A' && id[i] <= 'Z') ||
            (id[i] >= '0' && id[i] <= '9')))
            return 0;
    }
    return 1;
}

/**
 * Returns whether one password byte is safe to type in a shell token.
 * @param ch Input byte.
 * @return 1 when allowed, 0 otherwise.
 */
static int rp2p_is_pass_char(char ch) {
    if (ch >= 'a' && ch <= 'z') return 1;
    if (ch >= 'A' && ch <= 'Z') return 1;
    if (ch >= '0' && ch <= '9') return 1;
    return ch == '.' || ch == '_' || ch == '-' || ch == '+' ||
        ch == '=' || ch == ',' || ch == ':' || ch == '@' ||
        ch == '%' || ch == '/';
}

/**
 * Returns whether the password token uses only terminal-safe characters.
 * @param pass Password token to validate.
 * @return 1 when valid, 0 otherwise.
 */
int rp2p_is_valid_pass_token(const char *pass) {
    size_t i;

    if (!pass || !pass[0]) return 0;
    for (i = 0; pass[i]; i++) {
        if (i >= RP2P_PASS_MAX) return 0;
        if (!rp2p_is_pass_char(pass[i])) return 0;
    }
    return 1;
}

/**
 * Trims leading and trailing ASCII whitespace in place.
 * @param text Mutable string buffer.
 * @return Pointer to the first non-whitespace byte.
 */
static char *rp2p_trim(char *text) {
    char *end;

    if (!text) return NULL;
    while (*text && rp2p_is_space(*text)) text++;
    end = text + strlen(text);
    while (end > text && rp2p_is_space(end[-1])) end--;
    *end = '\0';
    return text;
}

/**
 * Finds one VIP seat by identifier.
 * @param ctx Open context.
 * @param id Reserved seat identifier.
 * @return VIP index on success, SIZE_MAX when missing.
 */
static size_t rp2p_find_vip(rp2p_t *ctx, const char *id) {
    size_t i;

    if (!ctx || !id) return SIZE_MAX;
    for (i = 0; i < ctx->n_vips; i++) {
        if (strcmp(ctx->vips[i].id, id) == 0) return i;
    }
    return SIZE_MAX;
}

/**
 * Recomputes non-VIP capacity after seats or VIP reservations change.
 * @param ctx Open context.
 * @return None.
 */
static void rp2p_update_nonvip_cap(rp2p_t *ctx) {
    if (!ctx) return;
    if (ctx->n_vips >= ctx->n_peers_cap) {
        ctx->nonvip_cap = 0;
    } else {
        ctx->nonvip_cap = ctx->n_peers_cap - ctx->n_vips;
    }
}

/**
 * Ensures peer storage can hold the requested number of online peers.
 * @param ctx  Open context.
 * @param need Required peer slots.
 * @return RP2P_OK on success, RP2P_ERROR on allocation failure.
 */
static int rp2p_ensure_peer_storage(rp2p_t *ctx, size_t need) {
    rp2p_peer_t *peers;
    size_t cap;
    size_t limit;

    if (!ctx) return RP2P_ERROR;
    limit = SIZE_MAX / sizeof(*ctx->peers);
    if (ctx->seats_set) limit = ctx->n_peers_cap;
    if (need > limit) return RP2P_EFULL;
    if (need <= ctx->peers_alloc) return RP2P_OK;
    cap = ctx->peers_alloc > 0 ? ctx->peers_alloc : 8;
    if (cap > limit) cap = limit;
    while (cap < need) {
        if (cap > limit / 2) {
            cap = limit;
        } else {
            cap *= 2;
        }
    }
    if (cap > SIZE_MAX / sizeof(*ctx->peers)) return RP2P_ERROR;
    peers = (rp2p_peer_t *)realloc(ctx->peers, cap * sizeof(*ctx->peers));
    if (!peers) return RP2P_ERROR;
    ctx->peers = peers;
    ctx->peers_alloc = cap;
    return RP2P_OK;
}

/**
 * Counts online peers that do not have a reserved VIP seat.
 * @param ctx Open context.
 * @return Number of online non-VIP peers.
 */
static size_t rp2p_count_nonvip_peers(rp2p_t *ctx) {
    size_t i;
    size_t count;

    if (!ctx) return 0;
    count = 0;
    for (i = 0; i < ctx->n_peers; i++) {
        if (rp2p_find_vip(ctx, ctx->peers[i].id) == SIZE_MAX) count++;
    }
    return count;
}

/**
 * Adds one VIP seat definition to the context.
 * @param ctx Open context.
 * @param id Reserved seat identifier.
 * @param pass Reserved seat password.
 * @param err Output error buffer.
 * @param err_cap Output error buffer capacity.
 * @return RP2P_OK on success, RP2P_ERROR on validation failure.
 */
static int rp2p_add_vip(rp2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap)
{
    rp2p_vip_entry_t *vips;
    size_t cap;

    if (!ctx || !id || !pass) return RP2P_ERROR;
    if (!rp2p_is_valid_id(id)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "RP2P_VIP invalid id '%s'", id);
        return RP2P_ERROR;
    }
    if (!rp2p_is_valid_pass_token(pass)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "RP2P_VIP invalid password for id '%s'", id);
        return RP2P_ERROR;
    }
    if (rp2p_find_vip(ctx, id) != SIZE_MAX) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "RP2P_VIP redefines reserved id '%s'", id);
        return RP2P_ERROR;
    }
    if (ctx->n_vips >= ctx->vips_cap) {
        if (ctx->vips_cap > SIZE_MAX / 2) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "RP2P_VIP table capacity overflow");
            return RP2P_ERROR;
        }
        cap = ctx->vips_cap > 0 ? ctx->vips_cap * 2 : 8;
        if (cap > SIZE_MAX / sizeof(*ctx->vips)) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "RP2P_VIP table allocation overflow");
            return RP2P_ERROR;
        }
        vips = (rp2p_vip_entry_t *)realloc(ctx->vips,
            cap * sizeof(*ctx->vips));
        if (!vips) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "failed to allocate RP2P_VIP table");
            return RP2P_ERROR;
        }
        ctx->vips = vips;
        ctx->vips_cap = cap;
    }
    strncpy(ctx->vips[ctx->n_vips].id, id, RP2P_ID_MAX);
    ctx->vips[ctx->n_vips].id[RP2P_ID_MAX] = '\0';
    strncpy(ctx->vips[ctx->n_vips].pass, pass, RP2P_PASS_MAX);
    ctx->vips[ctx->n_vips].pass[RP2P_PASS_MAX] = '\0';
    ctx->n_vips++;
    return RP2P_OK;
}

/**
 * Returns the registration password for one identifier.
 * @param ctx Open context.
 * @param id Service identifier.
 * @return VIP password when reserved, otherwise the global password.
 */
static const char *rp2p_get_register_pass(rp2p_t *ctx, const char *id) {
    size_t idx;

    if (!ctx) return "";
    idx = rp2p_find_vip(ctx, id);
    if (idx != SIZE_MAX) return ctx->vips[idx].pass;
    return ctx->pass;
}

/**
 * Open.
 * @return 0 on success, -1 on error.
 */
int rp2p_open(rp2p_t **out) {
    rp2p_t *ctx;
    if (!out) return RP2P_ERROR;
    ctx = (rp2p_t *)calloc(1, sizeof(rp2p_t));
    if (!ctx) return RP2P_ERROR;
    ctx->peers = NULL;
    ctx->n_peers = 0;
    ctx->peers_alloc = 0;
    ctx->n_peers_cap = 0;
    ctx->nonvip_cap = 0;
    ctx->seats_set = 0;
    ctx->pass[0] = '\0';
    ctx->pow_bits = 0;
    ctx->bind_port = 0;
    ctx->explicit_port = 0;
    ctx->proto = RP2P_PROTO_TCP;
    ctx->n_pow_challenges = 0;
    ctx->conns = NULL;
    ctx->n_conns = 0;
    ctx->conns_cap = 0;
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    ctx->stop_requested = 0;
#ifdef _WIN32
    InitializeCriticalSection(&ctx->mutex);
#else
    pthread_mutex_init(&ctx->mutex, NULL);
#endif

    *out = ctx;
    return RP2P_OK;
}

/**
 * Close.
 * @return 0 on success, -1 on error.
 */
int rp2p_close(rp2p_t *ctx) {
    int i;
    if (!ctx) return RP2P_ERROR;
    for (i = 0; i < ctx->n_conns; i++)
        RP2P_FD_CLOSE(ctx->conns[i].fd);
    if (ctx->conns)
        crypto_wipe(ctx->conns, (size_t)ctx->conns_cap * sizeof(*ctx->conns));
    free(ctx->conns);
    if (ctx->vips)
        crypto_wipe(ctx->vips, ctx->vips_cap * sizeof(*ctx->vips));
    free(ctx->vips);
    if (ctx->peers)
        crypto_wipe(ctx->peers, ctx->peers_alloc * sizeof(*ctx->peers));
    free(ctx->peers);
#ifdef _WIN32
    DeleteCriticalSection(&ctx->mutex);
#else
    pthread_mutex_destroy(&ctx->mutex);
#endif
    crypto_wipe(ctx, sizeof(*ctx));
    free(ctx);
    return RP2P_OK;
}

/**
 * Requests clean termination for the current blocking operation on one context.
 * @param ctx Context to stop.
 * @return 0 on success, -1 on error.
 */
int rp2p_stop(rp2p_t *ctx) {
    if (!ctx) return RP2P_EINVAL;
    atomic_store(&ctx->stop_requested, 1);
    return RP2P_OK;
}

/**
 * Checks whether one context was requested to stop.
 * @return Nonzero if a stop was requested, zero otherwise.
 */
int rp2p_stop_requested(rp2p_t *ctx) {
    return ctx && atomic_load(&ctx->stop_requested);
}

/**
 * Return string for status code.
 * @return Status string.
 */
const char *rp2p_strerror(int code) {
    switch (code) {
        case RP2P_OK:       return "OK";
        case RP2P_ERROR:    return "general error";
        case RP2P_ENET:     return "network error";
        case RP2P_ENOENT:   return "peer not found";
        case RP2P_ETIMEOUT: return "timeout";
        case RP2P_EFULL:    return "peer table full";
        case RP2P_EINVAL:   return "invalid argument";
        case RP2P_EPROTO:   return "protocol error";
        case RP2P_EAUTH:    return "authentication failed";
        case RP2P_EVERSION: return "unsupported protocol version";
        case RP2P_EPUNCH:   return "direct connectivity failed";
        default:              return "unknown error";
    }
}

/**
 * Records one per-context detail error message.
 * @return None.
 */
static void rp2p_set_error(rp2p_t *ctx, const char *fmt, ...) {
    va_list ap;
    if (!ctx) return;
    if (!fmt) { ctx->err_buf[0] = '\0'; return; }
    va_start(ap, fmt);
    vsnprintf(ctx->err_buf, sizeof(ctx->err_buf), fmt, ap);
    va_end(ap);
    ctx->err_buf[sizeof(ctx->err_buf) - 1] = '\0';
}

/**
 * Returns the last per-context detail error message.
 * @return Context-owned string valid until the next update or context close.
 */
const char *rp2p_get_error(rp2p_t *ctx) {
    if (!ctx) return "";
    return ctx->err_buf;
}

/**
 * Returns one caller-owned options struct with safe defaults.
 * Summary: Index port and sweep are populated; callers own the returned struct.
 * @return Default options struct.
 */
rp2p_options_t rp2p_options_default(void) {
    rp2p_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.seats = 0;
    opts.pow = 0;
    opts.sweep = 20;
    return opts;
}

/**
 * Loads RP2P_* environment values into one options struct with strict rules.
 * Summary: Invalid numeric values are ignored and defaults are retained.
 * Initialize with rp2p_options_default and free with rp2p_options_free.
 * @param opts Options struct to populate.
 * @return None.
 */
void rp2p_options_load_env(rp2p_options_t *opts) {
    const char *val;
    long num;
    size_t seats;

    if (!opts) return;

    val = getenv("RP2P_SEATS");
    if (rp2p_parse_size(val, &seats) &&
        seats <= SIZE_MAX / sizeof(rp2p_peer_t))
        opts->seats = seats;

    val = getenv("RP2P_POW");
    if (val && rp2p_parse_env(val, 0, RP2P_POW_MAX, &num))
        opts->pow = (int)num;

    val = getenv("RP2P_SWEEP");
    if (val && rp2p_parse_env(val, 0, RP2P_SWEEP_MAX, &num))
        opts->sweep = (int)num;

    val = getenv("RP2P_PASS");
    if (val) {
        crypto_wipe(opts->pass, sizeof(opts->pass));
        strncpy(opts->pass, val, RP2P_PASS_MAX);
        opts->pass[RP2P_PASS_MAX] = '\0';
    }

    val = getenv("RP2P_VIP");
    if (val) {
        size_t len = strlen(val);
        if (opts->vip) crypto_wipe(opts->vip, strlen(opts->vip));
        free(opts->vip);
        opts->vip = (char *)malloc(len + 1);
        if (opts->vip) memcpy(opts->vip, val, len + 1);
    }

    val = getenv("RP2P_STUN");
    if (val) {
        strncpy(opts->stun_url, val, sizeof(opts->stun_url) - 1);
        opts->stun_url[sizeof(opts->stun_url) - 1] = '\0';
    }
}

/**
 * Options free.
 * @return None.
 */
void rp2p_options_free(rp2p_options_t *opts) {
    if (!opts) return;
    crypto_wipe(opts->pass, sizeof(opts->pass));
    if (opts->vip) crypto_wipe(opts->vip, strlen(opts->vip));
    free(opts->vip);
    opts->vip = NULL;
}

/**
 * Set seats.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_seats(rp2p_t *ctx, size_t seats) {
    if (!ctx) return RP2P_EINVAL;
    if (seats > SIZE_MAX / sizeof(*ctx->peers)) {
        rp2p_set_error(ctx, "seats exceeds the platform allocation range");
        return RP2P_EINVAL;
    }
    ctx->n_peers_cap = seats;
    ctx->seats_set = 1;
    rp2p_update_nonvip_cap(ctx);
    rp2p_set_error(ctx, NULL);
    return RP2P_OK;
}

/**
 * Set pow.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_pow(rp2p_t *ctx, int bits) {
    if (!ctx) return RP2P_EINVAL;
    if (bits < 0 || bits > RP2P_POW_MAX) {
        rp2p_set_error(ctx, "pow must be between 0 and %d", RP2P_POW_MAX);
        return RP2P_EINVAL;
    }
    ctx->pow_bits = bits;
    rp2p_set_error(ctx, NULL);
    return RP2P_OK;
}

/**
 * Configures the local service or listener port used by set and con.
 * Summary: Marks the port as explicit for precedence over arguments.
 * @param ctx  Open context.
 * @param port Local bind port.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_port(rp2p_t *ctx, unsigned short port) {
    if (!ctx) return RP2P_EINVAL;
    if (port == 0) {
        rp2p_set_error(ctx, "port must be between 1 and 65535");
        return RP2P_EINVAL;
    }
    ctx->bind_port = port;
    ctx->explicit_port = 1;
    rp2p_set_error(ctx, NULL);
    return RP2P_OK;
}

/**
 * Set protocol.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_protocol(rp2p_t *ctx, int proto) {
    if (!ctx) return RP2P_EINVAL;
    if (proto != RP2P_PROTO_TCP && proto != RP2P_PROTO_UDP) {
        rp2p_set_error(ctx, "protocol must be RP2P_PROTO_TCP or RP2P_PROTO_UDP");
        return RP2P_EINVAL;
    }
    ctx->proto = proto;
    rp2p_set_error(ctx, NULL);
    return RP2P_OK;
}

/**
 * Set sweep count.
 * @return Status code.
 */
int rp2p_set_sweep(rp2p_t *ctx, int sweep) {
    if (!ctx) return RP2P_EINVAL;
    if (sweep < 0 || sweep > RP2P_SWEEP_MAX) {
        rp2p_set_error(ctx, "sweep must be between 0 and %d", RP2P_SWEEP_MAX);
        return RP2P_EINVAL;
    }
    ctx->sweep = sweep;
    rp2p_set_error(ctx, NULL);
    return RP2P_OK;
}

/**
 * Resolves the effective local port for set or con.
 * Summary: A nonzero argument overrides a default context port, while a nonzero
 * argument conflicting with an explicitly set context port is rejected.
 * @param ctx        Open context.
 * @param arg_port  Port argument from rp2p_wait or rp2p_connect.
 * @param out        Effective port output.
 * @return RP2P_OK on success, RP2P_ERROR on conflicting ports.
 */
static int rp2p_resolve_port(rp2p_t *ctx, unsigned short arg_port,
    unsigned short *out)
{
    if (arg_port == 0) {
        *out = ctx->bind_port;
        return RP2P_OK;
    }
    if (ctx->explicit_port && ctx->bind_port != 0 &&
        ctx->bind_port != arg_port)
        return RP2P_ERROR;
    *out = arg_port;
    return RP2P_OK;
}

/**
 * Stores the shared register password.
 * @param ctx  Open context.
 * @param pass Shared password string.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_pass(rp2p_t *ctx, const char *pass) {
    if (!ctx) return RP2P_EINVAL;
    if (!pass || (pass[0] && !rp2p_is_valid_pass_token(pass))) {
        rp2p_set_error(ctx, "registration password contains invalid bytes");
        return RP2P_EINVAL;
    }
    strncpy(ctx->pass, pass, RP2P_PASS_MAX);
    ctx->pass[RP2P_PASS_MAX] = '\0';
    rp2p_set_error(ctx, NULL);
    return RP2P_OK;
}

/**
 * Parses the VIP seat map from one whitespace-separated string.
 * @param ctx Open context.
 * @param vip Whitespace-separated id/pass pairs.
 * @param err Output error buffer.
 * @param err_cap Output error buffer capacity.
 * @return RP2P_OK on success, RP2P_ERROR on parse failure.
 */
int rp2p_set_vip(
rp2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
)
{
    char *copy;
    char *cursor;

    if (!ctx) return RP2P_ERROR;
    if (ctx->vips)
        crypto_wipe(ctx->vips, ctx->vips_cap * sizeof(*ctx->vips));
    free(ctx->vips);
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    rp2p_update_nonvip_cap(ctx);
    if (!vip || !vip[0]) return RP2P_OK;
    copy = (char *)malloc(strlen(vip) + 1);
    if (!copy) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "failed to allocate RP2P_VIP buffer");
        return RP2P_ERROR;
    }
    strcpy(copy, vip);
    cursor = rp2p_trim(copy);
    while (cursor && *cursor) {
        char *id;
        char *pass;

        id = cursor;
        while (*cursor && !rp2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && rp2p_is_space(*cursor)) cursor++;
        if (!*cursor) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "RP2P_VIP has odd token count");
            crypto_wipe(copy, strlen(vip) + 1);
            free(copy);
            if (ctx->vips)
                crypto_wipe(ctx->vips,
                    ctx->vips_cap * sizeof(*ctx->vips));
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            rp2p_update_nonvip_cap(ctx);
            return RP2P_ERROR;
        }
        pass = cursor;
        while (*cursor && !rp2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && rp2p_is_space(*cursor)) cursor++;
        if (rp2p_add_vip(ctx, id, pass, err, err_cap) != RP2P_OK) {
            crypto_wipe(copy, strlen(vip) + 1);
            free(copy);
            if (ctx->vips)
                crypto_wipe(ctx->vips,
                    ctx->vips_cap * sizeof(*ctx->vips));
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            rp2p_update_nonvip_cap(ctx);
            return RP2P_ERROR;
        }
    }
    crypto_wipe(copy, strlen(vip) + 1);
    free(copy);
    rp2p_update_nonvip_cap(ctx);
    return RP2P_OK;
}

/**
 * Find peer.
 * @return Peer index on success, SIZE_MAX when missing.
 */
static size_t rp2p_find_peer(rp2p_t *ctx, const char *id) {
    size_t i;

    for (i = 0; i < ctx->n_peers; i++) {
        if (strcmp(ctx->peers[i].id, id) == 0)
            return i;
    }
    return SIZE_MAX;
}

/**
 * Evict stale.
 * @return Status code.
 */
static void rp2p_evict_stale(rp2p_t *ctx) {
    uint64_t now;
    size_t i;

    now = rp2p_now_s();
    i = ctx->n_peers;
    while (i > 0) {
        i--;
        if (now - ctx->peers[i].last_seen > RP2P_ETIMEOUT_SEC) {
            if (i < ctx->n_peers - 1) {
                memmove(&ctx->peers[i], &ctx->peers[i + 1],
                    (ctx->n_peers - i - 1) * sizeof(ctx->peers[0]));
            }
            ctx->n_peers--;
        }
    }
}

/**
 * Generate key.
 * @return Status code.
 */
static int rp2p_generate_key(char *out) {
    unsigned char random_bytes[RP2P_KEY_SZ / 2];

    if (!out) return 0;
    if (rp2p_fill_random(random_bytes, sizeof(random_bytes)) != 0)
        return 0;
    return rp2p_hex_encode(random_bytes, sizeof(random_bytes), out,
        RP2P_KEY_SZ + 1);
}

/**
 * Add peer.
 * @return 0 on success, -1 on error.
 */
static int rp2p_add_peer(rp2p_t *ctx, const char *id)
{
    size_t id_len;
    size_t idx;
    int is_vip;

    idx = rp2p_find_peer(ctx, id);
    if (idx != SIZE_MAX) {
        ctx->peers[idx].last_seen = rp2p_now_s();
        if (!rp2p_generate_key(ctx->peers[idx].key))
            return RP2P_ERROR;
        return RP2P_OK;
    }

    is_vip = rp2p_find_vip(ctx, id) != SIZE_MAX;
    if (ctx->seats_set && ctx->n_peers >= ctx->n_peers_cap)
        return RP2P_EFULL;
    if (ctx->n_peers >= SIZE_MAX / sizeof(*ctx->peers))
        return RP2P_ERROR;
    if (ctx->seats_set && !is_vip &&
        rp2p_count_nonvip_peers(ctx) >= ctx->nonvip_cap)
        return RP2P_EFULL;
    if (rp2p_ensure_peer_storage(ctx, ctx->n_peers + 1) != RP2P_OK)
        return RP2P_ERROR;

    id_len = strlen(id);
    if (id_len > RP2P_ID_MAX)
        id_len = RP2P_ID_MAX;
    memcpy(ctx->peers[ctx->n_peers].id, id, id_len);
    ctx->peers[ctx->n_peers].id[id_len] = '\0';

    ctx->peers[ctx->n_peers].last_seen = rp2p_now_s();
    if (!rp2p_generate_key(ctx->peers[ctx->n_peers].key))
        return RP2P_ERROR;
    ctx->n_peers++;
    return RP2P_OK;
}

/**
 * Remove peer.
 * @return 0 on success, -1 on error.
 */
static int rp2p_remove_peer(rp2p_t *ctx, const char *id) {
    size_t idx;

    idx = rp2p_find_peer(ctx, id);
    if (idx == SIZE_MAX) return RP2P_ENOENT;
    if (idx < ctx->n_peers - 1) {
        memmove(&ctx->peers[idx], &ctx->peers[idx + 1],
            (ctx->n_peers - idx - 1) * sizeof(ctx->peers[0]));
    }
    ctx->n_peers--;
    return RP2P_OK;
}

/**
 * Refreshes one existing peer entry.
 * @param ctx  Open context.
 * @param id   Peer identifier.
 * @param addr Peer address.
 * @param port Peer port.
 * @return 0 on success, -1 on error.
 */
static int rp2p_refresh_peer(rp2p_t *ctx, const char *id)
{
    size_t idx;

    idx = rp2p_find_peer(ctx, id);
    if (idx == SIZE_MAX) return RP2P_ENOENT;
    ctx->peers[idx].last_seen = rp2p_now_s();
    return RP2P_OK;
}

/**
 * Finds one pending register challenge.
 * @param ctx     Open context.
 * @param peer_sa Remote peer address.
 * @return Challenge index on success, -1 on failure.
 */
static int rp2p_find_pow_challenge(rp2p_t *ctx,
    const struct sockaddr_storage *peer_sa)
{
    int i;

    for (i = 0; i < ctx->n_pow_challenges; i++) {
        if (rp2p_sockaddr_equal(&ctx->pow_challenges[i].addr, peer_sa))
            return i;
    }
    return -1;
}

/**
 * Removes one pending register challenge.
 * @param ctx Open context.
 * @param idx Challenge index.
 * @return None.
 */
static void rp2p_remove_pow_challenge(rp2p_t *ctx, int idx) {
    if (!ctx || idx < 0 || idx >= ctx->n_pow_challenges) return;
    if (idx < ctx->n_pow_challenges - 1)
        ctx->pow_challenges[idx] = ctx->pow_challenges[ctx->n_pow_challenges - 1];
    ctx->n_pow_challenges--;
}

/**
 * Evicts expired pending register challenges.
 * @param ctx Open context.
 * @param now Current monotonic time in seconds.
 * @return None.
 */
static void rp2p_evict_pow_challenges(rp2p_t *ctx, uint64_t now) {
    int i;

    if (!ctx) return;
    for (i = ctx->n_pow_challenges - 1; i >= 0; i--) {
        if (ctx->pow_challenges[i].expires_at != 0 &&
            now >= ctx->pow_challenges[i].expires_at)
            rp2p_remove_pow_challenge(ctx, i);
    }
}

/**
 * Stores one pending register challenge.
 * @param ctx       Open context.
 * @param peer_sa   Remote peer address.
 * @param id        Challenged service identifier.
 * @param nonce_hex Challenge nonce in hex.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_store_pow_challenge(rp2p_t *ctx,
    const struct sockaddr_storage *peer_sa, const char *id, const char *nonce_hex)
{
    int idx;
    size_t id_len;
    size_t nonce_len;

    idx = rp2p_find_pow_challenge(ctx, peer_sa);
    if (idx < 0) {
        if (ctx->n_pow_challenges >= RP2P_POW_CHALLENGES_MAX) return 0;
        idx = ctx->n_pow_challenges++;
    }
    nonce_len = strlen(nonce_hex);
    if (nonce_len > sizeof(ctx->pow_challenges[idx].nonce_hex) - 1)
        nonce_len = sizeof(ctx->pow_challenges[idx].nonce_hex) - 1;
    memcpy(ctx->pow_challenges[idx].nonce_hex, nonce_hex, nonce_len);
    ctx->pow_challenges[idx].nonce_hex[nonce_len] = '\0';
    ctx->pow_challenges[idx].nonce_hex[16] = '\0';
    id_len = strlen(id);
    if (id_len > sizeof(ctx->pow_challenges[idx].id) - 1)
        id_len = sizeof(ctx->pow_challenges[idx].id) - 1;
    memcpy(ctx->pow_challenges[idx].id, id, id_len);
    ctx->pow_challenges[idx].id[id_len] = '\0';
    ctx->pow_challenges[idx].id[RP2P_ID_MAX] = '\0';
    ctx->pow_challenges[idx].addr = *peer_sa;
    ctx->pow_challenges[idx].issued_at = rp2p_now_s();
    ctx->pow_challenges[idx].expires_at =
        ctx->pow_challenges[idx].issued_at + RP2P_POW_CHALLENGE_TTL_S;
    return 1;
}

/**
 * Formats one successful register reply.
 * @param ctx      Open context.
 * @param id       Registered service identifier.
 * @param reply    Output reply buffer.
 * @param reply_sz Output reply capacity.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_format_register_ok(rp2p_t *ctx, const char *id,
    char *reply, size_t reply_sz)
{
    size_t pidx;

    pidx = rp2p_find_peer(ctx, id);
    if (pidx == SIZE_MAX) return 0;
    snprintf(reply, reply_sz, "%s%s", RP2P_CTRTOK_OK_KEY,
        ctx->peers[pidx].key);
    return 1;
}

/**
 * Conn add.
 * @return 0 on success, -1 on error.
 */
static int rp2p_conn_add(rp2p_t *ctx, rp2p_fd_t fd) {
#ifdef _WIN32
    if (fd == INVALID_SOCKET) return RP2P_ERROR;
#else
    if (fd < 0) return RP2P_ERROR;
    if (fd >= FD_SETSIZE) return RP2P_ERROR;
#endif
    if (ctx->n_conns >= ctx->conns_cap) {
        int new_cap = ctx->conns_cap == 0 ? 64 : ctx->conns_cap * 2;
        rp2p_tcp_conn_t *c = (rp2p_tcp_conn_t *)realloc(
            ctx->conns, (size_t)new_cap * sizeof(rp2p_tcp_conn_t));
        if (!c) return RP2P_ERROR;
        ctx->conns = c;
        ctx->conns_cap = new_cap;
    }
    ctx->conns[ctx->n_conns].fd = fd;
    ctx->conns[ctx->n_conns].buf_len = 0;
    ctx->conns[ctx->n_conns].id[0] = '\0';
    ctx->conns[ctx->n_conns].registered = 0;
    ctx->conns[ctx->n_conns].hello_ok = 0;
    ctx->n_conns++;
    return RP2P_OK;
}

/**
 * Conn remove.
 * @return Status code.
 */
static void rp2p_conn_remove(rp2p_t *ctx, int idx) {
    if (idx < 0 || idx >= ctx->n_conns) return;
    rp2p_fd_t fd = ctx->conns[idx].fd;
    RP2P_FD_CLOSE(fd);
    for (int pi = 0; pi < ctx->n_pending_punches; pi++) {
        if (ctx->pending_punches[pi].consumer_fd == fd) {
            ctx->pending_punches[pi] = ctx->pending_punches[--ctx->n_pending_punches];
            pi--;
        }
    }
    if (idx < ctx->n_conns - 1) {
        memmove(&ctx->conns[idx], &ctx->conns[idx + 1],
            (size_t)(ctx->n_conns - idx - 1) * sizeof(ctx->conns[0]));
    }
    ctx->n_conns--;
}

/**
 * Transfers one registered identifier to its latest control connection.
 * @param ctx Open index context.
 * @param owner Connection receiving ownership.
 * @param id Registered identifier.
 * @return None.
 */
static void rp2p_conn_claim_registration(rp2p_t *ctx,
    rp2p_tcp_conn_t *owner, const char *id)
{
    int i;

    for (i = 0; i < ctx->n_conns; i++) {
        if (&ctx->conns[i] == owner) continue;
        if (ctx->conns[i].registered &&
            strcmp(ctx->conns[i].id, id) == 0)
            ctx->conns[i].registered = 0;
    }
    strcpy(owner->id, id);
    owner->registered = 1;
}

/**
 * Pending punch find.
 * @return index on success, -1 on error.
 */
static int rp2p_pending_punch_find(rp2p_t *ctx, const char *target_id, const char *self_id, const char *sess_id) {
    for (int i = 0; i < ctx->n_pending_punches; i++) {
        if (strcmp(ctx->pending_punches[i].target_id, target_id) == 0 &&
            strcmp(ctx->pending_punches[i].self_id, self_id) == 0 &&
            strcmp(ctx->pending_punches[i].sess_id, sess_id) == 0)
            return i;
    }
    return -1;
}

/**
 * Pending punch remove.
 * @return None.
 */
static void rp2p_pending_punch_remove(rp2p_t *ctx, int idx) {
    if (idx >= 0 && idx < ctx->n_pending_punches)
        ctx->pending_punches[idx] = ctx->pending_punches[--ctx->n_pending_punches];
}

/**
 * Pending punch evict stale.
 * @return None.
 */
static void rp2p_pending_punch_evict_stale(rp2p_t *ctx) {
    uint64_t now = rp2p_now_s();
    for (int i = 0; i < ctx->n_pending_punches; i++) {
        if (now - ctx->pending_punches[i].ts > 30) {
            ctx->pending_punches[i] = ctx->pending_punches[--ctx->n_pending_punches];
            i--;
        }
    }
}

/**
 * Appends text to a bounded output buffer.
 * @param out Output buffer.
 * @param cap Output buffer capacity.
 * @param text Text to append.
 * @return 1 on success, 0 on overflow.
 */
static int rp2p_append_text(char *out, size_t cap, const char *text) {
    size_t used;
    size_t add;

    if (!out || !text || cap == 0) return 0;
    used = strlen(out);
    add = strlen(text);
    if (used >= cap || add >= cap - used) return 0;
    memcpy(out + used, text, add + 1);
    return 1;
}

/**
 * Copies one colon-delimited field from a cursor.
 * @param cursor Input cursor updated after the field.
 * @param out    Output field buffer.
 * @param cap    Output field capacity.
 * @param delim  Required delimiter or NUL for final field.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_field(const char **cursor, char *out, size_t cap,
    char delim)
{
    const char *start;
    const char *end;
    size_t len;

    if (!cursor || !*cursor || !out || cap == 0) return 0;
    start = *cursor;
    end = delim ? strchr(start, delim) : start + strlen(start);
    if (!end) return 0;
    len = (size_t)(end - start);
    if (len == 0 || len >= cap) return 0;
    memcpy(out, start, len);
    out[len] = '\0';
    *cursor = delim ? end + 1 : end;
    return 1;
}

/**
 * Reports whether a token is lowercase or uppercase hexadecimal.
 * @param text Input token.
 * @param len  Required token length.
 * @return 1 when valid, 0 otherwise.
 */
static int rp2p_is_hex_token(const char *text, size_t len) {
    size_t i;

    if (!text || strlen(text) != len) return 0;
    for (i = 0; i < len; i++) {
        if ((text[i] >= '0' && text[i] <= '9') ||
            (text[i] >= 'a' && text[i] <= 'f') ||
            (text[i] >= 'A' && text[i] <= 'F'))
            continue;
        return 0;
    }
    return 1;
}

/**
 * Reports whether a session token is bounded and alphanumeric.
 * @param text Input token.
 * @return 1 when valid, 0 otherwise.
 */
static int rp2p_is_session_token(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= RP2P_CTRL_SESSION_MAX) return 0;
        if (!((text[i] >= 'a' && text[i] <= 'z') ||
            (text[i] >= 'A' && text[i] <= 'Z') ||
            (text[i] >= '0' && text[i] <= '9')))
            return 0;
    }
    return 1;
}

/**
 * Reports whether a transient punch id is bounded and safe.
 * @param text Input token.
 * @return 1 when valid, 0 otherwise.
 */
static int rp2p_is_punch_id(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= RP2P_ID_MAX) return 0;
        if (!((text[i] >= 'a' && text[i] <= 'z') ||
            (text[i] >= 'A' && text[i] <= 'Z') ||
            (text[i] >= '0' && text[i] <= '9') || text[i] == '-'))
            return 0;
    }
    return 1;
}

/**
 * Parses one strict decimal TCP or UDP port.
 * @param text Input token.
 * @param port Output port.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_port_token(const char *text, unsigned short *port) {
    long value;

    if (!port || !rp2p_parse_u(text, 1, 65535, &value)) return 0;
    *port = (unsigned short)value;
    return 1;
}

/**
 * Maps one candidate type token to an internal type.
 * @param text Input candidate type token.
 * @param type Output candidate type.
 * @return 1 on success, 0 on unknown type.
 */
static int rp2p_parse_candidate_type(const char *text,
    rp2p_candidate_type_t *type)
{
    if (!text || !type) return 0;
    if (strcmp(text, "host") == 0) *type = RP2P_CAND_HOST;
    else if (strcmp(text, "lan") == 0) *type = RP2P_CAND_LAN;
    else if (strcmp(text, "public") == 0) *type = RP2P_CAND_PUBLIC;
    else if (strcmp(text, "srflx") == 0) *type = RP2P_CAND_SRFLX;
    else return 0;
    return 1;
}

/**
 * Returns the textual name for one local candidate type.
 * @param type Candidate type.
 * @return Candidate type name.
 */
static const char *rp2p_candidate_type_name(rp2p_candidate_type_t type) {
    if (type == RP2P_CAND_LAN) return "lan";
    if (type == RP2P_CAND_PUBLIC) return "public";
    if (type == RP2P_CAND_SRFLX) return "srflx";
    return "host";
}

/**
 * Returns the address family for one candidate address.
 * @param candidate Candidate to inspect.
 * @return AF_INET, AF_INET6, or AF_UNSPEC.
 */
static int rp2p_candidate_family(const rp2p_candidate_t *candidate) {
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (!candidate) return AF_UNSPEC;
    if (inet_pton(AF_INET, candidate->addr, &ipv4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, candidate->addr, &ipv6) == 1) return AF_INET6;
    return AF_UNSPEC;
}

/**
 * Returns the deterministic local priority for one candidate.
 * @param candidate Candidate to rank.
 * @return Lower priority values are attempted first.
 */
static unsigned int rp2p_candidate_priority(
    const rp2p_candidate_t *candidate)
{
    int family;
    unsigned int base;

    if (!candidate) return 900u;
    family = rp2p_candidate_family(candidate);
    if (family == AF_INET6) base = 100u;
    else if (family == AF_INET) base = 200u;
    else return 900u;
    if (candidate->type == RP2P_CAND_HOST) return base;
    if (candidate->type == RP2P_CAND_LAN) return base + 10u;
    if (candidate->type == RP2P_CAND_PUBLIC) return base + 20u;
    if (candidate->type == RP2P_CAND_SRFLX) return base + 30u;
    if (candidate->type == RP2P_CAND_PRFLX) return base + 40u;
    if (candidate->type == RP2P_CAND_PREDICTED) return base + 50u;
    return 900u;
}

/**
 * Reports whether two candidates describe the same network endpoint.
 * @param a First candidate.
 * @param b Second candidate.
 * @return 1 when equivalent, 0 otherwise.
 */
static int rp2p_candidate_same_endpoint(const rp2p_candidate_t *a,
    const rp2p_candidate_t *b)
{
    struct sockaddr_storage aa;
    struct sockaddr_storage bb;

    if (!a || !b || a->port != b->port) return 0;
    if (rp2p_candidate_family(a) != rp2p_candidate_family(b)) return 0;
    if (!rp2p_candidate_sockaddr(a, &aa)) return 0;
    if (!rp2p_candidate_sockaddr(b, &bb)) return 0;
    return rp2p_sockaddr_equal(&aa, &bb);
}

/**
 * Compares two candidates by local priority and stable textual fields.
 * @param a First candidate.
 * @param b Second candidate.
 * @return Negative, zero, or positive comparison result.
 */
static int rp2p_candidate_compare(const rp2p_candidate_t *a,
    const rp2p_candidate_t *b)
{
    int cmp;

    if (a->priority != b->priority)
        return a->priority < b->priority ? -1 : 1;
    if (a->type != b->type) return (int)a->type - (int)b->type;
    cmp = strcmp(a->addr, b->addr);
    if (cmp != 0) return cmp;
    return (int)a->port - (int)b->port;
}

/**
 * Normalizes candidate priority, removes duplicates, and sorts the list.
 * @param candidates Candidate array.
 * @param count      Candidate count in and out.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_normalize_candidates(rp2p_candidate_t *candidates,
    int *count)
{
    int i;
    int n;

    if (!candidates || !count || *count < 0 || *count > RP2P_CANDIDATES_MAX)
        return 0;
    n = 0;
    for (i = 0; i < *count; i++) {
        int j;
        if (candidates[i].port == 0) return 0;
        if (rp2p_candidate_family(&candidates[i]) == AF_UNSPEC) return 0;
        candidates[i].priority = rp2p_candidate_priority(&candidates[i]);
        if (candidates[i].priority >= 900u) return 0;
        for (j = 0; j < n; j++) {
            if (!rp2p_candidate_same_endpoint(&candidates[j], &candidates[i]))
                continue;
            if (rp2p_candidate_compare(&candidates[i], &candidates[j]) < 0)
                candidates[j] = candidates[i];
            break;
        }
        if (j == n) candidates[n++] = candidates[i];
    }
    for (i = 1; i < n; i++) {
        rp2p_candidate_t item = candidates[i];
        int j = i - 1;
        while (j >= 0 && rp2p_candidate_compare(&item, &candidates[j]) < 0) {
            candidates[j + 1] = candidates[j];
            j--;
        }
        candidates[j + 1] = item;
    }
    *count = n;
    return 1;
}

/**
 * Parses one strict candidate line.
 * @param line Input line.
 * @param out  Output candidate.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_candidate_line(const char *line,
    rp2p_candidate_t *out)
{
    const char *cursor;
    const char *end;
    char type_text[16];
    char addr[RP2P_ADDR_MAX + 1];
    char port_text[8];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    size_t addr_len;

    if (!line || !out || strncmp(line, RP2P_CTRTOK_CAND,
        strlen(RP2P_CTRTOK_CAND)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_CAND);
    if (!rp2p_parse_field(&cursor, type_text, sizeof(type_text), ':'))
        return 0;
    if (*cursor == '[') {
        cursor++;
        end = strchr(cursor, ']');
        if (!end || end[1] != ':') return 0;
        addr_len = (size_t)(end - cursor);
        if (addr_len == 0 || addr_len >= sizeof(addr)) return 0;
        memcpy(addr, cursor, addr_len);
        addr[addr_len] = '\0';
        cursor = end + 2;
    } else {
        if (!rp2p_parse_field(&cursor, addr, sizeof(addr), ':'))
            return 0;
    }
    if (!rp2p_parse_field(&cursor, port_text, sizeof(port_text), '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    if (!rp2p_parse_candidate_type(type_text, &out->type)) return 0;
    if (inet_pton(AF_INET, addr, &ipv4) != 1 &&
        inet_pton(AF_INET6, addr, &ipv6) != 1)
        return 0;
    if (!rp2p_parse_port_token(port_text, &out->port)) return 0;
    snprintf(out->addr, sizeof(out->addr), "%s", addr);
    out->priority = rp2p_candidate_priority(out);
    if (out->priority >= 900u) return 0;
    return 1;
}

/**
 * Finds a complete END-framed block after the current line.
 * @param start First byte after the command line.
 * @param limit One byte past available buffered data.
 * @param end   Output pointer after END line.
 * @return 1 when END is present, 0 otherwise.
 */
static int rp2p_find_end_line(char *start, char *limit, char **end) {
    char *cursor;
    char *newline;

    if (!start || !limit || !end) return 0;
    cursor = start;
    while (cursor < limit &&
        (newline = (char *)memchr(cursor, '\n', (size_t)(limit - cursor))) != NULL)
    {
        size_t len = (size_t)(newline - cursor);
        if (len == strlen(RP2P_CTRTOK_END) &&
            memcmp(cursor, RP2P_CTRTOK_END, strlen(RP2P_CTRTOK_END)) == 0) {
            *end = newline + 1;
            return 1;
        }
        cursor = newline + 1;
    }
    return 0;
}

/**
 * Parse remote candidates.
 * Summary: Parses candidate list from a buffer.
 * @param buf       Input buffer.
 * @param out       Output array.
 * @param out_count Output count.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_remote_candidates(const char *buf,
    rp2p_candidate_t *out, int *out_count)
{
    const char *p;

    if (!buf || !out || !out_count) return 0;
    *out_count = 0;
    p = buf;
    if (strncmp(p, RP2P_CTRTOK_PUNCH_REQ2,
        strlen(RP2P_CTRTOK_PUNCH_REQ2)) == 0 ||
        strncmp(p, RP2P_CTRTOK_PUNCH_OK2,
        strlen(RP2P_CTRTOK_PUNCH_OK2)) == 0 ||
        strncmp(p, RP2P_CTRTOK_PUNCH_CALL2,
        strlen(RP2P_CTRTOK_PUNCH_CALL2)) == 0)
    {
        p = strchr(p, '\n');
        if (!p) return 0;
        p++;
    }
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        char line[128];
        size_t len;

        if (!nl) return 0;
        len = (size_t)(nl - p);
        if (len == 0) return 0;
        if (len == strlen(RP2P_CTRTOK_END) &&
            memcmp(p, RP2P_CTRTOK_END, strlen(RP2P_CTRTOK_END)) == 0)
            return *out_count > 0 &&
                rp2p_normalize_candidates(out, out_count);
        if (len >= sizeof(line)) return 0;
        if (!rp2p_control_bytes_valid(p, len)) return 0;
        memcpy(line, p, len);
        line[len] = '\0';
        if (strncmp(line, RP2P_CTRTOK_CAND,
            strlen(RP2P_CTRTOK_CAND)) != 0)
            return 0;
        if (*out_count >= RP2P_CANDIDATES_MAX) return 0;
        if (!rp2p_parse_candidate_line(line, &out[*out_count])) return 0;
        (*out_count)++;
        p = nl + 1;
    }
    return 0;
}

/**
 * Appends one validated candidate line to a control message.
 * @param msg  Output message buffer.
 * @param cap  Output message capacity.
 * @param line Candidate line.
 * @return 1 on success, 0 on malformed input or overflow.
 */
static int rp2p_append_candidate_line(char *msg, size_t cap,
    const char *line)
{
    rp2p_candidate_t candidate;

    if (!rp2p_parse_candidate_line(line, &candidate)) return 0;
    if (!rp2p_append_text(msg, cap, line)) return 0;
    if (!rp2p_append_text(msg, cap, "\n")) return 0;
    return 1;
}

/**
 * Appends a bounded local candidate line.
 * @param msg       Output message buffer.
 * @param cap       Output message capacity.
 * @param candidate Candidate to append.
 * @return 1 on success, 0 on overflow.
 */
static int rp2p_append_candidate(char *msg, size_t cap,
    const rp2p_candidate_t *candidate)
{
    char cbuf[128];
    int n;

    if (!candidate) return 0;
    if (strchr(candidate->addr, ':')) {
        n = snprintf(cbuf, sizeof(cbuf), "%s%s:[%s]:%u\n",
            RP2P_CTRTOK_CAND, rp2p_candidate_type_name(candidate->type),
            candidate->addr, candidate->port);
    } else {
        n = snprintf(cbuf, sizeof(cbuf), "%s%s:%s:%u\n",
            RP2P_CTRTOK_CAND, rp2p_candidate_type_name(candidate->type),
            candidate->addr, candidate->port);
    }
    if (n < 0 || (size_t)n >= sizeof(cbuf)) return 0;
    return rp2p_append_text(msg, cap, cbuf);
}

/**
 * Copies validated CAND lines from one complete END-framed block.
 * @param cursor Input cursor after the command line.
 * @param end    One byte after END line.
 * @param msg    Output control message.
 * @param cap    Output control message capacity.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_copy_candidate_block(char *cursor, char *end, char *msg,
    size_t cap)
{
    int count;

    count = 0;
    while (cursor < end) {
        char *newline = (char *)memchr(cursor, '\n', (size_t)(end - cursor));
        char line[128];
        size_t len;

        if (!newline) return 0;
        len = (size_t)(newline - cursor);
        if (len == strlen(RP2P_CTRTOK_END) &&
            memcmp(cursor, RP2P_CTRTOK_END, strlen(RP2P_CTRTOK_END)) == 0) {
            if (count == 0) return 0;
            return rp2p_append_text(msg, cap, RP2P_CTRTOK_END "\n");
        }
        if (len == 0 || len >= sizeof(line)) return 0;
        if (count >= RP2P_CANDIDATES_MAX ||
            !rp2p_control_bytes_valid(cursor, len))
            return 0;
        memcpy(line, cursor, len);
        line[len] = '\0';
        if (!rp2p_append_candidate_line(msg, cap, line)) return 0;
        count++;
        cursor = newline + 1;
    }
    return 0;
}

/**
 * Parses a REGISTER command without proof material.
 * @param line Input command line.
 * @param id   Output service id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_register_id(const char *line,
    char id[RP2P_ID_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_REGISTER,
        strlen(RP2P_CTRTOK_REGISTER)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_REGISTER);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(id);
}

/**
 * Parses a REGISTER proof command.
 * @param line     Input command line.
 * @param id       Output service id.
 * @param solution Output solution token.
 * @param proof    Output proof token.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_register_solution(const char *line,
    char id[RP2P_ID_MAX + 1], char solution[17], char proof[65])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_REGISTER,
        strlen(RP2P_CTRTOK_REGISTER)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_REGISTER);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (strncmp(cursor, RP2P_CTRTOK_SOLUTION,
        strlen(RP2P_CTRTOK_SOLUTION)) != 0)
        return 0;
    cursor += strlen(RP2P_CTRTOK_SOLUTION);
    if (!rp2p_parse_field(&cursor, solution, 17, ':')) return 0;
    if (strncmp(cursor, RP2P_CTRTOK_PROOF,
        strlen(RP2P_CTRTOK_PROOF)) != 0)
        return 0;
    cursor += strlen(RP2P_CTRTOK_PROOF);
    if (!rp2p_parse_field(&cursor, proof, 65, '\0')) return 0;
    if (*cursor != '\0') return 0;
    if (!rp2p_is_valid_id(id)) return 0;
    if (strlen(solution) == 0 || strlen(solution) > 16) return 0;
    if (!rp2p_is_hex_token(solution, strlen(solution))) return 0;
    if (!rp2p_is_hex_token(proof, 64)) return 0;
    return 1;
}

/**
 * Parses a PUNCH_REQ2 command line.
 * @param line      Input command line.
 * @param self_id   Output requester id.
 * @param target_id Output target id.
 * @param sess_id   Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_req2(const char *line,
    char self_id[RP2P_ID_MAX + 1], char target_id[RP2P_ID_MAX + 1],
    char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_REQ2,
        strlen(RP2P_CTRTOK_PUNCH_REQ2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_REQ2);
    if (!rp2p_parse_field(&cursor, self_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, target_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_punch_id(self_id) && rp2p_is_valid_id(target_id) &&
        rp2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_ACK2 command line.
 * @param line      Input command line.
 * @param self_id   Output publisher id.
 * @param target_id Output requester id.
 * @param sess_id   Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_ack2(const char *line,
    char self_id[RP2P_ID_MAX + 1], char target_id[RP2P_ID_MAX + 1],
    char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_ACK2,
        strlen(RP2P_CTRTOK_PUNCH_ACK2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_ACK2);
    if (!rp2p_parse_field(&cursor, self_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, target_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(self_id) && rp2p_is_punch_id(target_id) &&
        rp2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_CALL2 command line.
 * @param line    Input command line.
 * @param peer_id Output peer id.
 * @param sess_id Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_call2(const char *line,
    char peer_id[RP2P_ID_MAX + 1], char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_CALL2,
        strlen(RP2P_CTRTOK_PUNCH_CALL2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_CALL2);
    if (!rp2p_parse_field(&cursor, peer_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_punch_id(peer_id) && rp2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_OK2 command line.
 * @param line    Input command line.
 * @param peer_id Output peer id.
 * @param sess_id Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_ok2(const char *line,
    char peer_id[RP2P_ID_MAX + 1], char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_OK2,
        strlen(RP2P_CTRTOK_PUNCH_OK2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_OK2);
    if (!rp2p_parse_field(&cursor, peer_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_punch_id(peer_id) && rp2p_is_session_token(sess_id);
}

/**
 * Parses a DEREGISTER command line.
 * @param line Input command line.
 * @param id   Output service id.
 * @param key  Output registration key.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_deregister(const char *line,
    char id[RP2P_ID_MAX + 1], char key[RP2P_KEY_STR_SZ])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_DEREGISTER,
        strlen(RP2P_CTRTOK_DEREGISTER)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_DEREGISTER);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, ':')) return 0;
    if (strncmp(cursor, RP2P_CTRTOK_KEY, strlen(RP2P_CTRTOK_KEY)) != 0)
        return 0;
    cursor += strlen(RP2P_CTRTOK_KEY);
    if (!rp2p_parse_field(&cursor, key, RP2P_KEY_STR_SZ, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(id) && rp2p_is_hex_token(key, RP2P_KEY_SZ);
}

/**
 * Parses a LOOKUP command line.
 * @param line Input command line.
 * @param id   Output service id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_lookup(const char *line,
    char id[RP2P_ID_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_LOOKUP,
        strlen(RP2P_CTRTOK_LOOKUP)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_LOOKUP);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(id);
}

/**
 * Parses a CHALLENGE response line.
 * @param line Input response line.
 * @param nonce Output nonce token.
 * @param bits Output difficulty bits.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_challenge(const char *line, char nonce[17],
    unsigned int *bits)
{
    const char *cursor;
    char bits_text[16];
    long value;

    if (!line || !bits || strncmp(line, RP2P_CTRTOK_CHALLENGE,
        strlen(RP2P_CTRTOK_CHALLENGE)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_CHALLENGE);
    if (!rp2p_parse_field(&cursor, nonce, 17, ':')) return 0;
    if (!rp2p_parse_field(&cursor, bits_text, sizeof(bits_text), '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    if (!rp2p_is_hex_token(nonce, 16)) return 0;
    if (!rp2p_parse_u(bits_text, 0, 32, &value)) return 0;
    *bits = (unsigned int)value;
    return 1;
}

/**
 * Parses an OK registration response line.
 * @param line Input response line.
 * @param key  Output registration key.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_ok_key(const char *line, char key[RP2P_KEY_STR_SZ]) {
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_OK_KEY,
        strlen(RP2P_CTRTOK_OK_KEY)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_OK_KEY);
    if (!rp2p_parse_field(&cursor, key, RP2P_KEY_STR_SZ, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_hex_token(key, RP2P_KEY_SZ);
}

/**
 * Parses a UDP punch packet.
 * @param text     Input packet text.
 * @param prefix   Required packet prefix.
 * @param sess_id  Output session id.
 * @param from_id  Output source id.
 * @param to_id    Output destination id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_packet(const char *text, const char *prefix,
    char sess_id[RP2P_CTRL_SESSION_MAX + 1],
    char from_id[RP2P_ID_MAX + 1], char to_id[RP2P_ID_MAX + 1])
{
    const char *cursor;
    size_t prefix_len;

    if (!text || !prefix) return 0;
    prefix_len = strlen(prefix);
    if (strncmp(text, prefix, prefix_len) != 0) return 0;
    cursor = text + prefix_len;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, from_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, to_id, RP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    while (to_id[0]) {
        size_t len = strlen(to_id);
        if (to_id[len - 1] != '\n' && to_id[len - 1] != '\r') break;
        to_id[len - 1] = '\0';
    }
    return rp2p_is_session_token(sess_id) && rp2p_is_punch_id(from_id) &&
        rp2p_is_punch_id(to_id);
}

#define RP2P_STUN_ATTR_DATA 0x0013

/**
 * STUN put16.
 * @return None.
 */
static void rp2p_stun_put16(unsigned char *b, int o, int v) {
    b[o] = (unsigned char)(v >> 8); b[o + 1] = (unsigned char)(v);
}

/**
 * STUN length.
 * @return None.
 */
static void rp2p_stun_len(unsigned char *buf, int o) {
    rp2p_stun_put16(buf, 2, o - 20);
}

/**
 * STUN gen id.
 * @return None.
 */
static int rp2p_stun_gen_id(unsigned char id[12]) {
    return rp2p_fill_random(id, 12) == 0;
}

/**
 * STUN build.
 * @return offset after header.
 */
static int rp2p_stun_build(unsigned char *buf, int mt, const unsigned char id[12]) {
    memset(buf, 0, 20);
    rp2p_stun_put16(buf, 0, mt);
    rp2p_stun_put16(buf, 4, 0x2112); buf[6] = 0xA4; buf[7] = 0x42;
    memcpy(buf + 8, id, 12);
    return 20;
}

/**
 * STUN hdr.
 * @return message type, or -1 on error.
 */
static int rp2p_stun_hdr(const unsigned char *buf, int len, unsigned char id[12]) {
    if (len < 20) return -1;
    uint32_t mg = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
        ((uint32_t)buf[6] << 8) | buf[7];
    if (mg != RP2P_STUN_MAGIC) return -1;
    int msg_len = (buf[2] << 8) | buf[3];
    if (msg_len & 3) return -1;
    if (20 + msg_len > len) return -1;
    int mt = (buf[0] << 8) | buf[1];
    memcpy(id, buf + 8, 12);
    return mt;
}

/**
 * STUN find attr.
 * @return offset of attr, or -1.
 */
static int rp2p_stun_find(const unsigned char *buf, int len, int t, int *al) {
    int o = 20;
    while (o + 4 <= len) {
        int at = (buf[o] << 8) | buf[o + 1];
        int av = (buf[o + 2] << 8) | buf[o + 3];
        int pad = (av & 3) ? 4 - (av & 3) : 0;
        if (o + 4 + av > len) return -1;
        if (at == t) { if (al) *al = av; return o + 4; }
        o += 4 + av + pad;
    }
    return -1;
}

/**
 * STUN rd xaddr.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stun_rd_xaddr(const unsigned char *buf, int o, int al,
    unsigned char id[12], char *addr, int acap, unsigned short *port)
{
    (void)id;
    if (al < 8) return -1;
    if (buf[o + 1] != 1) return -1;
    unsigned short xp = ((unsigned short)buf[o + 2] << 8) | buf[o + 3];
    uint32_t xa = ((uint32_t)buf[o + 4] << 24) | ((uint32_t)buf[o + 5] << 16) |
        ((uint32_t)buf[o + 6] << 8) | buf[o + 7];
    *port = xp ^ (unsigned short)(RP2P_STUN_MAGIC >> 16);
    uint32_t a = xa ^ RP2P_STUN_MAGIC;
    snprintf(addr, (size_t)acap, "%u.%u.%u.%u",
        (unsigned)(a >> 24) & 0xff, (unsigned)(a >> 16) & 0xff,
        (unsigned)(a >> 8) & 0xff, (unsigned)(a & 0xff));
    return 0;
}

/**
 * STUN binding.
 * Summary: Sends Binding Request and returns srflx ip:port for udp_fd.
 * @param ctx      RP2P context.
 * @param udp_fd   Bound UDP socket.
 * @param out_ip   Output address buffer.
 * @param out_cap  Output address buffer size.
 * @param out_port Output port.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stun_binding(rp2p_t *ctx, int udp_fd,
    char *out_ip, int out_cap, unsigned short *out_port)
{
    unsigned char tx[4096], rx[4096], tx_id[12], rx_id[12];
    char host[256];
    unsigned short port;
    struct sockaddr_storage from;
    socklen_t from_len;
    struct sockaddr_storage srv;
    socklen_t srv_len;
    fd_set rfds;
    struct timeval tv;
    int off, rl, n, mt, ao, al;
    size_t sl;

    if (!ctx || !ctx->stun_url[0] || !out_ip || out_cap <= 0 || !out_port)
        return -1;

    const char *p = ctx->stun_url;
    const char *co;
    long lport;

    if (strncmp(p, "stun:", 5) != 0) return -1;
    p += 5;

    co = strchr(p, ':');
    if (!co || co == p) return -1;

    sl = (size_t)(co - p);
    if (sl >= sizeof(host)) return -1;
    memcpy(host, p, sl);
    host[sl] = '\0';

    if (*(co + 1) == '\0') return -1;
    if (!rp2p_parse_u(co + 1, 1, 65535, &lport)) return -1;
    port = (unsigned short)lport;

    if (rp2p_resolve(host, port, SOCK_DGRAM, &srv, &srv_len) != 0) return -1;
    if (srv.ss_family != AF_INET) return -1;

    if (!rp2p_stun_gen_id(tx_id)) return -1;
    off = rp2p_stun_build(tx, RP2P_STUN_BINDING, tx_id);
    rp2p_stun_len(tx, off);

    if (sendto(udp_fd, (const char *)tx, (size_t)off, 0,
        (const struct sockaddr *)&srv, srv_len) < 0) return -1;

    FD_ZERO(&rfds);
    if (!rp2p_fdset_add(udp_fd, &rfds, NULL)) return -1;
    tv.tv_sec = 3; tv.tv_usec = 0;
    n = select(udp_fd + 1, &rfds, NULL, NULL, &tv);
    if (n <= 0) return -1;
    from_len = sizeof(from);
    rl = (int)recvfrom(udp_fd, (char *)rx, sizeof(rx), 0,
        (struct sockaddr *)&from, &from_len);
    if (rl < 20) return -1;
    if (!rp2p_sockaddr_equal(&from, &srv)) return -1;

    mt = rp2p_stun_hdr(rx, rl, rx_id);
    if (mt != RP2P_STUN_BINDING_RESP) return -1;
    if (memcmp(tx_id, rx_id, sizeof(tx_id)) != 0) return -1;

    ao = rp2p_stun_find(rx, rl, RP2P_STUN_ATTR_XOR_MAPPED_ADDR, &al);
    if (ao < 0) return -1;
    if (rp2p_stun_rd_xaddr(rx, ao, al, tx_id, out_ip, out_cap, out_port) != 0)
        return -1;
    return 0;
}

/**
 * Set stun url.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_stun_url(rp2p_t *ctx, const char *url) {
    if (!ctx) return RP2P_ERROR;
    if (url) {
        strncpy(ctx->stun_url, url, sizeof(ctx->stun_url) - 1);
        ctx->stun_url[sizeof(ctx->stun_url) - 1] = '\0';
    } else {
        ctx->stun_url[0] = '\0';
    }
    return RP2P_OK;
}

/**
 * Gather candidates.
 * Summary: Gathers candidates for hole punching.
 * @param udp_fd     UDP socket fd.
 * @param index_host Index hostname.
 * @param index_port Index port.
 * @param out        Output array.
 * @param out_cap    Array capacity.
 * @param out_count  Output count.
 * @return 0 on success, -1 on error.
 */
int rp2p_gather_candidates(rp2p_t *ctx, int udp_fd,
    rp2p_candidate_t *out, int out_cap, int *out_count) {
    struct sockaddr_storage udp_sa;
    char stun_ip[RP2P_ADDR_MAX + 1];
    unsigned short stun_port;
    socklen_t udp_sa_len = sizeof(udp_sa);

    stun_ip[0] = '\0';
    stun_port = 0;
    *out_count = 0;
    if (getsockname(udp_fd, (struct sockaddr *)&udp_sa, &udp_sa_len) == 0) {
        unsigned short udp_port = rp2p_sockaddr_port(&udp_sa);
        if (*out_count < out_cap) {
            out[*out_count].type = RP2P_CAND_HOST;
            if (udp_sa.ss_family == AF_INET6)
                strcpy(out[*out_count].addr, "::1");
            else
                strcpy(out[*out_count].addr, "127.0.0.1");
            out[*out_count].port = udp_port;
            out[*out_count].priority = rp2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
        
        rp2p_fd_t test_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (!RP2P_ISERR(test_fd)) {
            struct sockaddr_in target;
            memset(&target, 0, sizeof(target));
            target.sin_family = AF_INET;
            target.sin_port = htons(53);
            inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
            
            if (connect(test_fd, (struct sockaddr *)&target, sizeof(target)) == 0) {
                struct sockaddr_in local_sa;
                socklen_t local_sa_len = sizeof(local_sa);
                if (getsockname(test_fd, (struct sockaddr *)&local_sa, &local_sa_len) == 0) {
                    char local_ip[64];
                    inet_ntop(AF_INET, &local_sa.sin_addr, local_ip, sizeof(local_ip));
                    
                    if (strcmp(local_ip, "127.0.0.1") != 0 && strcmp(local_ip, "0.0.0.0") != 0 && *out_count < out_cap) {
                        out[*out_count].type = RP2P_CAND_LAN;
                        strcpy(out[*out_count].addr, local_ip);
                        out[*out_count].port = udp_port;
                        out[*out_count].priority = rp2p_candidate_priority(&out[*out_count]);
                        (*out_count)++;
                    }
                }
            }
            RP2P_FD_CLOSE(test_fd);
        }

        if (ctx && ctx->stun_url[0]) {
            rp2p_stun_binding(ctx, udp_fd, stun_ip, (int)sizeof(stun_ip),
                &stun_port);
        }
        if (stun_ip[0] != '\0' && *out_count < out_cap) {
            unsigned short srflx_port = stun_port ? stun_port : udp_port;
            out[*out_count].type = RP2P_CAND_SRFLX;
            snprintf(out[*out_count].addr, sizeof(out[*out_count].addr),
                "%.47s", stun_ip);
            out[*out_count].port = srflx_port;
            out[*out_count].priority = rp2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
    }
    if (!rp2p_normalize_candidates(out, out_count)) return RP2P_ERROR;
    return RP2P_OK;
}

/**
 * Converts a candidate into a socket address.
 * @param candidate Candidate to convert.
 * @param out       Output socket address.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_candidate_sockaddr(const rp2p_candidate_t *candidate,
    struct sockaddr_storage *out)
{
    struct sockaddr_in *v4;
    struct sockaddr_in6 *v6;

    if (!candidate || !out || candidate->port == 0) return 0;
    memset(out, 0, sizeof(*out));
    v4 = (struct sockaddr_in *)out;
    if (inet_pton(AF_INET, candidate->addr, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(candidate->port);
        return 1;
    }
    v6 = (struct sockaddr_in6 *)out;
    if (inet_pton(AF_INET6, candidate->addr, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(candidate->port);
        return 1;
    }
    return 0;
}

/**
 * Sends one punch packet to one candidate endpoint.
 * @param udp_fd      UDP socket fd.
 * @param candidate   Candidate endpoint.
 * @param ping_msg    Punch packet text.
 * @param unsupported Unsupported candidate counter.
 * @return 1 when a packet was sent, 0 otherwise.
 */
static int rp2p_punch_send_candidate(int udp_fd,
    const rp2p_candidate_t *candidate, const char *ping_msg,
    int *unsupported)
{
    struct sockaddr_storage cand_sa;
    socklen_t cand_len;

    if (!rp2p_candidate_sockaddr(candidate, &cand_sa)) {
        if (unsupported) (*unsupported)++;
        return 0;
    }
    cand_len = rp2p_sockaddr_len(&cand_sa);
    if (cand_len == 0) {
        if (unsupported) (*unsupported)++;
        return 0;
    }
    return sendto(udp_fd, ping_msg, strlen(ping_msg), 0,
        (struct sockaddr *)&cand_sa, cand_len) >= 0;
}

/**
 * Waits for one valid punch response within the monotonic deadline.
 * @param udp_fd       UDP socket fd.
 * @param session_id   Expected session id.
 * @param from_id      Local peer id.
 * @param to_id        Remote peer id.
 * @param wait_ms      Maximum wait for this step.
 * @param deadline_ms  Absolute monotonic deadline.
 * @param selected_addr Output selected address.
 * @param malformed    Malformed packet counter.
 * @param mismatched   Session or peer mismatch counter.
 * @return RP2P_OK on valid response, RP2P_ETIMEOUT otherwise.
 */
static int rp2p_punch_wait_response(int udp_fd, const char *session_id,
    const char *from_id, const char *to_id, int wait_ms, uint64_t deadline_ms,
    struct sockaddr_storage *selected_addr, int *malformed, int *mismatched)
{
    uint64_t wait_deadline_ms;

    wait_deadline_ms = rp2p_now_ms() + (uint64_t)wait_ms;
    if (wait_deadline_ms > deadline_ms) wait_deadline_ms = deadline_ms;
    while (rp2p_now_ms() < wait_deadline_ms) {
        char recv_buf[1024];
        struct sockaddr_storage src_addr;
        socklen_t src_len = sizeof(src_addr);
        uint64_t now;
        int remaining_ms;
        fd_set readfds;
        struct timeval tv;
        int n;

        now = rp2p_now_ms();
        remaining_ms = (int)(wait_deadline_ms - now);
        FD_ZERO(&readfds);
        if (!rp2p_fdset_add(udp_fd, &readfds, NULL)) return RP2P_ENET;
        tv.tv_sec = remaining_ms / 1000;
        tv.tv_usec = (remaining_ms % 1000) * 1000;
        if (select(udp_fd + 1, &readfds, NULL, NULL, &tv) <= 0)
            return RP2P_ETIMEOUT;
        n = recvfrom(udp_fd, recv_buf, sizeof(recv_buf) - 1, 0,
            (struct sockaddr *)&src_addr, &src_len);
        if (n > 0) {
            char rx_sess[64] = {0};
            char rx_from[RP2P_ID_MAX + 1] = {0};
            char rx_to[RP2P_ID_MAX + 1] = {0};
            int is_ping;
            int is_pong;

            recv_buf[n] = '\0';
            is_pong = rp2p_parse_punch_packet(recv_buf,
                RP2P_CTRTOK_PUNCH_PONG,
                rx_sess, rx_from, rx_to);
            is_ping = 0;
            if (!is_pong) {
                is_ping = rp2p_parse_punch_packet(recv_buf,
                    RP2P_CTRTOK_PUNCH_PING, rx_sess, rx_from, rx_to);
            }
            if (!is_ping && !is_pong) {
                if (malformed) (*malformed)++;
                continue;
            }
            if (((is_ping && strcmp(rx_from, to_id) == 0 &&
                strcmp(rx_to, from_id) == 0) ||
                (is_pong && strcmp(rx_from, from_id) == 0 &&
                strcmp(rx_to, to_id) == 0)) &&
                strcmp(rx_sess, session_id) == 0)
            {
                *selected_addr = src_addr;
                if (is_ping) {
                    char pong_msg[256];
                    snprintf(pong_msg, sizeof(pong_msg), "%s%s:%s:%s\n",
                        RP2P_CTRTOK_PUNCH_PONG, session_id, to_id, from_id);
                    sendto(udp_fd, pong_msg, strlen(pong_msg), 0,
                        (struct sockaddr *)&src_addr, src_len);
                }
                return RP2P_OK;
            }
            if (mismatched) (*mismatched)++;
        }
    }
    return RP2P_ETIMEOUT;
}

/**
 * Punch select.
 * Summary: Selects a candidate and performs hole punching.
 * @param ctx                   Context.
 * @param udp_fd                 UDP socket fd.
 * @param session_id             Session ID.
 * @param from_id                From peer ID.
 * @param to_id                  To peer ID.
 * @param remote_candidates      Remote candidate array.
 * @param remote_candidate_count Remote candidate count.
 * @param selected_addr          Selected output address.
 * @return 0 on success, -1 on error.
 */
int rp2p_punch_select(rp2p_t *ctx, int sweep_limit, int udp_fd, const char *session_id, const char *from_id, const char *to_id, const rp2p_candidate_t *remote_candidates, int remote_candidate_count, struct sockaddr_storage *selected_addr) {
    char ping_msg[256];
    uint64_t deadline_ms;
    int direct_count;
    int sent_count;
    int malformed_count;
    int mismatch_count;
    int unsupported_count;

    (void)ctx;
    if (remote_candidate_count <= 0) {
        fprintf(stderr, "rp2p: punch failed: no candidates\n");
        return RP2P_ERROR;
    }
    if (sweep_limit < 0) sweep_limit = 0;
    deadline_ms = rp2p_now_ms() + RP2P_PUNCH_TOTAL_MS;
    direct_count = 0;
    sent_count = 0;
    malformed_count = 0;
    mismatch_count = 0;
    unsupported_count = 0;
    for (int c = 0; c < remote_candidate_count; c++) {
        if (remote_candidates[c].priority < 300u) direct_count++;
    }
    snprintf(ping_msg, sizeof(ping_msg), "%s%s:%s:%s\n",
        RP2P_CTRTOK_PUNCH_PING, session_id, from_id, to_id);
    for (int i = 0; direct_count > 0 && i < RP2P_PUNCH_DIRECT_ROUNDS; i++) {
        for (int c = 0; c < remote_candidate_count; c++) {
            if (remote_candidates[c].priority >= 300u) continue;
            sent_count += rp2p_punch_send_candidate(udp_fd,
                &remote_candidates[c], ping_msg, &unsupported_count);
        }
        if (rp2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
            RP2P_PUNCH_DIRECT_WAIT_MS, deadline_ms, selected_addr,
            &malformed_count, &mismatch_count) == RP2P_OK)
            return RP2P_OK;
    }
    for (int sweep = 1; sweep <= sweep_limit && rp2p_now_ms() < deadline_ms;
        sweep++)
    {
        for (int sign = -1; sign <= 1 && rp2p_now_ms() < deadline_ms;
            sign += 2)
        {
            int offset = sweep * sign;
            for (int c = 0; c < remote_candidate_count; c++) {
                struct sockaddr_storage exact_sa;
                int test_port;

                sent_count += rp2p_punch_send_candidate(udp_fd,
                    &remote_candidates[c], ping_msg, &unsupported_count);
                if (!rp2p_candidate_sockaddr(&remote_candidates[c], &exact_sa))
                    continue;
                if (exact_sa.ss_family != AF_INET) continue;
                if (remote_candidates[c].type != RP2P_CAND_SRFLX &&
                    remote_candidates[c].type != RP2P_CAND_PUBLIC)
                    continue;
                test_port = remote_candidates[c].port + offset;
                if (test_port <= 0 || test_port > 65535) continue;
                rp2p_sockaddr_set_port(&exact_sa, (unsigned short)test_port);
                if (rp2p_sendto_addr(udp_fd, ping_msg, strlen(ping_msg),
                    &exact_sa) >= 0)
                    sent_count++;
            }
            if (rp2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
                RP2P_PUNCH_SWEEP_WAIT_MS, deadline_ms, selected_addr,
                &malformed_count, &mismatch_count) == RP2P_OK)
                return RP2P_OK;
        }
    }
    if (sent_count == 0) {
        rp2p_set_error(ctx, "punch: no valid peer candidates");
        fprintf(stderr, "rp2p: punch failed: all candidates invalid or unsupported\n");
    } else if (malformed_count > 0) {
        rp2p_set_error(ctx, "punch: malformed peer response");
        fprintf(stderr, "rp2p: punch failed: malformed peer packet\n");
    } else if (mismatch_count > 0) {
        rp2p_set_error(ctx, "punch: peer session identity mismatch");
        fprintf(stderr, "rp2p: punch failed: session mismatch\n");
    } else if (unsupported_count > 0) {
        rp2p_set_error(ctx, "punch: peer address family unsupported");
        fprintf(stderr, "rp2p: punch failed: address family mismatch\n");
    } else if (rp2p_now_ms() >= deadline_ms) {
        rp2p_set_error(ctx, "punch: direct connectivity timed out");
        fprintf(stderr, "rp2p: punch failed: timeout\n");
    } else {
        rp2p_set_error(ctx, "punch: direct connectivity attempts exhausted");
        fprintf(stderr, "rp2p: punch failed: all attempts exhausted\n");
    }
    return RP2P_EPUNCH;
}

typedef struct {
    rp2p_t *ctx;
    rp2p_fd_t listener_fd;
    fd_set readable_fds;
    int max_fd;
    int platform_initialized;
} rp2p_index_runtime_t;

typedef enum {
    RP2P_INDEX_ACTION_KEEP,
    RP2P_INDEX_ACTION_REMOVE,
    RP2P_INDEX_ACTION_INCOMPLETE
} rp2p_index_action_t;

/**
 * Opens the index listener and records its owned runtime resources.
 * @param runtime Runtime receiving the listener and context reference.
 * @param ctx Index context.
 * @param host Listener host or NULL for the wildcard address.
 * @param port Listener port.
 * @return RP2P_OK on success, or a negative error code on failure.
 */
static int rp2p_index_runtime_initialize(
rp2p_index_runtime_t *runtime,
rp2p_t *ctx,
const char *host,
unsigned short port)
{
    struct addrinfo hints;
    struct addrinfo *addresses;
    struct addrinfo *address;
    char port_text[16];
    int result;

    memset(runtime, 0, sizeof(*runtime));
    runtime->ctx = ctx;
    runtime->listener_fd = RP2P_FD_INVALID;
    if (rp2p_platform_init() != 0) {
        rp2p_set_error(ctx, "index: platform init failed");
        return RP2P_ENET;
    }
    runtime->platform_initialized = 1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = host ? AF_UNSPEC : AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);
    result = getaddrinfo(host, port_text, &hints, &addresses);
    if (result != 0 && !host) {
        hints.ai_family = AF_INET;
        result = getaddrinfo(host, port_text, &hints, &addresses);
    }
    if (result != 0) {
        rp2p_set_error(ctx, "index: resolve %s:%u failed (%s)",
            host ? host : "*", (unsigned)port, gai_strerror(result));
        rp2p_platform_cleanup();
        runtime->platform_initialized = 0;
        return RP2P_ENET;
    }
    for (address = addresses; address; address = address->ai_next) {
        int reuse;

        runtime->listener_fd = socket(address->ai_family,
            address->ai_socktype, address->ai_protocol);
        if (RP2P_ISERR(runtime->listener_fd)) continue;
        reuse = 1;
        setsockopt(runtime->listener_fd, SOL_SOCKET, SO_REUSEADDR,
            (void *)&reuse, sizeof(reuse));
#ifdef IPV6_V6ONLY
        if (address->ai_family == AF_INET6) {
            int v6only;

            v6only = 0;
            setsockopt(runtime->listener_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                (void *)&v6only, sizeof(v6only));
        }
#endif
        if (bind(runtime->listener_fd, address->ai_addr,
            (socklen_t)address->ai_addrlen) == 0 &&
            listen(runtime->listener_fd, 32) == 0)
            break;
        RP2P_FD_CLOSE(runtime->listener_fd);
        runtime->listener_fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(addresses);
    if (RP2P_ISERR(runtime->listener_fd)) {
        rp2p_set_error(ctx, "index: bind/listen %s:%u failed",
            host ? host : "*", (unsigned)port);
        rp2p_platform_cleanup();
        runtime->platform_initialized = 0;
        return RP2P_ENET;
    }
    rp2p_set_nonblock(runtime->listener_fd);
    return RP2P_OK;
}

/**
 * Removes one disconnected connection and its associated index state.
 * @param ctx Locked index context.
 * @param connection_index Connection index to remove.
 * @return None.
 */
static void rp2p_index_disconnect(rp2p_t *ctx, int connection_index) {
    rp2p_tcp_conn_t *connection;
    struct sockaddr_storage peer_address;
    socklen_t peer_address_length;
    int challenge_index;

    connection = &ctx->conns[connection_index];
    memset(&peer_address, 0, sizeof(peer_address));
    peer_address_length = sizeof(peer_address);
    if (getpeername(connection->fd, (struct sockaddr *)&peer_address,
        &peer_address_length) == 0)
    {
        challenge_index = rp2p_find_pow_challenge(ctx, &peer_address);
    } else {
        challenge_index = -1;
    }
    if (challenge_index >= 0)
        rp2p_remove_pow_challenge(ctx, challenge_index);
    if (connection->registered) {
        rp2p_remove_peer(ctx, connection->id);
        fprintf(stderr, "rp2p: peer '%s' disconnected\n", connection->id);
    }
    rp2p_conn_remove(ctx, connection_index);
}

/**
 * Evicts expired registration challenges at the event-loop cadence.
 * @param ctx Locked index context.
 * @return None.
 */
static void rp2p_index_cleanup_stale_challenges(rp2p_t *ctx) {
    rp2p_evict_pow_challenges(ctx, rp2p_now_s());
}

/**
 * Evicts expired publishers immediately before list enumeration.
 * @param ctx Locked index context.
 * @return None.
 */
static void rp2p_index_cleanup_stale_peers(rp2p_t *ctx) {
    rp2p_evict_stale(ctx);
}

/**
 * Evicts expired pending punches immediately before pending insertion.
 * @param ctx Locked index context.
 * @return None.
 */
static void rp2p_index_cleanup_stale_punches(rp2p_t *ctx) {
    rp2p_pending_punch_evict_stale(ctx);
}

/**
 * Handles protocol version negotiation for one complete control line.
 * @param connection Connection receiving the HELLO command.
 * @param command_line Complete control line.
 * @return KEEP after a valid HELLO, REMOVE on a version violation, or
 * INCOMPLETE when the line is not a HELLO command.
 */
static rp2p_index_action_t rp2p_index_handle_hello(
rp2p_tcp_conn_t *connection,
const char *command_line)
{
    if (strcmp(command_line, RP2P_CTRTOK_HELLO) == 0) {
        if (connection->hello_ok) {
            rp2p_tcp_send(connection->fd,
                RP2P_CTRTOK_ERROR_VERSION_MISMATCH);
            return RP2P_INDEX_ACTION_REMOVE;
        }
        connection->hello_ok = 1;
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_HELLO_OK);
        return RP2P_INDEX_ACTION_KEEP;
    }
    if (strncmp(command_line, RP2P_CTRTOK_HELLO,
        strlen(RP2P_CTRTOK_HELLO) - strlen("RP2P/1")) == 0 ||
        !connection->hello_ok)
    {
        rp2p_tcp_send(connection->fd,
            RP2P_CTRTOK_ERROR_VERSION_MISMATCH);
        return RP2P_INDEX_ACTION_REMOVE;
    }
    return RP2P_INDEX_ACTION_INCOMPLETE;
}

/**
 * Completes a REGISTER proof exchange and claims registration ownership.
 * @param ctx Locked index context.
 * @param connection Registering connection.
 * @param command_line Complete REGISTER proof command.
 * @param peer_address Remote connection address.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_register_proof(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line,
const struct sockaddr_storage *peer_address)
{
    char id[RP2P_ID_MAX + 1];
    char solution[17];
    char proof[65];
    char reply[RP2P_BUF];
    const char *register_pass;
    int challenge_index;

    memset(solution, 0, sizeof(solution));
    memset(proof, 0, sizeof(proof));
    if (rp2p_parse_register_solution(command_line, id, solution, proof)) {
        uint64_t now;

        now = rp2p_now_s();
        register_pass = rp2p_get_register_pass(ctx, id);
        challenge_index = rp2p_find_pow_challenge(ctx, peer_address);
        if (challenge_index < 0 ||
            (ctx->pow_challenges[challenge_index].expires_at != 0 &&
            now >= ctx->pow_challenges[challenge_index].expires_at) ||
            strcmp(ctx->pow_challenges[challenge_index].id, id) != 0 ||
            !rp2p_verify_register_pow(register_pass,
                ctx->pow_challenges[challenge_index].nonce_hex, id,
                solution, proof, ctx->pow_bits))
        {
            if (challenge_index >= 0)
                rp2p_remove_pow_challenge(ctx, challenge_index);
            rp2p_tcp_send(connection->fd, RP2P_CTRTOK_AUTH_FAILED);
            crypto_wipe(solution, sizeof(solution));
            crypto_wipe(proof, sizeof(proof));
            return RP2P_INDEX_ACTION_KEEP;
        }
        rp2p_remove_pow_challenge(ctx, challenge_index);
        if (rp2p_add_peer(ctx, id) == RP2P_OK &&
            rp2p_format_register_ok(ctx, id, reply, sizeof(reply)))
        {
            rp2p_tcp_send(connection->fd, reply);
            rp2p_conn_claim_registration(ctx, connection, id);
        } else {
            rp2p_tcp_send(connection->fd,
                RP2P_CTRTOK_ERROR_PEER_TABLE_FULL);
        }
    } else {
        challenge_index = rp2p_find_pow_challenge(ctx, peer_address);
        if (challenge_index >= 0)
            rp2p_remove_pow_challenge(ctx, challenge_index);
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_AUTH_FAILED);
    }
    crypto_wipe(solution, sizeof(solution));
    crypto_wipe(proof, sizeof(proof));
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Refreshes an owned registration and returns its existing key.
 * @param ctx Locked index context.
 * @param connection Connection owning the registration.
 * @param id Registration identifier.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_register_refresh(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *id)
{
    char reply[RP2P_BUF];

    if (rp2p_refresh_peer(ctx, id) == RP2P_OK &&
        rp2p_format_register_ok(ctx, id, reply, sizeof(reply)))
    {
        rp2p_tcp_send(connection->fd, reply);
    } else {
        rp2p_tcp_send(connection->fd,
            RP2P_CTRTOK_ERROR_NOT_REGISTERED);
    }
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Issues and stores a new registration challenge for one remote address.
 * @param ctx Locked index context.
 * @param connection Connection requesting registration.
 * @param peer_address Remote connection address.
 * @param id Requested registration identifier.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_register_challenge(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const struct sockaddr_storage *peer_address,
const char *id)
{
    unsigned char nonce[8];
    char nonce_hex[17];
    char reply[RP2P_BUF];

    if (ctx->n_pow_challenges >= RP2P_POW_CHALLENGES_MAX &&
        rp2p_find_pow_challenge(ctx, peer_address) < 0)
    {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_BUSY);
        return RP2P_INDEX_ACTION_KEEP;
    }
    memset(nonce, 0, sizeof(nonce));
    memset(nonce_hex, 0, sizeof(nonce_hex));
    if (rp2p_fill_random(nonce, sizeof(nonce)) != 0 ||
        !rp2p_hex_encode(nonce, sizeof(nonce), nonce_hex,
            sizeof(nonce_hex)))
    {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_RANDOM);
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(nonce_hex, sizeof(nonce_hex));
        return RP2P_INDEX_ACTION_KEEP;
    }
    snprintf(reply, sizeof(reply), "%s%s:%d", RP2P_CTRTOK_CHALLENGE,
        nonce_hex, ctx->pow_bits);
    if (!rp2p_store_pow_challenge(ctx, peer_address, id,
        reply + strlen(RP2P_CTRTOK_CHALLENGE)))
    {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_BUSY);
    } else {
        rp2p_tcp_send(connection->fd, reply);
    }
    crypto_wipe(nonce, sizeof(nonce));
    crypto_wipe(nonce_hex, sizeof(nonce_hex));
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Handles registration challenge, refresh, and proof command forms.
 * @param ctx Locked index context.
 * @param connection Registering connection.
 * @param command_line Complete REGISTER command.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_register(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line)
{
    struct sockaddr_storage peer_address;
    socklen_t peer_address_length;
    char id[RP2P_ID_MAX + 1];
    int has_solution;

    peer_address_length = sizeof(peer_address);
    if (getpeername(connection->fd, (struct sockaddr *)&peer_address,
        &peer_address_length) != 0)
        memset(&peer_address, 0, sizeof(peer_address));
    has_solution = strstr(command_line,
        ":" RP2P_CTRTOK_SOLUTION) != NULL;
    if (!has_solution && !rp2p_parse_register_id(command_line, id)) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_INVALID_ID);
        return RP2P_INDEX_ACTION_KEEP;
    }
    if (connection->registered && strcmp(connection->id, id) != 0) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    if (has_solution)
        return rp2p_index_handle_register_proof(ctx, connection,
            command_line, &peer_address);
    if (connection->registered && strcmp(connection->id, id) == 0)
        return rp2p_index_handle_register_refresh(ctx, connection, id);
    return rp2p_index_handle_register_challenge(ctx, connection,
        &peer_address, id);
}

/**
 * Handles one complete PUNCH_REQ2 candidate block.
 * @param ctx Locked index context.
 * @param connection Requesting consumer connection.
 * @param command_line Complete PUNCH_REQ2 command line.
 * @param block_start First candidate block byte.
 * @param block_limit One byte past buffered input.
 * @param consumed_end Output cursor after the complete block.
 * @return KEEP after consuming a block or INCOMPLETE until END arrives.
 */
static rp2p_index_action_t rp2p_index_handle_punch_req2(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line,
char *block_start,
char *block_limit,
char **consumed_end)
{
    char self_id[RP2P_ID_MAX + 1] = {0};
    char target_id[RP2P_ID_MAX + 1] = {0};
    char session_id[RP2P_CTRL_SESSION_MAX + 1] = {0};
    char candidate_block[RP2P_BUF] = "";
    char message[RP2P_BUF];
    char *block_end;
    int target_fd;
    size_t peer_index;
    int pending_index;
    int i;

    if (!rp2p_find_end_line(block_start, block_limit, &block_end))
        return RP2P_INDEX_ACTION_INCOMPLETE;
    *consumed_end = block_end;
    if (!rp2p_parse_punch_req2(command_line, self_id, target_id,
        session_id) ||
        !rp2p_copy_candidate_block(block_start, block_end, candidate_block,
            sizeof(candidate_block)))
    {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    target_fd = -1;
    for (i = 0; i < ctx->n_conns; i++) {
        if (ctx->conns[i].registered &&
            strcmp(ctx->conns[i].id, target_id) == 0)
        {
            target_fd = ctx->conns[i].fd;
            break;
        }
    }
    peer_index = rp2p_find_peer(ctx, target_id);
    if (target_fd == -1 || peer_index == SIZE_MAX) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_OFFLINE);
        return RP2P_INDEX_ACTION_KEEP;
    }
    snprintf(message, sizeof(message), "%s%s:%s\n",
        RP2P_CTRTOK_PUNCH_CALL2, self_id, session_id);
    if (!rp2p_append_text(message, sizeof(message), candidate_block)) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    rp2p_index_cleanup_stale_punches(ctx);
    if (ctx->n_pending_punches >= RP2P_MAX_PENDING_PUNCHES) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_BUSY);
        return RP2P_INDEX_ACTION_KEEP;
    }
    pending_index = ctx->n_pending_punches++;
    snprintf(ctx->pending_punches[pending_index].self_id,
        sizeof(ctx->pending_punches[pending_index].self_id), "%s", self_id);
    snprintf(ctx->pending_punches[pending_index].target_id,
        sizeof(ctx->pending_punches[pending_index].target_id), "%s",
        target_id);
    snprintf(ctx->pending_punches[pending_index].sess_id,
        sizeof(ctx->pending_punches[pending_index].sess_id), "%s",
        session_id);
    ctx->pending_punches[pending_index].consumer_fd = connection->fd;
    ctx->pending_punches[pending_index].ts = rp2p_now_s();
    if (rp2p_tcp_send(target_fd, message) != RP2P_OK) {
        rp2p_pending_punch_remove(ctx, pending_index);
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_OFFLINE);
    }
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Handles one complete PUNCH_ACK2 candidate block.
 * @param ctx Locked index context.
 * @param connection Acknowledging publisher connection.
 * @param command_line Complete PUNCH_ACK2 command line.
 * @param block_start First candidate block byte.
 * @param block_limit One byte past buffered input.
 * @param consumed_end Output cursor after the complete block.
 * @return KEEP after consuming a block or INCOMPLETE until END arrives.
 */
static rp2p_index_action_t rp2p_index_handle_punch_ack2(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line,
char *block_start,
char *block_limit,
char **consumed_end)
{
    char self_id[RP2P_ID_MAX + 1] = {0};
    char target_id[RP2P_ID_MAX + 1] = {0};
    char session_id[RP2P_CTRL_SESSION_MAX + 1] = {0};
    char candidate_block[RP2P_BUF] = "";
    char response[RP2P_BUF];
    char *block_end;
    int pending_index;

    if (!rp2p_find_end_line(block_start, block_limit, &block_end))
        return RP2P_INDEX_ACTION_INCOMPLETE;
    *consumed_end = block_end;
    if (!rp2p_parse_punch_ack2(command_line, self_id, target_id,
        session_id) || !connection->registered ||
        strcmp(connection->id, self_id) != 0 ||
        !rp2p_copy_candidate_block(block_start, block_end, candidate_block,
            sizeof(candidate_block)))
    {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    pending_index = rp2p_pending_punch_find(ctx, self_id, target_id,
        session_id);
    if (pending_index < 0) return RP2P_INDEX_ACTION_KEEP;
    snprintf(response, sizeof(response), "%s%s:%s\n",
        RP2P_CTRTOK_PUNCH_OK2, self_id, session_id);
    if (!rp2p_append_text(response, sizeof(response), candidate_block)) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    rp2p_tcp_send(ctx->pending_punches[pending_index].consumer_fd, response);
    rp2p_pending_punch_remove(ctx, pending_index);
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Removes a registration when its identifier and key match.
 * @param ctx Locked index context.
 * @param connection Connection requesting removal.
 * @param command_line Complete DEREGISTER command.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_deregister(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line)
{
    char id[RP2P_ID_MAX + 1];
    char key[RP2P_KEY_STR_SZ];
    size_t peer_index;

    memset(key, 0, sizeof(key));
    if (rp2p_parse_deregister(command_line, id, key)) {
        peer_index = rp2p_find_peer(ctx, id);
        if (peer_index != SIZE_MAX &&
            strcmp(ctx->peers[peer_index].key, key) == 0)
        {
            rp2p_remove_peer(ctx, id);
            rp2p_tcp_send(connection->fd, RP2P_CTRTOK_OK);
        } else {
            rp2p_tcp_send(connection->fd,
                RP2P_CTRTOK_ERROR_INVALID_KEY);
        }
    } else {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
    }
    crypto_wipe(key, sizeof(key));
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Sends the active publisher list in current peer-table order.
 * @param ctx Locked index context.
 * @param connection Connection requesting the list.
 * @param command_line Complete LIST command.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_list(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line)
{
    char reply[RP2P_BUF];
    size_t peer_index;

    if (strcmp(command_line, RP2P_CTRTOK_LIST_PUBLISHERS) != 0) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    rp2p_index_cleanup_stale_peers(ctx);
    for (peer_index = 0; peer_index < ctx->n_peers; peer_index++) {
        snprintf(reply, sizeof(reply), "%s%s", RP2P_CTRTOK_PUBLISHER,
            ctx->peers[peer_index].id);
        rp2p_tcp_send(connection->fd, reply);
    }
    rp2p_tcp_send(connection->fd, RP2P_CTRTOK_END);
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Looks up one publisher and sends its current presence state.
 * @param ctx Locked index context.
 * @param connection Connection requesting the lookup.
 * @param command_line Complete LOOKUP command.
 * @return KEEP without removing the connection.
 */
static rp2p_index_action_t rp2p_index_handle_lookup(
rp2p_t *ctx,
rp2p_tcp_conn_t *connection,
const char *command_line)
{
    char id[RP2P_ID_MAX + 1];
    char reply[RP2P_BUF];
    size_t peer_index;

    if (rp2p_parse_lookup(command_line, id)) {
        peer_index = rp2p_find_peer(ctx, id);
        if (peer_index != SIZE_MAX) {
            snprintf(reply, sizeof(reply), "%s%s", RP2P_CTRTOK_PUBLISHER,
                ctx->peers[peer_index].id);
            rp2p_tcp_send(connection->fd, reply);
        } else {
            rp2p_tcp_send(connection->fd, RP2P_CTRTOK_NOT_FOUND);
        }
    } else {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
    }
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Dispatches one validated control line to its index command handler.
 * @param ctx Locked index context.
 * @param connection_index Current connection index.
 * @param command_line Complete validated command line.
 * @param block_start First byte after the command line.
 * @param block_limit One byte past buffered input.
 * @param consumed_end Output cursor after any consumed candidate block.
 * @return Explicit connection or buffering action.
 */
static rp2p_index_action_t rp2p_index_dispatch_command(
rp2p_t *ctx,
int connection_index,
const char *command_line,
char *block_start,
char *block_limit,
char **consumed_end)
{
    rp2p_tcp_conn_t *connection;
    rp2p_index_action_t action;
    const char *colon;
    char command[32];
    size_t command_length;

    connection = &ctx->conns[connection_index];
    action = rp2p_index_handle_hello(connection, command_line);
    if (action != RP2P_INDEX_ACTION_INCOMPLETE) return action;
    colon = strchr(command_line, ':');
    command_length = colon ? (size_t)(colon - command_line) :
        strlen(command_line);
    if (command_length == 0 || command_length >= sizeof(command)) {
        rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
        return RP2P_INDEX_ACTION_KEEP;
    }
    memcpy(command, command_line, command_length);
    command[command_length] = '\0';
    if (strcmp(command, RP2P_CTRCMD_REGISTER) == 0)
        return rp2p_index_handle_register(ctx, connection, command_line);
    if (strcmp(command, RP2P_CTRCMD_PUNCH_REQ2) == 0)
        return rp2p_index_handle_punch_req2(ctx, connection, command_line,
            block_start, block_limit, consumed_end);
    if (strcmp(command, RP2P_CTRCMD_PUNCH_ACK2) == 0)
        return rp2p_index_handle_punch_ack2(ctx, connection, command_line,
            block_start, block_limit, consumed_end);
    if (strcmp(command, RP2P_CTRCMD_DEREGISTER) == 0)
        return rp2p_index_handle_deregister(ctx, connection, command_line);
    if (strcmp(command, RP2P_CTRCMD_LIST_PUBLISHERS) == 0)
        return rp2p_index_handle_list(ctx, connection, command_line);
    if (strcmp(command, RP2P_CTRCMD_LOOKUP) == 0)
        return rp2p_index_handle_lookup(ctx, connection, command_line);
    rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_UNKNOWN_COMMAND);
    return RP2P_INDEX_ACTION_KEEP;
}

/**
 * Frames and consumes all complete commands buffered on one connection.
 * @param ctx Locked index context.
 * @param connection_index Current connection index.
 * @return KEEP while connected, REMOVE after connection removal, or
 * INCOMPLETE when an END-framed command remains buffered.
 */
static rp2p_index_action_t rp2p_index_process_connection_buffer(
rp2p_t *ctx,
int connection_index)
{
    rp2p_tcp_conn_t *connection;
    char *line_start;
    char *newline;
    int incomplete;

    connection = &ctx->conns[connection_index];
    line_start = connection->buf;
    incomplete = 0;
    while ((newline = (char *)memchr(line_start, '\n',
        (size_t)(connection->buf + connection->buf_len - line_start))) != NULL)
    {
        rp2p_index_action_t action;
        char command_line[RP2P_BUF];
        char *line_base;
        char *consumed_end;
        int line_length;

        line_base = line_start;
        line_length = (int)(newline - line_start);
        if (line_length <= 0) {
            line_start += line_length + 1;
            continue;
        }
        if (line_length > RP2P_CTRL_LINE_MAX ||
            line_length > (int)sizeof(command_line) - 1)
        {
            rp2p_conn_remove(ctx, connection_index);
            return RP2P_INDEX_ACTION_REMOVE;
        }
        if (!rp2p_control_bytes_valid(line_start, (size_t)line_length)) {
            rp2p_tcp_send(connection->fd, RP2P_CTRTOK_ERROR_MALFORMED);
            line_start += line_length + 1;
            continue;
        }
        memcpy(command_line, line_start, (size_t)line_length);
        command_line[line_length] = '\0';
        line_start += line_length + 1;
        consumed_end = line_start;
        action = rp2p_index_dispatch_command(ctx, connection_index,
            command_line, line_start, connection->buf + connection->buf_len,
            &consumed_end);
        if (action == RP2P_INDEX_ACTION_REMOVE) {
            rp2p_conn_remove(ctx, connection_index);
            return action;
        }
        if (action == RP2P_INDEX_ACTION_INCOMPLETE) {
            line_start = line_base;
            incomplete = 1;
            break;
        }
        line_start = consumed_end;
        if (line_start >= connection->buf + connection->buf_len) break;
    }
    if (line_start > connection->buf) {
        int remaining;

        remaining = (int)(connection->buf + connection->buf_len - line_start);
        if (remaining > 0)
            memmove(connection->buf, line_start, (size_t)remaining);
        connection->buf_len = remaining;
    }
    return incomplete || line_start == connection->buf ?
        RP2P_INDEX_ACTION_INCOMPLETE :
        RP2P_INDEX_ACTION_KEEP;
}

/**
 * Reads available input and processes complete commands for one connection.
 * @param ctx Locked index context.
 * @param connection_index Current connection index.
 * @return Explicit connection or buffering action.
 */
static rp2p_index_action_t rp2p_index_read_connection(
rp2p_t *ctx,
int connection_index)
{
    rp2p_tcp_conn_t *connection;
    char input[RP2P_BUF];
    int input_length;

    connection = &ctx->conns[connection_index];
    input_length = rp2p_sock_read(connection->fd, input,
        (int)sizeof(input) - 1);
    if (input_length <= 0) {
        rp2p_index_disconnect(ctx, connection_index);
        return RP2P_INDEX_ACTION_REMOVE;
    }
    input[input_length] = '\0';
    if (connection->buf_len + input_length >
        (int)sizeof(connection->buf) - 1)
    {
        rp2p_conn_remove(ctx, connection_index);
        return RP2P_INDEX_ACTION_REMOVE;
    }
    memcpy(connection->buf + connection->buf_len, input,
        (size_t)input_length);
    connection->buf_len += input_length;
    if (connection->buf_len >= RP2P_CTRL_LINE_MAX &&
        !memchr(connection->buf, '\n', (size_t)connection->buf_len))
    {
        rp2p_conn_remove(ctx, connection_index);
        return RP2P_INDEX_ACTION_REMOVE;
    }
    return rp2p_index_process_connection_buffer(ctx, connection_index);
}

/**
 * Builds the next readable descriptor set and evicts expired challenges.
 * @param runtime Initialized index runtime.
 * @return RP2P_OK when the descriptor set is ready, or RP2P_ENET on failure.
 */
static int rp2p_index_prepare_fdset(rp2p_index_runtime_t *runtime) {
    rp2p_t *ctx;
    int i;

    ctx = runtime->ctx;
    FD_ZERO(&runtime->readable_fds);
    runtime->max_fd = -1;
    if (!rp2p_fdset_add(runtime->listener_fd, &runtime->readable_fds,
        &runtime->max_fd))
    {
        rp2p_set_error(ctx,
            "index: listener cannot be represented by fd_set");
        return RP2P_ENET;
    }
    rp2p_lock(ctx);
    for (i = ctx->n_conns - 1; i >= 0; i--) {
        if (!rp2p_fdset_add(ctx->conns[i].fd, &runtime->readable_fds,
            &runtime->max_fd))
        {
            rp2p_set_error(ctx,
                "index: client descriptor cannot be represented by fd_set");
            rp2p_conn_remove(ctx, i);
        }
    }
    rp2p_index_cleanup_stale_challenges(ctx);
    rp2p_unlock(ctx);
    return RP2P_OK;
}

/**
 * Accepts at most one ready index client and transfers descriptor ownership.
 * @param runtime Initialized index runtime with a selected listener.
 * @return None.
 */
static void rp2p_index_accept_connection(rp2p_index_runtime_t *runtime) {
    struct sockaddr_storage client_address;
    socklen_t client_address_length;
    rp2p_fd_t client_fd;

    if (!FD_ISSET(runtime->listener_fd, &runtime->readable_fds)) return;
    client_address_length = sizeof(client_address);
    client_fd = accept(runtime->listener_fd,
        (struct sockaddr *)&client_address, &client_address_length);
    if (RP2P_ISERR(client_fd)) return;
    rp2p_set_nonblock(client_fd);
    rp2p_lock(runtime->ctx);
    if (rp2p_conn_add(runtime->ctx, client_fd) != RP2P_OK)
        RP2P_FD_CLOSE(client_fd);
    rp2p_unlock(runtime->ctx);
}

/**
 * Processes readable client connections in reverse table order.
 * @param runtime Initialized index runtime with selected descriptors.
 * @return None.
 */
static void rp2p_index_process_connections(rp2p_index_runtime_t *runtime) {
    rp2p_t *ctx;
    int i;

    ctx = runtime->ctx;
    rp2p_lock(ctx);
    for (i = ctx->n_conns - 1; i >= 0; i--) {
        if (!FD_ISSET(ctx->conns[i].fd, &runtime->readable_fds)) continue;
        (void)rp2p_index_read_connection(ctx, i);
    }
    rp2p_unlock(ctx);
}

/**
 * Runs the blocking select loop until stop or a descriptor-set failure.
 * @param runtime Initialized index runtime.
 * @return RP2P_OK on requested stop, or RP2P_ENET on fd-set failure.
 */
static int rp2p_index_event_loop(rp2p_index_runtime_t *runtime) {
    struct timeval timeout;
    int ready_count;
    int result;

    for (;;) {
        if (runtime->ctx->stop_requested) {
            fprintf(stderr, "rp2p: shutdown requested\n");
            break;
        }
        result = rp2p_index_prepare_fdset(runtime);
        if (result != RP2P_OK) return result;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        ready_count = select(runtime->max_fd + 1, &runtime->readable_fds,
            NULL, NULL, &timeout);
        if (ready_count < 0) {
            if (runtime->ctx->stop_requested) break;
            continue;
        }
        if (ready_count == 0) continue;
        rp2p_index_accept_connection(runtime);
        rp2p_index_process_connections(runtime);
    }
    return RP2P_OK;
}

/**
 * Releases all index-owned connections, listener, and platform state.
 * @param runtime Initialized index runtime.
 * @return None.
 */
static void rp2p_index_runtime_cleanup(rp2p_index_runtime_t *runtime) {
    int i;

    rp2p_lock(runtime->ctx);
    for (i = runtime->ctx->n_conns - 1; i >= 0; i--)
        rp2p_conn_remove(runtime->ctx, i);
    rp2p_unlock(runtime->ctx);
    if (!RP2P_ISERR(runtime->listener_fd))
        RP2P_FD_CLOSE(runtime->listener_fd);
    runtime->listener_fd = RP2P_FD_INVALID;
    if (runtime->platform_initialized) rp2p_platform_cleanup();
    runtime->platform_initialized = 0;
    atomic_store(&runtime->ctx->stop_requested, 0);
}

/**
 * Serves the blocking TCP rendezvous index lifecycle.
 * @param ctx Index context.
 * @param host Listener host or NULL for the wildcard address.
 * @param port Listener port.
 * @return RP2P_OK on requested stop, or a negative error code on failure.
 */
int rp2p_serve_index(
    rp2p_t *ctx,
    const char *host,
    unsigned short port)
{
    rp2p_index_runtime_t runtime;
    int result;

    if (!ctx) return RP2P_EINVAL;
    rp2p_set_error(ctx, NULL);
    if (rp2p_is_stop_requested(ctx)) {
        atomic_store(&ctx->stop_requested, 0);
        return RP2P_OK;
    }
    if (port == 0) {
        rp2p_set_error(ctx, "index: port must be between 1 and 65535");
        return RP2P_EINVAL;
    }
    result = rp2p_index_runtime_initialize(&runtime, ctx, host, port);
    if (result != RP2P_OK) return result;
    fprintf(stderr, "rp2p: index server listening on %s:%u\n",
        host ? host : "*", (unsigned)port);
    result = rp2p_index_event_loop(&runtime);
    rp2p_index_runtime_cleanup(&runtime);
    return result == RP2P_OK ? RP2P_OK : result;
}

typedef struct {
    char dir[768];
    char scoped[848];
    char legacy[848];
} rp2p_key_paths_t;

/**
 * Serializes access to persisted registration keys within this process.
 * @return None.
 */
static void rp2p_key_lock(void) {
#ifdef _WIN32
    AcquireSRWLockExclusive(&g_key_mutex);
#else
    pthread_mutex_lock(&g_key_mutex);
#endif
}

/**
 * Releases process-local registration key serialization.
 * @return None.
 */
static void rp2p_key_unlock(void) {
#ifdef _WIN32
    ReleaseSRWLockExclusive(&g_key_mutex);
#else
    pthread_mutex_unlock(&g_key_mutex);
#endif
}

/**
 * Produces a portable SHA-256 digest for one index and publisher scope.
 * @param index_host Index host text.
 * @param index_port Index port.
 * @param id Publisher identifier.
 * @param out Output digest.
 * @return None.
 */
static void rp2p_key_scope_hash(const char *index_host,
    unsigned short index_port, const char *id, unsigned char out[32])
{
    static const unsigned char domain[] = "rp2p-key-v1";
    rp2p_sha256_t hash;
    unsigned char digest[32];
    unsigned char port[2];

    port[0] = (unsigned char)(index_port >> 8);
    port[1] = (unsigned char)index_port;
    rp2p_sha256_init(&hash);
    rp2p_sha256_update(&hash, domain, sizeof(domain));
    rp2p_sha256_update(&hash, (const unsigned char *)index_host,
        strlen(index_host) + 1);
    rp2p_sha256_update(&hash, port, sizeof(port));
    rp2p_sha256_update(&hash, (const unsigned char *)id, strlen(id) + 1);
    rp2p_sha256_final(&hash, digest);
    memcpy(out, digest, sizeof(digest));
    crypto_wipe(&hash, sizeof(hash));
    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(port, sizeof(port));
}

/**
 * Builds bounded scoped and legacy registration key paths.
 * @param ctx Context receiving error detail.
 * @param index_host Index host.
 * @param index_port Index port.
 * @param id Publisher identifier.
 * @param paths Output paths.
 * @return RP2P_OK on success or RP2P_ERROR for invalid HOME/path length.
 */
static int rp2p_key_paths(rp2p_t *ctx, const char *index_host,
    unsigned short index_port, const char *id, rp2p_key_paths_t *paths)
{
    const char *home;
    unsigned char digest[32];
    char filename[65];
    int n;

    home = getenv("HOME");
#ifdef _WIN32
    if (!home || !home[0]) home = getenv("USERPROFILE");
#endif
    if (!home || !home[0]) {
        rp2p_set_error(ctx, "key: HOME is missing or empty");
        return RP2P_ERROR;
    }
    n = snprintf(paths->dir, sizeof(paths->dir),
        "%s/.local/share/rp2p/keys", home);
    if (n < 0 || (size_t)n >= sizeof(paths->dir)) {
        rp2p_set_error(ctx, "key: HOME path is too long");
        return RP2P_ERROR;
    }
    rp2p_key_scope_hash(index_host, index_port, id, digest);
    if (!rp2p_hex_encode(digest, sizeof(digest), filename,
        sizeof(filename)))
    {
        rp2p_set_error(ctx, "key: scope encoding failed");
        crypto_wipe(digest, sizeof(digest));
        crypto_wipe(filename, sizeof(filename));
        return RP2P_ERROR;
    }
    n = snprintf(paths->scoped, sizeof(paths->scoped), "%s/%s",
        paths->dir, filename);
    if (n < 0 || (size_t)n >= sizeof(paths->scoped)) {
        rp2p_set_error(ctx, "key: scoped path is too long");
        crypto_wipe(digest, sizeof(digest));
        crypto_wipe(filename, sizeof(filename));
        return RP2P_ERROR;
    }
    n = snprintf(paths->legacy, sizeof(paths->legacy), "%s/%s",
        paths->dir, id);
    if (n < 0 || (size_t)n >= sizeof(paths->legacy)) {
        rp2p_set_error(ctx, "key: legacy path is too long");
        crypto_wipe(digest, sizeof(digest));
        crypto_wipe(filename, sizeof(filename));
        return RP2P_ERROR;
    }
    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(filename, sizeof(filename));
    return RP2P_OK;
}

/**
 * Creates a directory hierarchy and rejects non-directory collisions.
 * @param path Mutable directory path.
 * @return 0 on success or -1 on failure with errno set where available.
 */
static int rp2p_mkdir_p(char *path) {
    char *p;

    for (p = path + 1; *p; p++) {
        int result;

        if (*p != '/' && *p != '\\') continue;
        *p = '\0';
#ifdef _WIN32
        result = _mkdir(path);
        if (result != 0 && errno != EEXIST) {
            *p = '/';
            return -1;
        }
#else
        result = mkdir(path, 0755);
        if (result != 0 && errno != EEXIST) {
            *p = '/';
            return -1;
        }
#endif
        *p = '/';
    }
#ifdef _WIN32
    if (_mkdir(path) != 0 && errno != EEXIST) return -1;
#else
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    if (chmod(path, 0700) != 0) return -1;
#endif
    return 0;
}

/**
 * Validates one complete registration key file payload.
 * @param data File bytes.
 * @param len File byte count.
 * @param key Output key.
 * @return 1 for exact key content with an optional line ending, otherwise 0.
 */
static int rp2p_key_parse(const char *data, size_t len,
    char key[RP2P_KEY_STR_SZ])
{
    size_t i;

    if (len == RP2P_KEY_SZ + 1 && data[len - 1] == '\n') len--;
    else if (len == RP2P_KEY_SZ + 2 && data[len - 2] == '\r' &&
        data[len - 1] == '\n')
        len -= 2;
    if (len != RP2P_KEY_SZ) return 0;
    for (i = 0; i < len; i++) {
        if (rp2p_hex_decode_nibble(data[i]) < 0) return 0;
    }
    memcpy(key, data, len);
    key[len] = '\0';
    return 1;
}

#ifdef _WIN32
/**
 * Reads one Windows key file without following reparse points.
 * @param ctx Context receiving error detail.
 * @param path Exact path to load.
 * @param data Output file bytes.
 * @param capacity Output buffer capacity.
 * @param total Output byte count.
 * @return RP2P_OK, RP2P_ENOENT, or RP2P_ERROR.
 */
static int rp2p_load_key_windows(
rp2p_t *ctx,
const char *path,
char *data,
size_t capacity,
size_t *total)
{
    HANDLE file;
    BY_HANDLE_FILE_INFORMATION info;
    DWORD got;

    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND ||
            GetLastError() == ERROR_PATH_NOT_FOUND)
            return RP2P_ENOENT;
        rp2p_set_error(ctx, "key: cannot open persisted key (%lu)",
            (unsigned long)GetLastError());
        return RP2P_ERROR;
    }
    if (!GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        rp2p_set_error(ctx, "key: persisted key is not a regular file");
        CloseHandle(file);
        return RP2P_ERROR;
    }
    *total = 0;
    while (*total < capacity) {
        if (!ReadFile(file, data + *total, (DWORD)(capacity - *total),
            &got, NULL))
        {
            rp2p_set_error(ctx, "key: persisted key read failed (%lu)",
                (unsigned long)GetLastError());
            CloseHandle(file);
            return RP2P_ERROR;
        }
        if (got == 0) break;
        *total += got;
    }
    if (!CloseHandle(file)) {
        rp2p_set_error(ctx, "key: persisted key close failed");
        return RP2P_ERROR;
    }
    return RP2P_OK;
}
#else
/**
 * Reads one POSIX key file without following symbolic links when supported.
 * @param ctx Context receiving error detail.
 * @param path Exact path to load.
 * @param data Output file bytes.
 * @param capacity Output buffer capacity.
 * @param total Output byte count.
 * @return RP2P_OK, RP2P_ENOENT, RP2P_EPROTO, or RP2P_ERROR.
 */
static int rp2p_load_key_posix(
rp2p_t *ctx,
const char *path,
char *data,
size_t capacity,
size_t *total)
{
    int fd;
    ssize_t got;
    int flags;
    struct stat status;

    flags = O_RDONLY | O_NONBLOCK;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(path, flags);
    if (fd < 0) {
        if (errno == ENOENT) return RP2P_ENOENT;
        rp2p_set_error(ctx, "key: cannot open persisted key: %s",
            strerror(errno));
        return RP2P_ERROR;
    }
    if (fstat(fd, &status) != 0) {
        rp2p_set_error(ctx, "key: cannot inspect persisted key: %s",
            strerror(errno));
        close(fd);
        return RP2P_ERROR;
    }
    if (!S_ISREG(status.st_mode)) {
        rp2p_set_error(ctx, "key: persisted key is not a regular file");
        close(fd);
        return RP2P_ERROR;
    }
    if (status.st_size < RP2P_KEY_SZ ||
        status.st_size > RP2P_KEY_SZ + 2)
    {
        rp2p_set_error(ctx, "key: persisted key has unexpected size");
        close(fd);
        return RP2P_EPROTO;
    }
    *total = 0;
    while (*total < capacity) {
        got = read(fd, data + *total, capacity - *total);
        if (got > 0) {
            *total += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) {
            rp2p_set_error(ctx, "key: persisted key read failed: %s",
                strerror(errno));
            close(fd);
            return RP2P_ERROR;
        }
        break;
    }
    if (close(fd) != 0) {
        rp2p_set_error(ctx, "key: persisted key close failed: %s",
            strerror(errno));
        return RP2P_ERROR;
    }
    return RP2P_OK;
}
#endif

/**
 * Loads and strictly validates one registration key path.
 * @param ctx Context receiving error detail.
 * @param path Exact path to load.
 * @param key Output key.
 * @return RP2P_OK, RP2P_ENOENT, RP2P_EPROTO, or RP2P_ERROR.
 */
static int rp2p_load_key_path(rp2p_t *ctx, const char *path,
    char key[RP2P_KEY_STR_SZ])
{
    char data[RP2P_KEY_SZ + 3];
    size_t total;
    int result;

#ifdef _WIN32
    result = rp2p_load_key_windows(ctx, path, data, sizeof(data), &total);
#else
    result = rp2p_load_key_posix(ctx, path, data, sizeof(data), &total);
#endif
    if (result != RP2P_OK) {
        crypto_wipe(data, sizeof(data));
        return result;
    }
    if (!rp2p_key_parse(data, total, key)) {
        rp2p_set_error(ctx, "key: persisted key is malformed");
        crypto_wipe(data, sizeof(data));
        return RP2P_EPROTO;
    }
    crypto_wipe(data, sizeof(data));
    return RP2P_OK;
}

#ifdef _WIN32
/**
 * Durably replaces one Windows key file through a private temporary file.
 * @param ctx Context receiving error detail.
 * @param paths Scoped key paths.
 * @param temp Temporary key path.
 * @param content Complete key file content.
 * @param total Content byte count.
 * @return RP2P_OK on replacement or RP2P_ERROR on failure.
 */
static int rp2p_save_key_windows(
rp2p_t *ctx,
const rp2p_key_paths_t *paths,
const char *temp,
const char *content,
size_t total)
{
    HANDLE file;
    DWORD written;
    size_t offset;
    int result;

    result = RP2P_ERROR;
    file = CreateFileA(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        rp2p_set_error(ctx, "key: temporary key create failed (%lu)",
            (unsigned long)GetLastError());
    } else {
        offset = 0;
        while (offset < total && WriteFile(file, content + offset,
            (DWORD)(total - offset), &written, NULL) && written > 0)
            offset += written;
        if (offset != total || !FlushFileBuffers(file)) {
            rp2p_set_error(ctx, "key: temporary key write failed (%lu)",
                (unsigned long)GetLastError());
        } else if (!CloseHandle(file)) {
            file = INVALID_HANDLE_VALUE;
            rp2p_set_error(ctx, "key: temporary key close failed");
        } else {
            file = INVALID_HANDLE_VALUE;
            if (MoveFileExA(temp, paths->scoped,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                result = RP2P_OK;
            else
                rp2p_set_error(ctx, "key: atomic replacement failed (%lu)",
                    (unsigned long)GetLastError());
        }
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    if (result != RP2P_OK) DeleteFileA(temp);
    return result;
}
#else
/**
 * Durably replaces one POSIX key file and synchronizes its directory entry.
 * @param ctx Context receiving error detail.
 * @param paths Scoped key paths.
 * @param temp Temporary key path.
 * @param content Complete key file content.
 * @param total Content byte count.
 * @return RP2P_OK on replacement or RP2P_ERROR on failure.
 */
static int rp2p_save_key_posix(
rp2p_t *ctx,
const rp2p_key_paths_t *paths,
const char *temp,
const char *content,
size_t total)
{
    int fd;
    int flags;
    size_t offset;
    int result;

    result = RP2P_ERROR;
    flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(temp, flags, 0600);
    if (fd < 0) {
        rp2p_set_error(ctx, "key: temporary key create failed: %s",
            strerror(errno));
    } else {
        offset = 0;
        while (offset < total) {
            ssize_t written;

            written = write(fd, content + offset, total - offset);
            if (written > 0) {
                offset += (size_t)written;
                continue;
            }
            if (written < 0 && errno == EINTR) continue;
            break;
        }
        if (offset != total || fchmod(fd, 0600) != 0 || fsync(fd) != 0) {
            rp2p_set_error(ctx, "key: temporary key write failed: %s",
                strerror(errno));
        } else if (close(fd) != 0) {
            fd = -1;
            rp2p_set_error(ctx, "key: temporary key close failed: %s",
                strerror(errno));
        } else {
            int dir_fd;

            fd = -1;
            if (rename(temp, paths->scoped) != 0) {
                rp2p_set_error(ctx, "key: atomic replacement failed: %s",
                    strerror(errno));
            } else {
                dir_fd = open(paths->dir, O_RDONLY
#ifdef O_DIRECTORY
                    | O_DIRECTORY
#endif
                );
                if (dir_fd < 0) {
                    rp2p_set_error(ctx,
                        "key: key directory sync failed: %s",
                        strerror(errno));
                } else if (fsync(dir_fd) != 0) {
                    rp2p_set_error(ctx,
                        "key: key directory sync failed: %s",
                        strerror(errno));
                    close(dir_fd);
                } else if (close(dir_fd) != 0) {
                    rp2p_set_error(ctx,
                        "key: key directory close failed: %s",
                        strerror(errno));
                } else {
                    result = RP2P_OK;
                }
            }
        }
        if (fd >= 0) close(fd);
    }
    if (result != RP2P_OK) unlink(temp);
    return result;
}
#endif

/**
 * Atomically persists one scoped registration key.
 * @param ctx Context receiving error detail.
 * @param paths Scoped key paths.
 * @param key Registration key.
 * @return RP2P_OK on durable replacement or RP2P_ERROR on failure.
 */
static int rp2p_save_key(rp2p_t *ctx, const rp2p_key_paths_t *paths,
    const char *key)
{
    unsigned char random[8];
    char suffix[17];
    char temp[896];
    char dir[sizeof(paths->dir)];
    char content[RP2P_KEY_STR_SZ + 1];
    size_t total;
    int name_len;
    int result;

    memcpy(dir, paths->dir, sizeof(dir));
    if (rp2p_mkdir_p(dir) != 0) {
        rp2p_set_error(ctx, "key: cannot create key directory: %s",
            strerror(errno));
        crypto_wipe(dir, sizeof(dir));
        return RP2P_ERROR;
    }
    name_len = -1;
    if (rp2p_fill_random(random, sizeof(random)) == 0 &&
        rp2p_hex_encode(random, sizeof(random), suffix, sizeof(suffix)))
        name_len = snprintf(temp, sizeof(temp), "%s/.%s.tmp", paths->dir,
            suffix);
    if (name_len < 0 || (size_t)name_len >= sizeof(temp))
    {
        rp2p_set_error(ctx, "key: cannot create temporary key name");
        crypto_wipe(random, sizeof(random));
        crypto_wipe(suffix, sizeof(suffix));
        crypto_wipe(temp, sizeof(temp));
        crypto_wipe(dir, sizeof(dir));
        return RP2P_ERROR;
    }
    memcpy(content, key, RP2P_KEY_SZ);
    content[RP2P_KEY_SZ] = '\n';
    total = RP2P_KEY_SZ + 1;
    rp2p_key_lock();
#ifdef _WIN32
    result = rp2p_save_key_windows(ctx, paths, temp, content, total);
#else
    result = rp2p_save_key_posix(ctx, paths, temp, content, total);
#endif
    rp2p_key_unlock();
    crypto_wipe(random, sizeof(random));
    crypto_wipe(suffix, sizeof(suffix));
    crypto_wipe(temp, sizeof(temp));
    crypto_wipe(dir, sizeof(dir));
    crypto_wipe(content, sizeof(content));
    return result;
}

/**
 * Removes one persisted path only while it still contains the observed key.
 * @param ctx Context receiving error detail.
 * @param path Exact persisted path.
 * @param key Observed registration key.
 * @return RP2P_OK when absent or removed, otherwise RP2P_ERROR.
 */
static int rp2p_remove_key(rp2p_t *ctx, const char *path, const char *key) {
    char current[RP2P_KEY_STR_SZ];
    int loaded;
    int result;

    rp2p_key_lock();
    loaded = rp2p_load_key_path(ctx, path, current);
    if (loaded == RP2P_ENOENT) {
        crypto_wipe(current, sizeof(current));
        rp2p_key_unlock();
        return RP2P_OK;
    }
    if (loaded != RP2P_OK || strcmp(current, key) != 0) {
        if (loaded == RP2P_OK)
            rp2p_set_error(ctx, "key: persisted key changed before removal");
        crypto_wipe(current, sizeof(current));
        rp2p_key_unlock();
        return RP2P_ERROR;
    }
#ifdef _WIN32
    result = DeleteFileA(path) ? RP2P_OK : RP2P_ERROR;
    if (result != RP2P_OK)
        rp2p_set_error(ctx, "key: persisted key removal failed (%lu)",
            (unsigned long)GetLastError());
#else
    result = unlink(path) == 0 ? RP2P_OK : RP2P_ERROR;
    if (result != RP2P_OK)
        rp2p_set_error(ctx, "key: persisted key removal failed: %s",
            strerror(errno));
#endif
    crypto_wipe(current, sizeof(current));
    rp2p_key_unlock();
    return result;
}

/**
 * Deregisters one publisher with an explicit observed key.
 * @param index_host Index host.
 * @param index_port Index port.
 * @param id Publisher identifier.
 * @param key Registration key.
 * @return 0 on success, -1 on error.
 */
static int rp2p_deregister_with_key(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *id,
    const char *key)
{
    char cmd[RP2P_BUF];
    char reply[RP2P_BUF];
    rp2p_fd_t fd;
    int connect_result;
    int line_result;
    int result;

    if (!key || key[0] == '\0') return RP2P_ENOENT;

    result = RP2P_OK;
    snprintf(cmd, sizeof(cmd), "%s%s:%s%s", RP2P_CTRTOK_DEREGISTER,
        id, RP2P_CTRTOK_KEY, key);
    fd = rp2p_control_connect(ctx, "deregister", index_host,
        index_port, &connect_result);
    if (RP2P_ISERR(fd)) {
        result = connect_result;
        goto cleanup;
    }
    if (rp2p_tcp_send(fd, cmd) != RP2P_OK) {
        RP2P_FD_CLOSE(fd);
        rp2p_set_error(ctx, "deregister: control write failed");
        result = RP2P_ENET;
        goto cleanup;
    }
    line_result = rp2p_tcp_readline(fd, reply, (int)sizeof(reply), 5);
    RP2P_FD_CLOSE(fd);
    if (line_result < 0) {
        if (line_result == -1) {
            rp2p_set_error(ctx, "deregister: control response timed out");
            result = RP2P_ETIMEOUT;
        } else if (line_result == -3 || line_result == -4) {
            rp2p_set_error(ctx, "deregister: malformed control response");
            result = RP2P_EPROTO;
        } else {
            rp2p_set_error(ctx, "deregister: control response failed");
            result = RP2P_ENET;
        }
        goto cleanup;
    }

    if (strcmp(reply, RP2P_CTRTOK_OK) != 0) {
        if (strcmp(reply, RP2P_CTRTOK_ERROR_INVALID_KEY) == 0) {
            rp2p_set_error(ctx,
                "deregister: index rejected registration key");
            result = RP2P_EAUTH;
        } else if (strncmp(reply, "RP2P_CTRTOK_ERROR:",
            strlen("RP2P_CTRTOK_ERROR:")) == 0)
        {
            rp2p_set_error(ctx, "deregister: index protocol error: %s",
                reply);
            result = RP2P_EPROTO;
        } else {
            rp2p_set_error(ctx, "deregister: index rejected key: %s", reply);
            result = RP2P_EPROTO;
        }
        goto cleanup;
    }
    rp2p_set_error(ctx, NULL);

cleanup:
    crypto_wipe(cmd, sizeof(cmd));
    crypto_wipe(reply, sizeof(reply));
    return result;
}

/**
 * Deregister.
 * @return 0 on success, -1 on error.
 */
int rp2p_deregister(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *id)
{
    rp2p_key_paths_t paths;
    const char *loaded_path;
    char key[RP2P_KEY_STR_SZ];
    int result;

    if (!ctx) return RP2P_EINVAL;
    memset(key, 0, sizeof(key));
    rp2p_set_error(ctx, NULL);
    if (!index_host || !index_host[0]) {
        rp2p_set_error(ctx, "deregister: index host is missing");
        return RP2P_EINVAL;
    }
    if (index_port == 0) {
        rp2p_set_error(ctx, "deregister: index port must be nonzero");
        return RP2P_EINVAL;
    }
    if (!rp2p_is_valid_id(id)) {
        rp2p_set_error(ctx, "deregister: publisher id is invalid");
        return RP2P_EINVAL;
    }
    result = rp2p_key_paths(ctx, index_host, index_port, id, &paths);
    if (result != RP2P_OK) return result;
    rp2p_key_lock();
    result = rp2p_load_key_path(ctx, paths.scoped, key);
    loaded_path = paths.scoped;
    if (result == RP2P_ENOENT) {
        result = rp2p_load_key_path(ctx, paths.legacy, key);
        loaded_path = paths.legacy;
    }
    rp2p_key_unlock();
    if (result == RP2P_ENOENT) {
        rp2p_set_error(ctx, "deregister: no persisted key for publisher");
        crypto_wipe(key, sizeof(key));
        return RP2P_ENOENT;
    }
    if (result == RP2P_OK) {
        result = rp2p_deregister_with_key(ctx, index_host, index_port, id,
            key);
        if (result == RP2P_OK)
            result = rp2p_remove_key(ctx, loaded_path, key);
    }
    crypto_wipe(key, sizeof(key));
    return result;
}

/**
 * List publishers.
 * @return 0 on success, negative error code on failure.
 */
int rp2p_list_publishers(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    rp2p_publisher_cb cb,
    void *userdata)
{
    rp2p_fd_t fd;
    char line[RP2P_BUF];
    size_t prefix_len;

    int connect_result;

    if (!ctx || !index_host || !index_host[0] || !cb) return RP2P_ERROR;
    rp2p_set_error(ctx, NULL);
    fd = rp2p_control_connect(ctx, "list", index_host, index_port,
        &connect_result);
    if (RP2P_ISERR(fd)) return connect_result;
    if (rp2p_tcp_send(fd, RP2P_CTRTOK_LIST_PUBLISHERS) != RP2P_OK) {
        RP2P_FD_CLOSE(fd);
        rp2p_set_error(ctx, "list: control write failed");
        return RP2P_ENET;
    }
    prefix_len = strlen(RP2P_CTRTOK_PUBLISHER);
    for (;;) {
        int line_result;

        line_result = rp2p_tcp_readline(fd, line, (int)sizeof(line),
            RP2P_ETIMEOUT_SEC);
        if (line_result < 0)
        {
            RP2P_FD_CLOSE(fd);
            if (line_result == -1) {
                rp2p_set_error(ctx, "list: control line timed out");
                return RP2P_ETIMEOUT;
            }
            if (line_result == -3 || line_result == -4) {
                rp2p_set_error(ctx, "list: malformed control line");
                return RP2P_EPROTO;
            }
            rp2p_set_error(ctx, "list: control connection closed");
            return RP2P_ENET;
        }
        if (strcmp(line, RP2P_CTRTOK_END) == 0) {
            RP2P_FD_CLOSE(fd);
            rp2p_set_error(ctx, NULL);
            return RP2P_OK;
        }
        if (strncmp(line, RP2P_CTRTOK_PUBLISHER, prefix_len) == 0) {
            const char *id = line + prefix_len;
            if (!rp2p_is_valid_id(id)) {
                RP2P_FD_CLOSE(fd);
                rp2p_set_error(ctx, "list: malformed publisher id");
                return RP2P_EPROTO;
            }
            cb(id, userdata);
            continue;
        }
        RP2P_FD_CLOSE(fd);
        rp2p_set_error(ctx, "list: unexpected control response: %s", line);
        return RP2P_EPROTO;
    }
}

/**
 * Validates publisher inputs and opens its control and UDP transports.
 * @param runtime Runtime that borrows inputs and owns opened descriptors.
 * @param ctx Publisher context to borrow.
 * @param index_host Index host to borrow.
 * @param index_port Index control port.
 * @param self_id Publisher identifier to borrow.
 * @param bind_port Requested local backend port.
 * @return RP2P_OK on success, or a negative error code on failure.
 */
static int rp2p_publisher_initialize(
rp2p_publisher_runtime_t *runtime,
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
unsigned short bind_port)
{
    unsigned short effective_port;
    int control_result;

    memset(runtime, 0, sizeof(*runtime));
    runtime->borrowed_ctx = ctx;
    runtime->borrowed_index_host = index_host;
    runtime->borrowed_self_id = self_id;
    runtime->index_port = index_port;
    runtime->owned_control_fd = RP2P_FD_INVALID;
    runtime->owned_udp_fd = RP2P_FD_INVALID;
    if (ctx->proto != RP2P_PROTO_TCP && ctx->proto != RP2P_PROTO_UDP) {
        rp2p_set_error(ctx, "wait: invalid transport protocol");
        return RP2P_EINVAL;
    }
    if (rp2p_resolve_port(ctx, bind_port, &effective_port) != RP2P_OK) {
        rp2p_set_error(ctx, "wait: conflicting local ports");
        return RP2P_EINVAL;
    }
    if (effective_port == 0 || !index_host || !self_id ||
        !rp2p_is_valid_id(self_id) || index_port == 0)
    {
        rp2p_set_error(ctx, "wait: invalid index, service id, or local port");
        return RP2P_EINVAL;
    }
    ctx->bind_port = effective_port;
    runtime->borrowed_udp_any_host = rp2p_host_is_ipv6_literal(index_host) ?
        "::" : "0.0.0.0";
    runtime->owned_control_fd = rp2p_control_connect(ctx, "wait", index_host,
        index_port, &control_result);
    if (RP2P_ISERR(runtime->owned_control_fd)) return control_result;
    runtime->owned_udp_fd = rp2p_create_socket(
        runtime->borrowed_udp_any_host, 0);
    if (RP2P_ISERR(runtime->owned_udp_fd)) {
        RP2P_FD_CLOSE(runtime->owned_control_fd);
        runtime->owned_control_fd = RP2P_FD_INVALID;
        return RP2P_ENET;
    }
    return RP2P_OK;
}

/**
 * Completes the registration challenge, proof, and response exchange.
 * @param runtime Initialized publisher runtime.
 * @param response Registration response buffer.
 * @param response_size Registration response buffer size.
 * @return RP2P_OK on success, or a negative error code on failure.
 */
static int rp2p_publisher_register(
rp2p_publisher_runtime_t *runtime,
char *response,
size_t response_size)
{
    rp2p_t *ctx;
    char send_buf[RP2P_BUF];
    char nonce[17];
    char solution[17];
    char proof[65];
    unsigned int challenge_bits;
    int control_result;
    int result;

    ctx = runtime->borrowed_ctx;
    memset(nonce, 0, sizeof(nonce));
    memset(solution, 0, sizeof(solution));
    memset(proof, 0, sizeof(proof));
    snprintf(send_buf, sizeof(send_buf), "%s%s", RP2P_CTRTOK_REGISTER,
        runtime->borrowed_self_id);
    control_result = rp2p_tcp_send(runtime->owned_control_fd, send_buf);
    if (control_result == RP2P_OK)
        control_result = rp2p_tcp_readline(runtime->owned_control_fd, response,
            (int)response_size, 10);
    if (control_result < 0) {
        if (control_result == -1) {
            rp2p_set_error(ctx, "wait: registration challenge timed out");
            result = RP2P_ETIMEOUT;
        } else if (control_result == -3 || control_result == -4) {
            rp2p_set_error(ctx,
                "wait: malformed registration challenge line");
            result = RP2P_EPROTO;
        } else {
            rp2p_set_error(ctx,
                "wait: registration challenge transport failed");
            result = RP2P_ENET;
        }
        goto cleanup;
    }
    if (strncmp(response, RP2P_CTRTOK_CHALLENGE,
        strlen(RP2P_CTRTOK_CHALLENGE)) != 0)
    {
        rp2p_set_error(ctx, "wait: unexpected registration challenge: %s",
            response);
        result = RP2P_EPROTO;
        goto cleanup;
    }
    if (!rp2p_parse_challenge(response, nonce, &challenge_bits)) {
        rp2p_set_error(ctx, "wait: malformed registration challenge");
        result = RP2P_EPROTO;
        goto cleanup;
    }
    fprintf(stderr, "rp2p: connecting...\n");
    if (!rp2p_solve_register_pow(ctx, ctx->pass, nonce,
        runtime->borrowed_self_id, (int)challenge_bits, solution,
        sizeof(solution), proof, sizeof(proof)))
    {
        rp2p_set_error(ctx, "wait: registration proof solve failed");
        result = RP2P_ERROR;
        goto cleanup;
    }
    snprintf(send_buf, sizeof(send_buf), "%s%s:%s%s:%s%s",
        RP2P_CTRTOK_REGISTER, runtime->borrowed_self_id,
        RP2P_CTRTOK_SOLUTION, solution, RP2P_CTRTOK_PROOF, proof);
    control_result = rp2p_tcp_send(runtime->owned_control_fd, send_buf);
    if (control_result == RP2P_OK)
        control_result = rp2p_tcp_readline(runtime->owned_control_fd, response,
            (int)response_size, 10);
    if (control_result < 0) {
        if (control_result == -1) {
            rp2p_set_error(ctx, "wait: registration response timed out");
            result = RP2P_ETIMEOUT;
        } else if (control_result == -3 || control_result == -4) {
            rp2p_set_error(ctx,
                "wait: malformed registration response line");
            result = RP2P_EPROTO;
        } else {
            rp2p_set_error(ctx, "wait: registration response failed");
            result = RP2P_ENET;
        }
        goto cleanup;
    }
    result = RP2P_OK;

cleanup:
    crypto_wipe(nonce, sizeof(nonce));
    crypto_wipe(solution, sizeof(solution));
    crypto_wipe(proof, sizeof(proof));
    crypto_wipe(send_buf, sizeof(send_buf));
    return result;
}

/**
 * Persists the registration key and rolls registration back on failure.
 * @param runtime Registered publisher runtime.
 * @param response Registration response containing the key.
 * @return RP2P_OK on success, or a negative error code on failure.
 */
static int rp2p_publisher_persist_registration(
rp2p_publisher_runtime_t *runtime,
const char *response)
{
    rp2p_t *ctx;
    rp2p_key_paths_t paths;
    char observed_key[RP2P_KEY_STR_SZ];
    int path_result;
    int result;

    ctx = runtime->borrowed_ctx;
    memset(observed_key, 0, sizeof(observed_key));
    if (!rp2p_parse_ok_key(response, observed_key)) {
        fprintf(stderr, "rp2p: registration failed: %s\n", response);
        if (strcmp(response, RP2P_CTRTOK_AUTH_FAILED) == 0) {
            rp2p_set_error(ctx, "wait: registration authentication failed");
            result = RP2P_EAUTH;
        } else if (strcmp(response,
            RP2P_CTRTOK_ERROR_PEER_TABLE_FULL) == 0)
        {
            rp2p_set_error(ctx, "wait: index peer table is full");
            result = RP2P_EFULL;
        } else {
            rp2p_set_error(ctx, "wait: malformed registration response: %s",
                response);
            result = RP2P_EPROTO;
        }
        crypto_wipe(observed_key, sizeof(observed_key));
        return result;
    }
    memcpy(ctx->key, observed_key, RP2P_KEY_STR_SZ);
    ctx->key[RP2P_KEY_STR_SZ - 1] = '\0';
    path_result = rp2p_key_paths(ctx, runtime->borrowed_index_host,
        runtime->index_port, runtime->borrowed_self_id, &paths);
    if (path_result != RP2P_OK ||
        rp2p_save_key(ctx, &paths, ctx->key) != RP2P_OK)
    {
        rp2p_deregister_with_key(NULL, runtime->borrowed_index_host,
            runtime->index_port, runtime->borrowed_self_id, ctx->key);
        if (path_result == RP2P_OK)
            rp2p_remove_key(NULL, paths.scoped, ctx->key);
        ctx->key[0] = '\0';
        crypto_wipe(observed_key, sizeof(observed_key));
        return RP2P_ERROR;
    }
    crypto_wipe(observed_key, sizeof(observed_key));
    return RP2P_OK;
}

/**
 * Finds an active publisher session for one peer address and transport ID.
 * @param runtime Publisher runtime containing the session table.
 * @param peer_addr Peer address to match.
 * @param session_id TCP session identifier, or NULL for UDP.
 * @return Matching session index, or -1 when no session matches.
 */
static int rp2p_publisher_session_find(
const rp2p_publisher_runtime_t *runtime,
const struct sockaddr_storage *peer_addr,
const unsigned char *session_id)
{
    int i;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (!rp2p_sockaddr_equal(&runtime->owned_sessions[i].peer_addr,
            peer_addr))
            continue;
        if (!runtime->owned_sessions[i].is_tcp && !session_id) return i;
        if (runtime->owned_sessions[i].is_tcp && session_id &&
            memcmp(runtime->owned_sessions[i].stream.session_id, session_id,
                RP2P_STREAM_SESSION_ID_SZ) == 0)
            return i;
    }
    return -1;
}

/**
 * Transfers one initialized publisher session into the owned table.
 * @param runtime Publisher runtime that owns the session table.
 * @param session Initialized session whose descriptors transfer on success.
 * @return Inserted session index, or -1 on allocation failure.
 */
static int rp2p_publisher_session_insert(
rp2p_publisher_runtime_t *runtime,
rp2p_udp_server_session_t *session)
{
    rp2p_udp_server_session_t *new_sessions;
    int index;
    int new_capacity;
    int i;

    index = -1;
    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) {
            index = i;
            break;
        }
    }
    if (index < 0 && runtime->session_count >= runtime->session_capacity) {
        new_capacity = runtime->session_capacity == 0 ? 8 :
            runtime->session_capacity * 2;
        new_sessions = (rp2p_udp_server_session_t *)realloc(
            runtime->owned_sessions,
            (size_t)new_capacity * sizeof(*runtime->owned_sessions));
        if (!new_sessions) {
            rp2p_server_session_close(session);
            crypto_wipe(session, sizeof(*session));
            return -1;
        }
        runtime->owned_sessions = new_sessions;
        runtime->session_capacity = new_capacity;
    }
    if (index < 0) index = runtime->session_count++;
    runtime->owned_sessions[index] = *session;
    crypto_wipe(session, sizeof(*session));
    return index;
}

/**
 * Closes all active publisher sessions in table order.
 * @param runtime Publisher runtime that owns the sessions.
 * @return None.
 */
static void rp2p_publisher_session_close_all(
rp2p_publisher_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].is_tcp &&
            !rp2p_stream_is_done(&runtime->owned_sessions[i].stream))
        {
            rp2p_stream_fail(runtime->borrowed_ctx,
                &runtime->owned_sessions[i].stream);
        }
        rp2p_server_session_close(&runtime->owned_sessions[i]);
    }
}

/**
 * Reads the complete candidate block following one punch call line.
 * @param runtime Publisher runtime owning the control descriptor.
 * @param message Message buffer containing the punch call line.
 * @param message_size Message buffer size.
 * @return 1 for a complete block, 0 for ignored framing, or -1 on error.
 */
static int rp2p_publisher_read_candidate_block(
rp2p_publisher_runtime_t *runtime,
char *message,
size_t message_size)
{
    char line[128];
    int saw_end;
    int line_result;

    saw_end = 0;
    while ((line_result = rp2p_tcp_readline(runtime->owned_control_fd, line,
        sizeof(line), 5)) > 0)
    {
        if (!rp2p_append_text(message, message_size, "\n") ||
            !rp2p_append_text(message, message_size, line))
            break;
        if (strcmp(line, RP2P_CTRTOK_END) == 0) {
            saw_end = 1;
            break;
        }
    }
    if (line_result < 0) {
        rp2p_set_error(runtime->borrowed_ctx,
            "wait: incomplete candidate block");
        return -1;
    }
    if (saw_end && !rp2p_append_text(message, message_size, "\n")) return 0;
    if (!saw_end) return 0;
    return 1;
}

/**
 * Sends the publisher ACK and its exact candidate framing.
 * @param runtime Publisher runtime owning control and UDP descriptors.
 * @param connection_id Consumer identifier.
 * @param session_token Session token used by the punch exchange.
 * @return 1 when framing completed, or 0 when the event must be ignored.
 */
static int rp2p_publisher_send_ack(
rp2p_publisher_runtime_t *runtime,
const char *connection_id,
const char *session_token)
{
    rp2p_candidate_t candidates[RP2P_CANDIDATES_MAX];
    char ack_buf[RP2P_BUF];
    int candidate_count;
    int i;

    candidate_count = 0;
    rp2p_gather_candidates(runtime->borrowed_ctx, runtime->owned_udp_fd,
        candidates, RP2P_CANDIDATES_MAX, &candidate_count);
    snprintf(ack_buf, sizeof(ack_buf), "%s%s:%s:%s\n",
        RP2P_CTRTOK_PUNCH_ACK2, runtime->borrowed_self_id, connection_id,
        session_token);
    for (i = 0; i < candidate_count; i++) {
        if (!rp2p_append_candidate(ack_buf, sizeof(ack_buf), &candidates[i]))
            continue;
    }
    if (!rp2p_append_text(ack_buf, sizeof(ack_buf), RP2P_CTRTOK_END "\n"))
        return 0;
    rp2p_tcp_send(runtime->owned_control_fd, ack_buf);
    return 1;
}

/**
 * Selects a direct peer endpoint while preserving nonfatal punch failures.
 * @param runtime Publisher runtime owning the UDP descriptor.
 * @param connection_id Consumer identifier.
 * @param session_token Session token used by the punch exchange.
 * @param candidates Remote candidate array.
 * @param candidate_count Remote candidate count.
 * @param peer_addr Selected peer address.
 * @return 1 on selection, or 0 for a nonfatal punch failure.
 */
static int rp2p_publisher_select_peer(
rp2p_publisher_runtime_t *runtime,
const char *connection_id,
const char *session_token,
rp2p_candidate_t *candidates,
int candidate_count,
struct sockaddr_storage *peer_addr)
{
    memset(peer_addr, 0, sizeof(*peer_addr));
    return rp2p_punch_select(runtime->borrowed_ctx,
        runtime->borrowed_ctx->sweep, runtime->owned_udp_fd, session_token,
        runtime->borrowed_self_id, connection_id, candidates, candidate_count,
        peer_addr) == RP2P_OK;
}

/**
 * Opens a backend and creates a publisher session when the peer is new.
 * @param runtime Publisher runtime that owns created session resources.
 * @param session_hex Canonical TCP stream session token.
 * @param session_id Decoded TCP stream session identifier.
 * @param peer_addr Selected peer address.
 * @return 1 when the peer is ready, or 0 on a nonfatal backend failure.
 */
static int rp2p_publisher_open_session(
rp2p_publisher_runtime_t *runtime,
const char *session_hex,
const unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ],
const struct sockaddr_storage *peer_addr)
{
    rp2p_udp_server_session_t session;
    rp2p_t *ctx;

    ctx = runtime->borrowed_ctx;
    if (rp2p_publisher_session_find(runtime, peer_addr,
        ctx->proto == RP2P_PROTO_TCP ? session_id : NULL) >= 0)
        return 1;
    memset(&session, 0, sizeof(session));
    session.backend_fd = RP2P_FD_INVALID;
    session.tcp_fd = RP2P_FD_INVALID;
    session.peer_addr = *peer_addr;
    session.last_rx = rp2p_now_s();
    session.last_ka = session.last_rx;
    session.is_tcp = ctx->proto == RP2P_PROTO_TCP ? 1 : 0;
    if (session.is_tcp) {
        session.backend_fd = rp2p_connect_local_tcp(ctx->bind_port);
        if (RP2P_ISERR(session.backend_fd)) {
            fprintf(stderr,
                "rp2p: local backend connect failed on 127.0.0.1:%u\n",
                (unsigned)ctx->bind_port);
            crypto_wipe(&session, sizeof(session));
            return 0;
        }
        if (rp2p_stream_init(ctx, &session.stream, 0,
            runtime->owned_udp_fd, peer_addr, session_id, session_hex,
            RP2P_PROTO_TCP) != 0)
        {
            RP2P_FD_CLOSE(session.backend_fd);
            crypto_wipe(&session, sizeof(session));
            return 0;
        }
    } else {
        session.backend_fd = rp2p_create_socket(
            runtime->borrowed_udp_any_host, 0);
        if (RP2P_ISERR(session.backend_fd)) {
            crypto_wipe(&session, sizeof(session));
            return 0;
        }
    }
    session.active = 1;
    return rp2p_publisher_session_insert(runtime, &session) >= 0;
}

/**
 * Handles one complete publisher punch-call operation.
 * @param runtime Publisher runtime owning control, UDP, and session state.
 * @param message Buffer containing the first control line.
 * @param message_size Control message buffer size.
 * @return 0 to continue this iteration, 1 to skip it, or -1 on error.
 */
static int rp2p_publisher_handle_punch_call(
rp2p_publisher_runtime_t *runtime,
char *message,
size_t message_size)
{
    rp2p_candidate_t remote_candidates[RP2P_CANDIDATES_MAX];
    struct sockaddr_storage peer_addr;
    char connection_id[RP2P_ID_MAX + 1];
    char remote_token[RP2P_CTRL_SESSION_MAX + 1];
    char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
    const char *ack_session;
    int candidate_count;
    int block_result;

    memset(session_hex, 0, sizeof(session_hex));
    if (!rp2p_parse_punch_call2(message, connection_id, remote_token))
        return 0;
    if (runtime->borrowed_ctx->proto == RP2P_PROTO_TCP) {
        if (!rp2p_is_hex_token(remote_token,
            RP2P_STREAM_SESSION_ID_SZ * 2))
            return 1;
        memcpy(session_hex, remote_token, RP2P_STREAM_SESSION_ID_SZ * 2);
        session_hex[RP2P_STREAM_SESSION_ID_SZ * 2] = '\0';
        if (!rp2p_hex_decode(session_hex, session_id, sizeof(session_id)))
            return 1;
    }
    block_result = rp2p_publisher_read_candidate_block(runtime, message,
        message_size);
    if (block_result < 0) return -1;
    if (block_result == 0) return 1;
    candidate_count = 0;
    if (!rp2p_parse_remote_candidates(message, remote_candidates,
        &candidate_count))
        return 1;
    ack_session = session_hex[0] ? session_hex : remote_token;
    if (!rp2p_publisher_send_ack(runtime, connection_id, ack_session))
        return 1;
    if (!rp2p_publisher_select_peer(runtime, connection_id, ack_session,
        remote_candidates, candidate_count, &peer_addr))
        return 1;
    if (!rp2p_publisher_open_session(runtime, session_hex,
        session_id, &peer_addr))
        return 1;
    rp2p_sendto_addr(runtime->owned_udp_fd, RP2P_CTRTOK_PUNCH_SERVER,
        strlen(RP2P_CTRTOK_PUNCH_SERVER), &peer_addr);
    return 0;
}

/**
 * Builds the publisher read set and closes unrepresentable backends.
 * @param runtime Publisher runtime containing all descriptors.
 * @param read_fds Output descriptor set.
 * @param max_fd Output highest descriptor.
 * @return 1 when selectable, 0 to retry, or RP2P_ENET on fatal failure.
 */
static int rp2p_publisher_build_fdset(
rp2p_publisher_runtime_t *runtime,
fd_set *read_fds,
int *max_fd)
{
    rp2p_t *ctx;
    int failed;
    int i;

    ctx = runtime->borrowed_ctx;
    FD_ZERO(read_fds);
    *max_fd = -1;
    if (!rp2p_fdset_add(runtime->owned_control_fd, read_fds, max_fd) ||
        !rp2p_fdset_add(runtime->owned_udp_fd, read_fds, max_fd))
    {
        rp2p_set_error(ctx,
            "wait: essential descriptor cannot be represented by fd_set");
        return RP2P_ENET;
    }
    failed = 0;
    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].backend_fd == RP2P_FD_INVALID) continue;
        if (runtime->owned_sessions[i].is_tcp &&
            !rp2p_stream_can_send_data(&runtime->owned_sessions[i].stream))
            continue;
        if (rp2p_fdset_add(runtime->owned_sessions[i].backend_fd, read_fds,
            max_fd))
            continue;
        rp2p_set_error(ctx,
            "wait: backend descriptor cannot be represented by fd_set");
        if (runtime->owned_sessions[i].is_tcp)
            rp2p_stream_fail(ctx, &runtime->owned_sessions[i].stream);
        rp2p_server_session_close(&runtime->owned_sessions[i]);
        failed = 1;
    }
    return failed ? 0 : 1;
}

/**
 * Sends a due publisher control heartbeat.
 * @param runtime Publisher runtime owning the control descriptor.
 * @return RP2P_OK on success, or RP2P_ENET on send failure.
 */
static int rp2p_publisher_heartbeat(
rp2p_publisher_runtime_t *runtime)
{
    char send_buf[RP2P_BUF];

    if (rp2p_now_s() - runtime->last_heartbeat < RP2P_HEARTBEAT_S)
        return RP2P_OK;
    snprintf(send_buf, sizeof(send_buf), "%s%s", RP2P_CTRTOK_REGISTER,
        runtime->borrowed_self_id);
    if (rp2p_tcp_send(runtime->owned_control_fd, send_buf) != RP2P_OK) {
        rp2p_set_error(runtime->borrowed_ctx,
            "wait: control heartbeat send failed");
        return RP2P_ENET;
    }
    runtime->last_heartbeat = rp2p_now_s();
    return RP2P_OK;
}

/**
 * Processes one ready publisher control event.
 * @param runtime Publisher runtime owning control and session state.
 * @param read_fds Descriptor set returned by select.
 * @return 0 to continue, 1 to skip the iteration, or a negative error code.
 */
static int rp2p_publisher_process_control(
rp2p_publisher_runtime_t *runtime,
const fd_set *read_fds)
{
    char recv_buf[RP2P_BUF];
    int control_result;
    int punch_result;

    if (!FD_ISSET(runtime->owned_control_fd, read_fds)) return 0;
    control_result = rp2p_tcp_readline(runtime->owned_control_fd, recv_buf,
        (int)sizeof(recv_buf), 0);
    if (control_result < 0) {
        if (control_result == -3 || control_result == -4) {
            rp2p_set_error(runtime->borrowed_ctx,
                "wait: invalid control line");
            return RP2P_EPROTO;
        }
        rp2p_set_error(runtime->borrowed_ctx, control_result == -2 ?
            "wait: index closed control connection" :
            "wait: control receive failed");
        return RP2P_ENET;
    }
    if (control_result == 0) return 0;
    punch_result = rp2p_publisher_handle_punch_call(runtime, recv_buf,
        sizeof(recv_buf));
    if (punch_result < 0) return RP2P_EPROTO;
    return punch_result;
}

/**
 * Receives one peer datagram and forwards eligible payload to its backend.
 * @param runtime Publisher runtime owning UDP and session state.
 * @param read_fds Descriptor set returned by select.
 * @return 0 to continue, 1 to skip the iteration, or a negative error code.
 */
static int rp2p_publisher_receive_peer(
rp2p_publisher_runtime_t *runtime,
const fd_set *read_fds)
{
    rp2p_udp_server_session_t *session;
    struct sockaddr_storage from;
    struct sockaddr_in backend_addr;
    char buf[RP2P_BUF + 1];
    char pong[256];
    char ping_session[64] = {0};
    char ping_from[64] = {0};
    char ping_to[64] = {0};
    socklen_t from_length;
    int receive_flags;
    int found;
    int plain_keepalive;
    int punch_control;
    int n;
    rp2p_stream_envelope_t envelope;

    if (!FD_ISSET(runtime->owned_udp_fd, read_fds)) return 0;
    from_length = sizeof(from);
    receive_flags = 0;
#ifndef _WIN32
    receive_flags |= MSG_TRUNC;
#endif
    n = (int)recvfrom(runtime->owned_udp_fd, buf, sizeof(buf) - 1,
        receive_flags, (struct sockaddr *)&from, &from_length);
    if (n < 0) return 0;
#ifndef _WIN32
    if ((size_t)n > sizeof(buf) - 1) {
        rp2p_set_error(runtime->borrowed_ctx,
            "wait: oversized peer datagram");
        return RP2P_ENET;
    }
#endif
    if ((size_t)n >= sizeof(buf)) n = (int)(sizeof(buf) - 1);
    buf[n] = '\0';
    found = -1;
    if (runtime->borrowed_ctx->proto == RP2P_PROTO_TCP) {
        if (rp2p_stream_unpack((const unsigned char *)buf, (size_t)n,
            &envelope))
        {
            found = rp2p_publisher_session_find(runtime, &from,
                envelope.session_id);
        }
    } else {
        found = rp2p_publisher_session_find(runtime, &from, NULL);
    }
    if (found < 0) {
        if (strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
            strlen(RP2P_CTRTOK_PUNCH_PING)) == 0 &&
            rp2p_parse_punch_packet(buf, RP2P_CTRTOK_PUNCH_PING,
                ping_session, ping_from, ping_to))
        {
            snprintf(pong, sizeof(pong), "%s%s:%s:%s",
                RP2P_CTRTOK_PUNCH_PONG, ping_session, ping_to, ping_from);
            sendto(runtime->owned_udp_fd, pong, strlen(pong), 0,
                (const struct sockaddr *)&from, from_length);
        }
        return 0;
    }
    session = &runtime->owned_sessions[found];
    if (!session->is_tcp && (size_t)n > RP2P_UDP_PAYLOAD_MAX) {
        rp2p_set_error(runtime->borrowed_ctx,
            "UDP datagram exceeds maximum payload size");
        return 1;
    }
    plain_keepalive = !session->is_tcp &&
        (size_t)n == strlen(RP2P_CTRTOK_KA) &&
        memcmp(buf, RP2P_CTRTOK_KA, strlen(RP2P_CTRTOK_KA)) == 0;
    punch_control = strncmp(buf, RP2P_CTRTOK_PUNCH,
        strlen(RP2P_CTRTOK_PUNCH)) == 0 ||
        strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
        strlen(RP2P_CTRTOK_PUNCH_PING)) == 0 ||
        strncmp(buf, RP2P_CTRTOK_PUNCH_PONG,
        strlen(RP2P_CTRTOK_PUNCH_PONG)) == 0;
    if (plain_keepalive) {
        session->last_rx = rp2p_now_s();
        return 0;
    }
    if (punch_control) return 1;
    if (session->is_tcp) {
        if (session->backend_fd != RP2P_FD_INVALID &&
            rp2p_stream_process_packet(runtime->borrowed_ctx, &session->stream,
                session->backend_fd, (const unsigned char *)buf,
                (size_t)n) != 0)
        {
            rp2p_stream_fail(runtime->borrowed_ctx, &session->stream);
            rp2p_server_session_close(session);
        }
    } else {
        memset(&backend_addr, 0, sizeof(backend_addr));
        backend_addr.sin_family = AF_INET;
        backend_addr.sin_port = htons(runtime->borrowed_ctx->bind_port);
        inet_pton(AF_INET, "127.0.0.1", &backend_addr.sin_addr);
        sendto(session->backend_fd, (const char *)buf, (size_t)n, 0,
            (const struct sockaddr *)&backend_addr, sizeof(backend_addr));
    }
    session->last_rx = rp2p_now_s();
    return 0;
}

/**
 * Processes ready backend descriptors and forwards data to peers.
 * @param runtime Publisher runtime owning backend and peer descriptors.
 * @param read_fds Descriptor set returned by select.
 * @return None.
 */
static void rp2p_publisher_process_backends(
rp2p_publisher_runtime_t *runtime,
const fd_set *read_fds)
{
    struct sockaddr_in backend_from;
    char buf[RP2P_BUF];
    socklen_t backend_from_length;
    int i;
    int n;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].backend_fd == RP2P_FD_INVALID) continue;
        if (!FD_ISSET(runtime->owned_sessions[i].backend_fd, read_fds))
            continue;
        if (runtime->owned_sessions[i].is_tcp) {
            if (rp2p_stream_pump_tcp(runtime->borrowed_ctx,
                &runtime->owned_sessions[i].stream,
                runtime->owned_sessions[i].backend_fd) != 0)
            {
                rp2p_stream_fail(runtime->borrowed_ctx,
                    &runtime->owned_sessions[i].stream);
                rp2p_server_session_close(&runtime->owned_sessions[i]);
            }
            continue;
        }
        backend_from_length = sizeof(backend_from);
        n = (int)recvfrom(runtime->owned_sessions[i].backend_fd, buf,
            sizeof(buf), 0, (struct sockaddr *)&backend_from,
            &backend_from_length);
        if (n < 0) continue;
        if (backend_from.sin_family != AF_INET ||
            backend_from.sin_port != htons(runtime->borrowed_ctx->bind_port) ||
            ntohl(backend_from.sin_addr.s_addr) != RP2P_IPV4_LOOPBACK)
            continue;
        rp2p_sendto_addr(runtime->owned_udp_fd, buf, (size_t)n,
            &runtime->owned_sessions[i].peer_addr);
        runtime->owned_sessions[i].last_rx = rp2p_now_s();
    }
}

/**
 * Advances publisher stream, keepalive, and disconnect state.
 * @param runtime Publisher runtime owning all sessions.
 * @return None.
 */
static void rp2p_publisher_maintain_sessions(
rp2p_publisher_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].is_tcp) {
            if (rp2p_stream_tick(runtime->borrowed_ctx,
                &runtime->owned_sessions[i].stream) != 0)
            {
                rp2p_stream_fail(runtime->borrowed_ctx,
                    &runtime->owned_sessions[i].stream);
                rp2p_server_session_close(&runtime->owned_sessions[i]);
                continue;
            }
            if (rp2p_stream_is_done(&runtime->owned_sessions[i].stream)) {
                rp2p_server_session_close(&runtime->owned_sessions[i]);
                continue;
            }
        }
        if (rp2p_now_s() - runtime->owned_sessions[i].last_ka >
            RP2P_KEEPALIVE_S)
        {
            if (!runtime->owned_sessions[i].is_tcp)
                rp2p_sendto_addr(runtime->owned_udp_fd, RP2P_CTRTOK_KA,
                    strlen(RP2P_CTRTOK_KA),
                    &runtime->owned_sessions[i].peer_addr);
            runtime->owned_sessions[i].last_ka = rp2p_now_s();
        }
        if (rp2p_now_s() - runtime->owned_sessions[i].last_rx >
            RP2P_DISCONNECT_S)
            rp2p_server_session_close(&runtime->owned_sessions[i]);
    }
}

/**
 * Finds the nearest publisher-side KCP deadline.
 * @return Milliseconds until select should wake, capped at one second.
 */
static uint32_t rp2p_publisher_wait_ms(
    const rp2p_publisher_runtime_t *runtime)
{
    uint32_t wait_ms;
    uint32_t session_wait;
    uint64_t now;
    int i;

    wait_ms = 1000;
    now = rp2p_now_ms();
    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active ||
            !runtime->owned_sessions[i].is_tcp)
            continue;
        session_wait = rp2p_stream_wait_ms(
            &runtime->owned_sessions[i].stream, now);
        if (session_wait < wait_ms) wait_ms = session_wait;
    }
    return wait_ms;
}

/**
 * Runs the publisher event loop in its established event order.
 * @param runtime Registered publisher runtime.
 * @return RP2P_OK on shutdown, or a negative error code on failure.
 */
static int rp2p_publisher_event_loop(
rp2p_publisher_runtime_t *runtime)
{
    fd_set read_fds;
    struct timeval timeout;
    int stage_result;
    int max_fd;
    int selected;
    int result;
    uint32_t wait_ms;

    result = RP2P_OK;
    runtime->last_heartbeat = rp2p_now_s();
    rp2p_set_nonblock(runtime->owned_control_fd);
    rp2p_set_nonblock(runtime->owned_udp_fd);
    while (!runtime->borrowed_ctx->stop_requested) {
        stage_result = rp2p_publisher_build_fdset(runtime, &read_fds, &max_fd);
        if (stage_result < 0) {
            result = stage_result;
            break;
        }
        if (stage_result == 0) continue;
        wait_ms = rp2p_publisher_wait_ms(runtime);
        timeout.tv_sec = (long)(wait_ms / 1000u);
        timeout.tv_usec = (long)((wait_ms % 1000u) * 1000u);
        selected = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (selected < 0) continue;
        if (runtime->borrowed_ctx->stop_requested) break;
        stage_result = rp2p_publisher_heartbeat(runtime);
        if (stage_result != RP2P_OK) {
            result = stage_result;
            break;
        }
        stage_result = rp2p_publisher_process_control(runtime, &read_fds);
        if (stage_result < 0) {
            result = stage_result;
            break;
        }
        if (stage_result > 0) {
            rp2p_publisher_maintain_sessions(runtime);
            continue;
        }
        stage_result = rp2p_publisher_receive_peer(runtime, &read_fds);
        if (stage_result < 0) {
            result = stage_result;
            break;
        }
        if (stage_result > 0) {
            rp2p_publisher_maintain_sessions(runtime);
            continue;
        }
        rp2p_publisher_process_backends(runtime, &read_fds);
        rp2p_publisher_maintain_sessions(runtime);
    }
    rp2p_publisher_session_close_all(runtime);
    return result;
}

/**
 * Deregisters the publisher and removes its persisted key when accepted.
 * @param runtime Publisher runtime borrowing registration identity.
 * @param wait_result Current wait result, updated on key removal failure.
 * @return None.
 */
static void rp2p_publisher_remove_registration(
rp2p_publisher_runtime_t *runtime,
int *wait_result)
{
    rp2p_t *ctx;
    rp2p_key_paths_t paths;
    char prior_error[sizeof(runtime->borrowed_ctx->err_buf)];
    int deregistered;
    int removed;

    ctx = runtime->borrowed_ctx;
    if (ctx->key[0] != '\0') {
        memcpy(prior_error, ctx->err_buf, sizeof(prior_error));
        removed = RP2P_OK;
        deregistered = rp2p_deregister_with_key(ctx,
            runtime->borrowed_index_host, runtime->index_port,
            runtime->borrowed_self_id, ctx->key);
        if (deregistered == RP2P_OK) {
            if (rp2p_key_paths(ctx, runtime->borrowed_index_host,
                runtime->index_port, runtime->borrowed_self_id, &paths) !=
                RP2P_OK ||
                rp2p_remove_key(ctx, paths.scoped, ctx->key) != RP2P_OK)
            {
                removed = RP2P_ERROR;
                *wait_result = RP2P_ERROR;
            }
        }
        if (prior_error[0] != '\0' && deregistered == RP2P_OK &&
            removed == RP2P_OK)
            memcpy(ctx->err_buf, prior_error, sizeof(ctx->err_buf));
        crypto_wipe(prior_error, sizeof(prior_error));
    }
    crypto_wipe(ctx->key, sizeof(ctx->key));
}

/**
 * Releases all publisher-owned runtime resources and optionally resets stop.
 * @param runtime Publisher runtime whose owned resources are released.
 * @param reset_stop Whether to clear the context stop request.
 * @return None.
 */
static void rp2p_publisher_runtime_cleanup(
rp2p_publisher_runtime_t *runtime,
int reset_stop)
{
    rp2p_publisher_session_close_all(runtime);
    if (runtime->owned_sessions)
        crypto_wipe(runtime->owned_sessions,
            (size_t)runtime->session_capacity *
            sizeof(*runtime->owned_sessions));
    free(runtime->owned_sessions);
    runtime->owned_sessions = NULL;
    if (!RP2P_ISERR(runtime->owned_control_fd))
        RP2P_FD_CLOSE(runtime->owned_control_fd);
    if (!RP2P_ISERR(runtime->owned_udp_fd))
        RP2P_FD_CLOSE(runtime->owned_udp_fd);
    runtime->owned_control_fd = RP2P_FD_INVALID;
    runtime->owned_udp_fd = RP2P_FD_INVALID;
    if (reset_stop)
        atomic_store(&runtime->borrowed_ctx->stop_requested, 0);
}

/**
 * Registers a publisher, serves sessions, and tears registration down.
 * @return 0 on success, or a negative error code on failure.
 */
int rp2p_wait(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *self_id,
    unsigned short bind_port)
{
    rp2p_publisher_runtime_t runtime;
    char registration_response[RP2P_BUF];
    int wait_result;

    if (!ctx) return RP2P_EINVAL;
    rp2p_set_error(ctx, NULL);
    if (rp2p_is_stop_requested(ctx)) {
        atomic_store(&ctx->stop_requested, 0);
        return RP2P_OK;
    }
    wait_result = rp2p_publisher_initialize(&runtime, ctx, index_host,
        index_port, self_id, bind_port);
    if (wait_result != RP2P_OK) return wait_result;
    wait_result = rp2p_publisher_register(&runtime, registration_response,
        sizeof(registration_response));
    if (wait_result != RP2P_OK) {
        rp2p_publisher_runtime_cleanup(&runtime, 0);
        return wait_result;
    }
    wait_result = rp2p_publisher_persist_registration(&runtime,
        registration_response);
    if (wait_result != RP2P_OK) {
        rp2p_publisher_runtime_cleanup(&runtime, 0);
        return wait_result;
    }
    rp2p_set_error(ctx, NULL);
    fprintf(stderr, "rp2p: published %s backend 127.0.0.1:%u as '%s'\n",
        ctx->proto == RP2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)ctx->bind_port, self_id);
    wait_result = rp2p_publisher_event_loop(&runtime);
    rp2p_publisher_remove_registration(&runtime, &wait_result);
    rp2p_publisher_runtime_cleanup(&runtime, 1);
    return wait_result;
}

/**
 * Send punch req cands.
 * Summary: Send punch request with candidates.
 * @param ctrl_fd Control fd.
 * @param self_id Self id.
 * @param target_id Target id.
 * @param cands Candidates.
 * @param cand_count Candidate count.
 * @param remote_cands Remote candidates.
 * @param remote_cand_count Remote candidate count.
 * @return 0 on success, -1 on error.
 */
static int rp2p_send_punch_req_cands(
    rp2p_t *ctx,
    rp2p_fd_t ctrl_fd,
    const char *self_id,
    const char *target_id,
    const char *session_id,
    rp2p_candidate_t *cands,
    int cand_count,
    rp2p_candidate_t *remote_cands,
    int *remote_cand_count)
{
    char send_buf[RP2P_BUF];
    char recv_buf[RP2P_BUF];
    int line_result;
    int n;
    
    if (!cands || cand_count <= 0 ||
        cand_count > RP2P_CANDIDATES_MAX || !remote_cands ||
        !remote_cand_count)
        return RP2P_EPROTO;
    *remote_cand_count = 0;
    n = snprintf(send_buf, sizeof(send_buf), "%s%s:%s:%s\n",
        RP2P_CTRTOK_PUNCH_REQ2, self_id, target_id,
        session_id ? session_id : "0");
    if (n < 0 || (size_t)n >= sizeof(send_buf)) {
        rp2p_set_error(ctx, "connect: punch request is too large");
        return RP2P_EPROTO;
    }
    for (int i = 0; i < cand_count; i++) {
        if (!rp2p_append_candidate(send_buf, sizeof(send_buf), &cands[i])) {
            rp2p_set_error(ctx, "connect: invalid local punch candidate");
            return RP2P_EPROTO;
        }
    }
    if (!rp2p_append_text(send_buf, sizeof(send_buf), RP2P_CTRTOK_END "\n")) {
        rp2p_set_error(ctx, "connect: punch request is too large");
        return RP2P_EPROTO;
    }
    
    if (rp2p_tcp_send(ctrl_fd, send_buf) != RP2P_OK) {
        rp2p_set_error(ctx, "connect: punch control write failed");
        return RP2P_ENET;
    }
    line_result = rp2p_tcp_readline(ctrl_fd, recv_buf,
        (int)sizeof(recv_buf), 20);
    if (line_result < 0) {
        if (line_result == -1) {
            rp2p_set_error(ctx, "connect: punch response timed out");
            return RP2P_ETIMEOUT;
        }
        if (line_result == -3 || line_result == -4) {
            rp2p_set_error(ctx, "connect: malformed punch response line");
            return RP2P_EPROTO;
        }
        rp2p_set_error(ctx, "connect: punch control connection closed");
        return RP2P_ENET;
    }
    
    if (strncmp(recv_buf, RP2P_CTRTOK_PUNCH_OK2,
        strlen(RP2P_CTRTOK_PUNCH_OK2)) == 0) {
        char lbuf[128];
        char ok_id[RP2P_ID_MAX + 1];
        char ok_sess[RP2P_CTRL_SESSION_MAX + 1];
        int saw_end = 0;
        if (!rp2p_parse_punch_ok2(recv_buf, ok_id, ok_sess)) {
            rp2p_set_error(ctx, "connect: malformed punch response");
            return RP2P_EPROTO;
        }
        if (strcmp(ok_id, target_id) != 0 ||
            strcmp(ok_sess, session_id ? session_id : "0") != 0) {
            rp2p_set_error(ctx, "connect: punch response identity mismatch");
            return RP2P_EPROTO;
        }

        while ((line_result = rp2p_tcp_readline(ctrl_fd, lbuf,
            sizeof(lbuf), 5)) > 0)
        {
            if (!rp2p_append_text(recv_buf, sizeof(recv_buf), "\n") ||
                !rp2p_append_text(recv_buf, sizeof(recv_buf), lbuf)) {
                rp2p_set_error(ctx,
                    "connect: punch candidate response is too large");
                return RP2P_EPROTO;
            }
            if (strcmp(lbuf, RP2P_CTRTOK_END) == 0) {
                saw_end = 1;
                break;
            }
        }
        if (line_result < 0) {
            if (line_result == -1) {
                rp2p_set_error(ctx,
                    "connect: punch candidate line timed out");
                return RP2P_ETIMEOUT;
            }
            if (line_result == -3 || line_result == -4) {
                rp2p_set_error(ctx,
                    "connect: malformed punch candidate line");
                return RP2P_EPROTO;
            }
            rp2p_set_error(ctx,
                "connect: punch candidate connection closed");
            return RP2P_ENET;
        }
        if (saw_end && !rp2p_append_text(recv_buf, sizeof(recv_buf), "\n")) {
            rp2p_set_error(ctx,
                "connect: punch candidate response is too large");
            return RP2P_EPROTO;
        }
        if (!saw_end) {
            rp2p_set_error(ctx, "connect: incomplete punch candidate block");
            return RP2P_EPROTO;
        }
        if (!rp2p_parse_remote_candidates(recv_buf, remote_cands,
            remote_cand_count)) {
            rp2p_set_error(ctx, "connect: malformed punch candidate block");
            return RP2P_EPROTO;
        }
    } else {
        rp2p_set_error(ctx, "connect: unexpected punch response: %s",
            recv_buf);
        return RP2P_EPROTO;
    }
    return RP2P_OK;
}

/**
 * Finds an active UDP session for one local client address.
 * @param runtime Consumer runtime containing the session table.
 * @param client_addr Local client address to match.
 * @return Matching session index, or -1 when no session matches.
 */
static int rp2p_consumer_session_find(
const rp2p_consumer_runtime_t *runtime,
const struct sockaddr_storage *client_addr)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (rp2p_sockaddr_equal(&runtime->sessions[i].client_addr,
            client_addr))
            return i;
    }
    return -1;
}

/**
 * Transfers one initialized session into a compatible table slot.
 * @param runtime Consumer runtime that owns the session table.
 * @param session Initialized session whose descriptors transfer on success.
 * @return Inserted session index, or -1 on allocation failure.
 */
static int rp2p_consumer_session_insert(
rp2p_consumer_runtime_t *runtime,
rp2p_udp_consumer_session_t *session)
{
    rp2p_udp_consumer_session_t *new_sessions;
    int index;
    int new_cap;

    index = -1;
    for (int i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) {
            index = i;
            break;
        }
    }
    if (index < 0 && runtime->n_sessions >= runtime->cap_sessions) {
        new_cap = runtime->cap_sessions == 0 ? 8 : runtime->cap_sessions * 2;
        new_sessions = (rp2p_udp_consumer_session_t *)realloc(
            runtime->sessions, (size_t)new_cap * sizeof(*runtime->sessions));
        if (!new_sessions) {
            rp2p_consumer_session_close(session);
            crypto_wipe(session, sizeof(*session));
            return -1;
        }
        runtime->sessions = new_sessions;
        runtime->cap_sessions = new_cap;
    }
    if (index < 0) index = runtime->n_sessions++;
    runtime->sessions[index] = *session;
    crypto_wipe(session, sizeof(*session));
    return index;
}

/**
 * Closes every active consumer session in table order.
 * @param runtime Consumer runtime that owns the sessions.
 * @return None.
 */
static void rp2p_consumer_session_close_all(
rp2p_consumer_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (runtime->sessions[i].is_tcp &&
            !rp2p_stream_is_done(&runtime->sessions[i].stream))
        {
            rp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
        }
        rp2p_consumer_session_close(&runtime->sessions[i]);
    }
}

/**
 * Establishes one peer path and transfers its descriptor only on success.
 * @param runtime Consumer runtime containing control and peer settings.
 * @param is_tcp Non-zero selects the TCP stream session identifier format.
 * @param out_fd Output peer descriptor.
 * @param out_peer Output selected peer address.
 * @param session_bin Output binary session identifier.
 * @param session_hex Output hexadecimal session identifier.
 * @param skip_iteration Output set when the current event iteration must end.
 * @return RP2P_OK on success, or the existing establishment error code.
 */
static int rp2p_consumer_establish_peer(
rp2p_consumer_runtime_t *runtime,
int is_tcp,
rp2p_fd_t *out_fd,
struct sockaddr_storage *out_peer,
unsigned char session_bin[RP2P_STREAM_SESSION_ID_SZ],
char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1],
int *skip_iteration)
{
    rp2p_candidate_t candidates[RP2P_CANDIDATES_MAX];
    rp2p_candidate_t remote_candidates[RP2P_CANDIDATES_MAX];
    struct sockaddr_storage peer_addr;
    rp2p_fd_t control_fd;
    rp2p_fd_t peer_fd;
    int candidate_count;
    int control_result;
    int remote_candidate_count;
    int result;
    size_t random_size;
    size_t hex_size;

    *out_fd = RP2P_FD_INVALID;
    memset(out_peer, 0, sizeof(*out_peer));
    memset(session_bin, 0, RP2P_STREAM_SESSION_ID_SZ);
    memset(session_hex, 0, RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
    if (skip_iteration) *skip_iteration = 0;
    control_fd = rp2p_control_connect(runtime->ctx, "connect",
        runtime->index_host, runtime->index_port, &control_result);
    if (RP2P_ISERR(control_fd)) return control_result;

    if (is_tcp) {
        if (!rp2p_stream_make_session_id(session_bin, session_hex)) {
            if (skip_iteration) *skip_iteration = 1;
            crypto_wipe(session_bin, RP2P_STREAM_SESSION_ID_SZ);
            crypto_wipe(session_hex, RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
            RP2P_FD_CLOSE(control_fd);
            return RP2P_ENET;
        }
    } else {
        random_size = 8;
        hex_size = 17;
        if (rp2p_fill_random(session_bin, random_size) != 0 ||
            !rp2p_hex_encode(session_bin, random_size, session_hex, hex_size))
        {
            if (skip_iteration) *skip_iteration = 1;
            crypto_wipe(session_bin, RP2P_STREAM_SESSION_ID_SZ);
            crypto_wipe(session_hex, RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
            RP2P_FD_CLOSE(control_fd);
            return RP2P_ENET;
        }
    }

    peer_fd = rp2p_create_socket(runtime->udp_any_host, 0);
    candidate_count = 0;
    if (RP2P_ISERR(peer_fd) ||
        rp2p_gather_candidates(runtime->ctx, peer_fd, candidates,
            RP2P_CANDIDATES_MAX, &candidate_count) != RP2P_OK)
    {
        if (skip_iteration) *skip_iteration = 1;
        crypto_wipe(session_bin, RP2P_STREAM_SESSION_ID_SZ);
        crypto_wipe(session_hex, RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
        if (!RP2P_ISERR(peer_fd)) RP2P_FD_CLOSE(peer_fd);
        RP2P_FD_CLOSE(control_fd);
        return RP2P_ENET;
    }
    remote_candidate_count = 0;
    result = rp2p_send_punch_req_cands(runtime->ctx, control_fd,
        runtime->self_id, runtime->target_id, session_hex,
        candidates, candidate_count, remote_candidates,
        &remote_candidate_count);
    RP2P_FD_CLOSE(control_fd);
    if (result != RP2P_OK) {
        if (skip_iteration) *skip_iteration = 1;
        crypto_wipe(session_bin, RP2P_STREAM_SESSION_ID_SZ);
        crypto_wipe(session_hex, RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
        RP2P_FD_CLOSE(peer_fd);
        return result;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    result = rp2p_punch_select(runtime->ctx, runtime->ctx->sweep,
        (int)peer_fd,
        session_hex, runtime->self_id, runtime->target_id,
        remote_candidates, remote_candidate_count, &peer_addr);
    if (result != RP2P_OK) {
        fprintf(stderr, "rp2p: udp punch failed\n");
        RP2P_FD_CLOSE((int)peer_fd);
        crypto_wipe(session_bin, RP2P_STREAM_SESSION_ID_SZ);
        crypto_wipe(session_hex, RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
        return result;
    }

    *out_fd = (int)peer_fd;
    *out_peer = peer_addr;
    return RP2P_OK;
}

/**
 * Initializes one established TCP consumer session.
 * @param runtime Consumer runtime containing stream identities.
 * @param session Session receiving ownership of peer and client descriptors.
 * @param peer_fd Established peer descriptor.
 * @param peer_addr Selected peer address.
 * @param client_fd Accepted local TCP descriptor.
 * @param session_bin Binary stream session identifier.
 * @param session_hex Hexadecimal stream session identifier.
 * @return 0 on success, -1 when KCP initialization fails.
 */
static int rp2p_consumer_tcp_session_init(
rp2p_consumer_runtime_t *runtime,
rp2p_udp_consumer_session_t *session,
rp2p_fd_t peer_fd,
const struct sockaddr_storage *peer_addr,
rp2p_fd_t client_fd,
const unsigned char session_bin[RP2P_STREAM_SESSION_ID_SZ],
const char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1])
{
    memset(session, 0, sizeof(*session));
    session->fd = peer_fd;
    session->tcp_fd = client_fd;
    session->peer_addr = *peer_addr;
    if (rp2p_stream_init(runtime->ctx, &session->stream, 1, peer_fd,
        peer_addr, session_bin, session_hex, RP2P_PROTO_TCP) != 0)
        return -1;
    session->active = 1;
    session->is_tcp = 1;
    session->last_rx = rp2p_now_s();
    session->last_ka = session->last_rx;
    memset(&session->client_addr, 0, sizeof(session->client_addr));
    return 0;
}

/**
 * Initializes one established UDP consumer session.
 * @param session Session receiving ownership of the peer descriptor.
 * @param peer_fd Established peer descriptor.
 * @param peer_addr Selected peer address.
 * @param client_addr Local datagram source address.
 * @return None.
 */
static void rp2p_consumer_udp_session_init(
rp2p_udp_consumer_session_t *session,
rp2p_fd_t peer_fd,
const struct sockaddr_storage *peer_addr,
const struct sockaddr_storage *client_addr)
{
    memset(session, 0, sizeof(*session));
    session->fd = peer_fd;
    session->tcp_fd = RP2P_FD_INVALID;
    session->peer_addr = *peer_addr;
    session->client_addr = *client_addr;
    session->last_rx = rp2p_now_s();
    session->last_ka = session->last_rx;
    session->active = 1;
    session->is_tcp = 0;
}

/**
 * Initializes consumer validation, platform state, and local descriptors.
 * @param runtime Consumer runtime receiving owned resources.
 * @param ctx Public context borrowed for the runtime lifetime.
 * @param index_host Index host borrowed for the runtime lifetime.
 * @param index_port Index control port.
 * @param self_id Consumer identity borrowed for the runtime lifetime.
 * @param target_id Publisher identity borrowed for the runtime lifetime.
 * @param bind_port Requested local adapter port.
 * @param should_run Output set when the consumer loop should start.
 * @return RP2P_OK on success, or the existing initialization error code.
 */
static int rp2p_consumer_runtime_init(
rp2p_consumer_runtime_t *runtime,
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port,
int *should_run)
{
    unsigned short effective_port;

    memset(runtime, 0, sizeof(*runtime));
    runtime->ctx = ctx;
    runtime->index_host = index_host;
    runtime->index_port = index_port;
    runtime->self_id = self_id;
    runtime->target_id = target_id;
    runtime->local_fd = RP2P_FD_INVALID;
    runtime->tcp_listen_fd = RP2P_FD_INVALID;
    *should_run = 0;
    rp2p_set_error(runtime->ctx, NULL);
    if (rp2p_is_stop_requested(runtime->ctx)) {
        atomic_store(&runtime->ctx->stop_requested, 0);
        return RP2P_OK;
    }
    if (rp2p_resolve_port(runtime->ctx, bind_port, &effective_port) != RP2P_OK) {
        rp2p_set_error(runtime->ctx, "connect: conflicting local ports");
        return RP2P_EINVAL;
    }
    if (effective_port == 0 || !runtime->index_host || !runtime->self_id ||
        !runtime->target_id || !rp2p_is_valid_id(runtime->self_id) ||
        !rp2p_is_valid_id(runtime->target_id) || runtime->index_port == 0 ||
        (runtime->ctx->proto != RP2P_PROTO_TCP &&
        runtime->ctx->proto != RP2P_PROTO_UDP))
    {
        rp2p_set_error(runtime->ctx,
            "connect: invalid index, identity, protocol, or local port");
        return RP2P_EINVAL;
    }
    runtime->ctx->bind_port = effective_port;
    if (rp2p_platform_init() != 0) {
        rp2p_set_error(runtime->ctx, "connect: platform init failed");
        return RP2P_ENET;
    }
    runtime->platform_initialized = 1;
    runtime->udp_any_host = rp2p_host_is_ipv6_literal(runtime->index_host) ?
        "::" : "0.0.0.0";

    if (runtime->ctx->proto == RP2P_PROTO_UDP) {
        runtime->local_fd = rp2p_create_socket("127.0.0.1",
            runtime->ctx->bind_port);
        if (RP2P_ISERR(runtime->local_fd)) {
            rp2p_set_error(runtime->ctx, "connect: local UDP bind failed");
            return RP2P_ENET;
        }
    } else {
        runtime->local_fd = rp2p_create_socket(runtime->udp_any_host, 0);
        if (RP2P_ISERR(runtime->local_fd)) {
            rp2p_set_error(runtime->ctx,
                "connect: peer UDP socket setup failed");
            return RP2P_ENET;
        }
        runtime->tcp_listen_fd = rp2p_create_tcp_listener("127.0.0.1",
            runtime->ctx->bind_port);
        if (RP2P_ISERR(runtime->tcp_listen_fd)) {
            rp2p_set_error(runtime->ctx,
                "connect: local TCP bind/listen failed");
            return RP2P_ENET;
        }
    }
    *should_run = 1;
    return RP2P_OK;
}

/**
 * Confirms that the target publisher exists before serving local clients.
 * @param runtime Initialized consumer runtime.
 * @return RP2P_OK on success, or the existing lookup error code.
 */
static int rp2p_consumer_initial_lookup(rp2p_consumer_runtime_t *runtime) {
    char recv_buf[RP2P_BUF];
    rp2p_fd_t control_fd;
    int control_result;
    int line_result;

    control_fd = rp2p_control_connect(runtime->ctx, "connect",
        runtime->index_host, runtime->index_port, &control_result);
    if (RP2P_ISERR(control_fd)) return control_result;
    snprintf(recv_buf, sizeof(recv_buf), "%s%s", RP2P_CTRTOK_LOOKUP,
        runtime->target_id);
    line_result = rp2p_tcp_send(control_fd, recv_buf);
    if (line_result == RP2P_OK) {
        line_result = rp2p_tcp_readline(control_fd, recv_buf,
            (int)sizeof(recv_buf), 5);
    }
    if (line_result < 0) {
        RP2P_FD_CLOSE(control_fd);
        if (line_result == -1) {
            rp2p_set_error(runtime->ctx,
                "connect: lookup response timed out");
            return RP2P_ETIMEOUT;
        }
        if (line_result == -3 || line_result == -4) {
            rp2p_set_error(runtime->ctx,
                "connect: malformed lookup response line");
            return RP2P_EPROTO;
        }
        rp2p_set_error(runtime->ctx, "connect: lookup transport failed");
        return RP2P_ENET;
    }
    if (strcmp(recv_buf, RP2P_CTRTOK_NOT_FOUND) == 0) {
        rp2p_set_error(runtime->ctx, "connect: target publisher not found");
        RP2P_FD_CLOSE(control_fd);
        return RP2P_ENOENT;
    }
    if (strcmp(recv_buf, RP2P_CTRTOK_PUBLISHER) == 0 ||
        strncmp(recv_buf, RP2P_CTRTOK_PUBLISHER,
            strlen(RP2P_CTRTOK_PUBLISHER)) != 0 ||
        strcmp(recv_buf + strlen(RP2P_CTRTOK_PUBLISHER),
            runtime->target_id) != 0)
    {
        rp2p_set_error(runtime->ctx, "connect: malformed lookup response: %s",
            recv_buf);
        RP2P_FD_CLOSE(control_fd);
        return RP2P_EPROTO;
    }
    RP2P_FD_CLOSE(control_fd);
    rp2p_set_error(runtime->ctx, NULL);
    return RP2P_OK;
}

/**
 * Builds the consumer read set while closing unrepresentable sessions.
 * @param runtime Consumer runtime containing all descriptors.
 * @param fds Output descriptor set.
 * @param maxfd Output highest descriptor.
 * @return 1 when selectable, 0 after a session close, or -1 on fatal error.
 */
static int rp2p_consumer_fdset_build(
rp2p_consumer_runtime_t *runtime,
fd_set *fds,
int *maxfd)
{
    int failed;
    int i;

    FD_ZERO(fds);
    *maxfd = -1;
    if (!rp2p_fdset_add(runtime->local_fd, fds, maxfd)) {
        rp2p_set_error(runtime->ctx,
            "connect: local descriptor cannot be represented by fd_set");
        return -1;
    }
    if (!RP2P_ISERR(runtime->tcp_listen_fd) &&
        !rp2p_fdset_add(runtime->tcp_listen_fd, fds, maxfd))
    {
        rp2p_set_error(runtime->ctx,
            "connect: listener cannot be represented by fd_set");
        return -1;
    }

    failed = 0;
    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (!rp2p_fdset_add(runtime->sessions[i].fd, fds, maxfd)) {
            rp2p_set_error(runtime->ctx,
                "connect: peer descriptor cannot be represented by fd_set");
            if (runtime->sessions[i].is_tcp) {
                rp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
            }
            rp2p_consumer_session_close(&runtime->sessions[i]);
            failed = 1;
            continue;
        }
        if (!runtime->sessions[i].is_tcp ||
            runtime->sessions[i].tcp_fd == RP2P_FD_INVALID ||
            !rp2p_stream_can_send_data(&runtime->sessions[i].stream))
            continue;
        if (!rp2p_fdset_add(runtime->sessions[i].tcp_fd, fds, maxfd)) {
            rp2p_set_error(runtime->ctx,
                "connect: client descriptor cannot be represented by fd_set");
            rp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
            rp2p_consumer_session_close(&runtime->sessions[i]);
            failed = 1;
        }
    }
    return failed ? 0 : 1;
}

/**
 * Accepts and establishes one pending local TCP client.
 * @param runtime Consumer runtime owning accepted sessions.
 * @param fds Selected descriptor set.
 * @return 1 when the current event iteration must end, 0 otherwise.
 */
static int rp2p_consumer_tcp_accept(
rp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    unsigned char session_bin[RP2P_STREAM_SESSION_ID_SZ];
    char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    struct sockaddr_storage peer_addr;
    rp2p_udp_consumer_session_t session;
    rp2p_fd_t client_fd;
    rp2p_fd_t peer_fd;
    int skip_iteration;

    if (RP2P_ISERR(runtime->tcp_listen_fd) ||
        !FD_ISSET(runtime->tcp_listen_fd, fds))
        return 0;
    client_fd = accept(runtime->tcp_listen_fd, NULL, NULL);
    if (RP2P_ISERR(client_fd)) return 0;
    if (rp2p_consumer_establish_peer(runtime, 1, &peer_fd, &peer_addr,
        session_bin, session_hex, &skip_iteration) != RP2P_OK)
    {
        RP2P_FD_CLOSE(client_fd);
        return skip_iteration;
    }
    if (rp2p_consumer_tcp_session_init(runtime, &session, peer_fd, &peer_addr,
        client_fd, session_bin, session_hex) != 0)
    {
        RP2P_FD_CLOSE(peer_fd);
        RP2P_FD_CLOSE(client_fd);
        crypto_wipe(session_bin, sizeof(session_bin));
        crypto_wipe(session_hex, sizeof(session_hex));
        return 1;
    }
    crypto_wipe(session_bin, sizeof(session_bin));
    crypto_wipe(session_hex, sizeof(session_hex));
    return rp2p_consumer_session_insert(runtime, &session) < 0 ? 1 : 0;
}

/**
 * Receives one local UDP datagram and finds or creates its peer session.
 * @param runtime Consumer runtime owning UDP sessions.
 * @param fds Selected descriptor set.
 * @return 1 when processing may continue, or 0 after oversized input.
 */
static int rp2p_consumer_udp_receive(
rp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    unsigned char session_bin[RP2P_STREAM_SESSION_ID_SZ];
    char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    char buf[RP2P_BUF];
    struct sockaddr_storage from;
    struct sockaddr_storage peer_addr;
    rp2p_udp_consumer_session_t session;
    rp2p_fd_t peer_fd;
    socklen_t fromlen;
    int found;
    int n;

    if (!RP2P_ISERR(runtime->tcp_listen_fd) ||
        !FD_ISSET(runtime->local_fd, fds))
        return 1;
    fromlen = sizeof(from);
    n = (int)recvfrom(runtime->local_fd, buf, sizeof(buf), 0,
        (struct sockaddr *)&from, &fromlen);
    if (n < 0) return 1;
    if ((size_t)n > RP2P_UDP_PAYLOAD_MAX) {
        rp2p_set_error(runtime->ctx,
            "UDP datagram exceeds maximum payload size");
        return 0;
    }

    found = rp2p_consumer_session_find(runtime, &from);
    if (found < 0 && rp2p_consumer_establish_peer(runtime, 0, &peer_fd,
        &peer_addr, session_bin, session_hex, NULL) == RP2P_OK)
    {
        rp2p_consumer_udp_session_init(&session, peer_fd, &peer_addr, &from);
        crypto_wipe(session_bin, sizeof(session_bin));
        crypto_wipe(session_hex, sizeof(session_hex));
        found = rp2p_consumer_session_insert(runtime, &session);
    }
    if (found >= 0) {
        rp2p_sendto_addr(runtime->sessions[found].fd, buf, (size_t)n,
            &runtime->sessions[found].peer_addr);
        runtime->sessions[found].last_rx = rp2p_now_s();
    }
    return 1;
}

/**
 * Pumps readable local TCP clients into their peer streams.
 * @param runtime Consumer runtime containing TCP sessions.
 * @param fds Selected descriptor set.
 * @return None.
 */
static void rp2p_consumer_tcp_pump(
rp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    int i;

    if (RP2P_ISERR(runtime->tcp_listen_fd)) return;
    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (!FD_ISSET(runtime->sessions[i].tcp_fd, fds)) continue;
        if (rp2p_stream_pump_tcp(runtime->ctx,
            &runtime->sessions[i].stream, runtime->sessions[i].tcp_fd) != 0)
        {
            rp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
            rp2p_consumer_session_close(&runtime->sessions[i]);
        }
    }
}

/**
 * Receives selected peer packets in session-table order.
 * @param runtime Consumer runtime containing peer sessions.
 * @param fds Selected descriptor set.
 * @return None.
 */
static void rp2p_consumer_peer_receive(
rp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        char buf[RP2P_BUF];
        struct sockaddr_storage from;
        socklen_t fromlen;
        int n;
        int plain_keepalive;
        int punch_control;

        if (!runtime->sessions[i].active) continue;
        if (!FD_ISSET(runtime->sessions[i].fd, fds)) continue;
        fromlen = sizeof(from);
        n = (int)recvfrom(runtime->sessions[i].fd, buf, sizeof(buf), 0,
            (struct sockaddr *)&from, &fromlen);
        if (n < 0) continue;
        if (!runtime->sessions[i].is_tcp &&
            (size_t)n > RP2P_UDP_PAYLOAD_MAX)
        {
            rp2p_set_error(runtime->ctx,
                "UDP datagram exceeds maximum payload size");
            continue;
        }
        if (!rp2p_sockaddr_equal(&from, &runtime->sessions[i].peer_addr))
            continue;
        plain_keepalive = !runtime->sessions[i].is_tcp &&
            (size_t)n == strlen(RP2P_CTRTOK_KA) &&
            memcmp(buf, RP2P_CTRTOK_KA, strlen(RP2P_CTRTOK_KA)) == 0;
        punch_control = ((size_t)n >= strlen(RP2P_CTRTOK_PUNCH) &&
            strncmp(buf, RP2P_CTRTOK_PUNCH,
                strlen(RP2P_CTRTOK_PUNCH)) == 0) ||
            ((size_t)n >= strlen(RP2P_CTRTOK_PUNCH_PING) &&
            strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
                strlen(RP2P_CTRTOK_PUNCH_PING)) == 0) ||
            ((size_t)n >= strlen(RP2P_CTRTOK_PUNCH_PONG) &&
            strncmp(buf, RP2P_CTRTOK_PUNCH_PONG,
                strlen(RP2P_CTRTOK_PUNCH_PONG)) == 0);
        if (plain_keepalive) {
            runtime->sessions[i].last_rx = rp2p_now_s();
        } else if (punch_control) {
            continue;
        } else {
            if (runtime->sessions[i].is_tcp) {
                if (runtime->sessions[i].tcp_fd != RP2P_FD_INVALID &&
                    rp2p_stream_process_packet(runtime->ctx,
                        &runtime->sessions[i].stream,
                        runtime->sessions[i].tcp_fd,
                        (const unsigned char *)buf, (size_t)n) != 0)
                {
                    rp2p_stream_fail(runtime->ctx,
                        &runtime->sessions[i].stream);
                    rp2p_consumer_session_close(&runtime->sessions[i]);
                }
            } else {
                rp2p_sendto_addr(runtime->local_fd, buf, (size_t)n,
                    &runtime->sessions[i].client_addr);
            }
            runtime->sessions[i].last_rx = rp2p_now_s();
        }
    }
}

/**
 * Advances stream state, keepalives, and idle expiry in table order.
 * @param runtime Consumer runtime containing active sessions.
 * @return None.
 */
static void rp2p_consumer_session_maintain(
rp2p_consumer_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (runtime->sessions[i].is_tcp) {
            if (rp2p_stream_tick(runtime->ctx,
                &runtime->sessions[i].stream) != 0)
            {
                rp2p_stream_fail(runtime->ctx,
                    &runtime->sessions[i].stream);
                rp2p_consumer_session_close(&runtime->sessions[i]);
                continue;
            }
            if (rp2p_stream_is_done(&runtime->sessions[i].stream)) {
                rp2p_consumer_session_close(&runtime->sessions[i]);
                continue;
            }
        }
        if (rp2p_now_s() - runtime->sessions[i].last_ka >
            RP2P_KEEPALIVE_S)
        {
            if (!runtime->sessions[i].is_tcp) {
                rp2p_sendto_addr(runtime->sessions[i].fd, RP2P_CTRTOK_KA,
                    strlen(RP2P_CTRTOK_KA),
                    &runtime->sessions[i].peer_addr);
            }
            runtime->sessions[i].last_ka = rp2p_now_s();
        }
        if (rp2p_now_s() - runtime->sessions[i].last_rx >
            RP2P_DISCONNECT_S)
        {
            rp2p_consumer_session_close(&runtime->sessions[i]);
        }
    }
}

/**
 * Finds the nearest consumer-side KCP deadline.
 * @return Milliseconds until select should wake, capped at one second.
 */
static uint32_t rp2p_consumer_wait_ms(
    const rp2p_consumer_runtime_t *runtime)
{
    uint32_t wait_ms;
    uint32_t session_wait;
    uint64_t now;
    int i;

    wait_ms = 1000;
    now = rp2p_now_ms();
    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active || !runtime->sessions[i].is_tcp)
            continue;
        session_wait = rp2p_stream_wait_ms(&runtime->sessions[i].stream, now);
        if (session_wait < wait_ms) wait_ms = session_wait;
    }
    return wait_ms;
}

/**
 * Runs the consumer event loop with the existing phase ordering.
 * @param runtime Initialized and target-validated consumer runtime.
 * @return RP2P_OK on stop, or RP2P_ENET on fatal descriptor failure.
 */
static int rp2p_consumer_loop(rp2p_consumer_runtime_t *runtime) {
    int result;

    result = RP2P_OK;
    fprintf(stderr, "rp2p: %s edge adapter on 127.0.0.1:%u for %s\n",
        runtime->ctx->proto == RP2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)runtime->ctx->bind_port, runtime->target_id);
    rp2p_set_nonblock(runtime->local_fd);
    if (!RP2P_ISERR(runtime->tcp_listen_fd))
        rp2p_set_nonblock(runtime->tcp_listen_fd);

    while (!runtime->ctx->stop_requested) {
        fd_set fds;
        struct timeval tv;
        int fdset_result;
        int maxfd;
        int selected;
        uint32_t wait_ms;

        fdset_result = rp2p_consumer_fdset_build(runtime, &fds, &maxfd);
        if (fdset_result < 0) {
            result = RP2P_ENET;
            break;
        }
        if (fdset_result == 0) continue;
        wait_ms = rp2p_consumer_wait_ms(runtime);
        tv.tv_sec = (long)(wait_ms / 1000u);
        tv.tv_usec = (long)((wait_ms % 1000u) * 1000u);
        selected = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (selected < 0) continue;
        if (runtime->ctx->stop_requested) break;

        if (rp2p_consumer_tcp_accept(runtime, &fds)) {
            rp2p_consumer_session_maintain(runtime);
            continue;
        }
        if (!RP2P_ISERR(runtime->tcp_listen_fd)) {
            rp2p_consumer_tcp_pump(runtime, &fds);
        } else if (!rp2p_consumer_udp_receive(runtime, &fds)) {
            rp2p_consumer_session_maintain(runtime);
            continue;
        }
        rp2p_consumer_peer_receive(runtime, &fds);
        rp2p_consumer_session_maintain(runtime);
    }
    return result;
}

/**
 * Releases every resource owned by one consumer runtime.
 * @param runtime Consumer runtime to release.
 * @param reset_stop Non-zero consumes the context stop request.
 * @return None.
 */
static void rp2p_consumer_runtime_cleanup(
rp2p_consumer_runtime_t *runtime,
int reset_stop)
{
    rp2p_consumer_session_close_all(runtime);
    if (runtime->sessions) {
        crypto_wipe(runtime->sessions,
            (size_t)runtime->cap_sessions * sizeof(*runtime->sessions));
    }
    free(runtime->sessions);
    runtime->sessions = NULL;
    runtime->n_sessions = 0;
    runtime->cap_sessions = 0;
    if (!RP2P_ISERR(runtime->local_fd)) {
        RP2P_FD_CLOSE(runtime->local_fd);
        runtime->local_fd = RP2P_FD_INVALID;
    }
    if (!RP2P_ISERR(runtime->tcp_listen_fd)) {
        RP2P_FD_CLOSE(runtime->tcp_listen_fd);
        runtime->tcp_listen_fd = RP2P_FD_INVALID;
    }
    if (runtime->platform_initialized) {
        rp2p_platform_cleanup();
        runtime->platform_initialized = 0;
    }
    if (reset_stop) atomic_store(&runtime->ctx->stop_requested, 0);
}

/**
 * Runs the consumer lifecycle for one local edge adapter.
 * @return Existing public RP2P result code.
 */
int rp2p_connect(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port)
{
    rp2p_consumer_runtime_t runtime;
    int loop_ran;
    int result;
    int should_run;

    if (!ctx) return RP2P_EINVAL;
    loop_ran = 0;

    result = rp2p_consumer_runtime_init(&runtime, ctx, index_host, index_port,
        self_id, target_id, bind_port, &should_run);
    if (result != RP2P_OK || !should_run) {
        rp2p_consumer_runtime_cleanup(&runtime, 0);
        return result;
    }
    result = rp2p_consumer_initial_lookup(&runtime);
    if (result == RP2P_OK) {
        loop_ran = 1;
        result = rp2p_consumer_loop(&runtime);
    }
    rp2p_consumer_runtime_cleanup(&runtime, loop_ran);
    return result;
}

#ifdef RP2P_TEST_RANDOM
/**
 * Generates one registration key through the test-visible path.
 * @param out Output key buffer.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_generate_key(char *out) {
    return rp2p_generate_key(out);
}

/**
 * Generates one STUN transaction identifier through the test-visible path.
 * @param out Output transaction identifier.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_stun_gen_id(unsigned char out[12]) {
    return rp2p_stun_gen_id(out);
}

/**
 * Generates one stream session identifier through the test-visible path.
 * @param out Output binary identifier.
 * @param hex Output hex identifier.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_stream_make_session_id(
unsigned char out[RP2P_STREAM_SESSION_ID_SZ],
char hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1]
)
{
    return rp2p_stream_make_session_id(out, hex);
}

/**
 * Generates one register challenge nonce through the test-visible path.
 * @param hex Output hex nonce.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_pow_nonce(char hex[17]) {
    unsigned char nonce[8];

    if (rp2p_fill_random(nonce, sizeof(nonce)) != 0) return 0;
    return rp2p_hex_encode(nonce, sizeof(nonce), hex, 17);
}

/**
 * Generates one UDP session identifier through the test-visible path.
 * @param hex Output hex session identifier.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_udp_session_id(char hex[17]) {
    unsigned char session_id[8];

    if (rp2p_fill_random(session_id, sizeof(session_id)) != 0) return 0;
    return rp2p_hex_encode(session_id, sizeof(session_id), hex, 17);
}

/**
 * Compares STUN transaction identifiers through the test-visible path.
 * @param expected Expected transaction identifier.
 * @param actual   Actual transaction identifier.
 * @return 1 when equal, 0 otherwise.
 */
int rp2p_test_stun_id_matches(const unsigned char expected[12],
const unsigned char actual[12])
{
    return memcmp(expected, actual, 12) == 0;
}
#endif
