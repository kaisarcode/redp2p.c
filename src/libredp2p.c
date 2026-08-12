/**
 * libredp2p.c - REDP2P.
 * Summary: Core shared library. TCP rendezvous control and direct peer transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "libredp2p.h"
#include "ikcp.h"
#include "monocypher.h"
#include "parson.h"

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
typedef SOCKET redp2p_fd_t;
#  define REDP2P_FD_INVALID  INVALID_SOCKET
#  define REDP2P_FD_CLOSE(f) closesocket(f)
#  define REDP2P_ISERR(f)    ((f) == INVALID_SOCKET)
#  define REDP2P_LASTERR()   ((int)WSAGetLastError())
#  define REDP2P_EWOULD      WSAEWOULDBLOCK
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
typedef int redp2p_fd_t;
#  define REDP2P_FD_INVALID  (-1)
#  define REDP2P_FD_CLOSE(f) close(f)
#  define REDP2P_ISERR(f)    ((f) < 0)
#  define REDP2P_LASTERR()   errno
#  define REDP2P_EWOULD      EAGAIN
#  define INVALID_SOCKET     (-1)
#  define SOCKET_ERROR       (-1)
#endif

#define REDP2P_SWEEP_MAX   1024
#define REDP2P_POW_MAX      32
#define REDP2P_PORT_MIN      1
#define REDP2P_PORT_MAX      65535

/**
 * Parses one strict unsigned decimal integer.
 * Summary: Rejects NULL, empty, leading/trailing garbage, signs, and overflow.
 * @param text    Input text to parse.
 * @param min     Inclusive lower bound.
 * @param max     Inclusive upper bound.
 * @param out     Output parsed value.
 * @return 1 on valid parse within bounds, 0 otherwise.
 */
static int redp2p_parse_u(const char *text, long min, long max, long *out) {
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
 * Compares two ASCII strings case-insensitively.
 * Summary: Keeps HTTP header-name matching portable across platforms that
 *          do not declare strcasecmp (macOS with strict C, Windows).
 * @param a Left string.
 * @param b Right string.
 * @return 0 when equal ignoring ASCII case, nonzero otherwise.
 */
static int redp2p_ascii_casecmp(const char *a, const char *b) {
    size_t i;

    if (!a || !b) return -1;
    for (i = 0; ; i++) {
        unsigned char ca;
        unsigned char cb;

        ca = (unsigned char)a[i];
        cb = (unsigned char)b[i];
        if (ca >= (unsigned char)'A' && ca <= (unsigned char)'Z')
            ca = (unsigned char)(ca - (unsigned char)'A' + (unsigned char)'a');
        if (cb >= (unsigned char)'A' && cb <= (unsigned char)'Z')
            cb = (unsigned char)(cb - (unsigned char)'A' + (unsigned char)'a');
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == '\0') return 0;
    }
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
static int redp2p_parse_env(const char *text, long min, long max, long *out) {
    if (!text || text[0] == '\0') return 0;
    return redp2p_parse_u(text, min, max, out);
}

/**
 * Parses one strict unsigned decimal size value.
 * @param text Input text to parse.
 * @param out Output parsed value.
 * @return 1 on success, 0 on invalid input or overflow.
 */
static int redp2p_parse_size(const char *text, size_t *out) {
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

#define REDP2P_ETIMEOUT_SEC     120
#define REDP2P_DISCONNECT_S     10
#define REDP2P_KEEPALIVE_S       3
#define REDP2P_PUNCH_ATTEMPTS   10
#define REDP2P_PUNCH_INTERVAL_MS 200
#define REDP2P_CANDIDATES_MAX       16
#define REDP2P_MAX_PENDING_CALLS     32
#define REDP2P_MAX_PENDING_ANSWERS   32
#define REDP2P_PENDING_CALL_TTL_S    30
#define REDP2P_PENDING_ANSWER_TTL_S  30
#define REDP2P_POW_CHALLENGES_MAX   256
#define REDP2P_POW_CHALLENGE_TTL_S   120
#define REDP2P_PRUNE_INTERVAL_S      60
#define REDP2P_MAX_CONNECTIONS      128
#define REDP2P_STREAM_MAGIC             0x50434b52u
#define REDP2P_STREAM_VERSION           2u
#define REDP2P_STREAM_SESSION_ID_SZ     16
#define REDP2P_STREAM_ENVELOPE_SZ       24
#define REDP2P_STREAM_KCP_MTU           1400
#define REDP2P_STREAM_MAX_FRAME         (REDP2P_STREAM_ENVELOPE_SZ + REDP2P_STREAM_KCP_MTU)
#define REDP2P_STREAM_SEND_WINDOW       64
#define REDP2P_STREAM_RECV_WINDOW       128
#define REDP2P_STREAM_KCP_INTERVAL_MS   20
#define REDP2P_STREAM_KCP_FAST_RESEND   2
#define REDP2P_STREAM_MAX_WAIT_SEND     128
#define REDP2P_STREAM_HELLO_MS          500
#define REDP2P_STREAM_CLOSE_MS          500
#define REDP2P_LINK_MTU                 1500
#define REDP2P_IPV4_UDP_OVERHEAD        (20 + 8)
#define REDP2P_IPV6_UDP_OVERHEAD        (40 + 8)
#define REDP2P_IPV4_LOOPBACK             0x7f000001u
#define REDP2P_MAX_DATAGRAM_V4          (REDP2P_LINK_MTU - REDP2P_IPV4_UDP_OVERHEAD)
#define REDP2P_MAX_DATAGRAM_V6          (REDP2P_LINK_MTU - REDP2P_IPV6_UDP_OVERHEAD)
#define REDP2P_PUNCH_DIRECT_ROUNDS 3
#define REDP2P_PUNCH_DIRECT_WAIT_MS 500
#define REDP2P_PUNCH_SWEEP_WAIT_MS 20
#define REDP2P_PUNCH_TOTAL_MS 4000
#define REDP2P_PUNCH_POLL_MS 500
#define REDP2P_CTRL_LINE_MAX     1024
#define REDP2P_CTRL_FIELD_MAX     256
#define REDP2P_CTRL_SESSION_MAX    63
#define REDP2P_HTTP_LINE_MAX      256
#define REDP2P_HTTP_HEADERS_MAX    32
#define REDP2P_HTTP_BODY_MAX     REDP2P_BUF
#define REDP2P_HTTP_TIMEOUT_S       5
#define REDP2P_HTTP_BUF_MAX (REDP2P_HTTP_LINE_MAX * REDP2P_HTTP_HEADERS_MAX + \
    REDP2P_HTTP_BODY_MAX + 128)
#define REDP2P_CTRTOK_HELLO        "REDP2P_CTRTOK_HELLO REDP2P/1"
#define REDP2P_CTRTOK_HELLO_OK     "REDP2P_CTRTOK_HELLO_OK"
#define REDP2P_CTRTOK_ERROR_VERSION_MISMATCH "REDP2P_CTRTOK_ERROR:version mismatch"

#define REDP2P_CTRTOK_REGISTER     "REDP2P_CTRTOK_REGISTER:"
#define REDP2P_CTRTOK_DEREGISTER   "REDP2P_CTRTOK_DEREGISTER:"
#define REDP2P_CTRTOK_LOOKUP       "REDP2P_CTRTOK_LOOKUP:"
#define REDP2P_CTRTOK_LIST_PUBLISHERS "REDP2P_CTRTOK_LIST_PUBLISHERS"
#define REDP2P_CTRTOK_PUBLISHER    "REDP2P_CTRTOK_PUBLISHER:"
#define REDP2P_CTRTOK_END          "REDP2P_CTRTOK_END"
#define REDP2P_CTRTOK_CHALLENGE    "REDP2P_CTRTOK_CHALLENGE:"
#define REDP2P_CTRTOK_OK           "REDP2P_CTRTOK_OK"
#define REDP2P_CTRTOK_OK_KEY       "REDP2P_CTRTOK_OK:REDP2P_CTRTOK_KEY:"
#define REDP2P_CTRTOK_SOLUTION     "REDP2P_CTRTOK_SOLUTION:"
#define REDP2P_CTRTOK_PROOF        "REDP2P_CTRTOK_PROOF:"
#define REDP2P_CTRTOK_KEY          "REDP2P_CTRTOK_KEY:"
#define REDP2P_CTRTOK_AUTH_FAILED  "REDP2P_CTRTOK_AUTH_FAILED"
#define REDP2P_CTRTOK_NOT_FOUND    "REDP2P_CTRTOK_NOT_FOUND"
#define REDP2P_CTRTOK_PUNCH_REQ2   "REDP2P_CTRTOK_PUNCH_REQ2:"
#define REDP2P_CTRTOK_PUNCH_ACK2   "REDP2P_CTRTOK_PUNCH_ACK2:"
#define REDP2P_CTRTOK_PUNCH_CALL2  "REDP2P_CTRTOK_PUNCH_CALL2:"
#define REDP2P_CTRTOK_PUNCH_OK2    "REDP2P_CTRTOK_PUNCH_OK2:"
#define REDP2P_CTRTOK_CAND         "REDP2P_CTRTOK_CAND:"
#define REDP2P_CTRTOK_PUNCH        "REDP2P_CTRTOK_PUNCH:"
#define REDP2P_CTRTOK_PUNCH_SERVER "REDP2P_CTRTOK_PUNCH:server"
#define REDP2P_CTRTOK_PUNCH_PING   "REDP2P_CTRTOK_PUNCH_PING:"
#define REDP2P_CTRTOK_PUNCH_PONG   "REDP2P_CTRTOK_PUNCH_PONG:"
#define REDP2P_CTRTOK_KA           "REDP2P_CTRTOK_KA:"

#define REDP2P_CTRCMD_REGISTER     "REDP2P_CTRTOK_REGISTER"
#define REDP2P_CTRCMD_DEREGISTER   "REDP2P_CTRTOK_DEREGISTER"
#define REDP2P_CTRCMD_LOOKUP       "REDP2P_CTRTOK_LOOKUP"
#define REDP2P_CTRCMD_LIST_PUBLISHERS "REDP2P_CTRTOK_LIST_PUBLISHERS"
#define REDP2P_CTRCMD_PUNCH_REQ2   "REDP2P_CTRTOK_PUNCH_REQ2"
#define REDP2P_CTRCMD_PUNCH_ACK2   "REDP2P_CTRTOK_PUNCH_ACK2"
#define REDP2P_CTRCMD_CALL         "REDP2P_CTRTOK_CALL"
#define REDP2P_CTRCMD_COLLECT      "REDP2P_CTRTOK_COLLECT"
#define REDP2P_CTRCMD_ANSWER       "REDP2P_CTRTOK_ANSWER"
#define REDP2P_CTRCMD_POLL         "REDP2P_CTRTOK_POLL"

#define REDP2P_CTRTOK_ERROR_MALFORMED "REDP2P_CTRTOK_ERROR:malformed"
#define REDP2P_CTRTOK_ERROR_INVALID_ID "REDP2P_CTRTOK_ERROR:invalid id"
#define REDP2P_CTRTOK_ERROR_PEER_TABLE_FULL "REDP2P_CTRTOK_ERROR:peer table full"
#define REDP2P_CTRTOK_ERROR_NOT_REGISTERED "REDP2P_CTRTOK_ERROR:not registered"
#define REDP2P_CTRTOK_ERROR_BUSY "REDP2P_CTRTOK_ERROR:busy"
#define REDP2P_CTRTOK_ERROR_RANDOM "REDP2P_CTRTOK_ERROR:random"
#define REDP2P_CTRTOK_ERROR_OFFLINE "REDP2P_CTRTOK_ERROR:offline"
#define REDP2P_CTRTOK_ERROR_INVALID_KEY "REDP2P_CTRTOK_ERROR:invalid key"
#define REDP2P_CTRTOK_ERROR_UNKNOWN_COMMAND "REDP2P_CTRTOK_ERROR:unknown command"
#define REDP2P_CTRTOK_ERROR_TARGET_OFFLINE "REDP2P_CTRTOK_ERROR:target offline"

#define REDP2P_CTRTOK_CALL      "REDP2P_CTRTOK_CALL:"
#define REDP2P_CTRTOK_COLLECT   "REDP2P_CTRTOK_COLLECT:"
#define REDP2P_CTRTOK_ANSWER    "REDP2P_CTRTOK_ANSWER:"
#define REDP2P_CTRTOK_POLL      "REDP2P_CTRTOK_POLL:"
#define REDP2P_CTRTOK_CALL2     "REDP2P_CTRTOK_CALL2:"
#define REDP2P_CTRTOK_ANSWER2   "REDP2P_CTRTOK_ANSWER2:"
#define REDP2P_CTRTOK_CALL_OK   "REDP2P_CTRTOK_CALL_OK"
#define REDP2P_CTRTOK_ANSWER_OK "REDP2P_CTRTOK_ANSWER_OK"
#define REDP2P_CTRTOK_NONE      "REDP2P_CTRTOK_NONE"

#define REDP2P_STREAM_TYPE_HELLO      1u
#define REDP2P_STREAM_TYPE_HELLO_ACK  2u
#define REDP2P_STREAM_TYPE_KCP        3u
#define REDP2P_STREAM_TYPE_CLOSE      4u
#define REDP2P_STREAM_TYPE_CLOSE_ACK  5u
#define REDP2P_STREAM_TYPE_RESET      6u
#define REDP2P_STREAM_TYPE_KEEPALIVE  7u
#define REDP2P_STREAM_ROLE_INITIATOR 1u
#define REDP2P_STREAM_ROLE_RESPONDER 2u

typedef struct {
    uint8_t type;
    uint8_t role;
    uint8_t protocol;
    unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ];
    const unsigned char *payload;
    size_t payload_len;
} redp2p_stream_envelope_t;

typedef struct {
    redp2p_t *ctx;
    redp2p_fd_t fd;
    struct sockaddr_storage peer_addr;
    unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ];
    uint8_t role;
    uint8_t protocol;
    int send_error;
    int fault_pending_used;
    size_t fault_pending_len;
    unsigned char fault_pending[REDP2P_STREAM_MAX_FRAME];
} redp2p_stream_adapter_t;

#ifndef REDP2P_BUILD_VERSION
#define REDP2P_BUILD_VERSION 0
#endif

_Static_assert(REDP2P_STREAM_MAX_FRAME <= REDP2P_MAX_DATAGRAM_V4,
    "Stream frame exceeds IPv4 datagram limit");
_Static_assert(REDP2P_STREAM_MAX_FRAME <= REDP2P_MAX_DATAGRAM_V6,
    "Stream frame exceeds IPv6 datagram limit");

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t redp2p_version(void) {
    return (uint64_t)REDP2P_BUILD_VERSION;
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
    unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ];
    char session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    uint8_t transport_protocol;
    ikcpcb *kcp;
    redp2p_stream_adapter_t *adapter;
    uint64_t last_tx_ms;
    uint64_t last_hello_ms;
    uint64_t last_close_ms;
    uint64_t last_keepalive_ms;
    uint32_t next_update_ms;
} redp2p_stream_state_t;

#ifdef _WIN32
static SRWLOCK g_key_mutex = SRWLOCK_INIT;
#else
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static int redp2p_is_stop_requested(redp2p_t *ctx);
static int redp2p_fdset_add(redp2p_fd_t fd, fd_set *set, int *maxfd);
static void redp2p_set_error(redp2p_t *ctx, const char *fmt, ...);
static int redp2p_sockaddr_equal(const struct sockaddr_storage *a,
    const struct sockaddr_storage *b);
static int redp2p_sendto_addr(redp2p_fd_t fd, const void *buf, size_t len,
    const struct sockaddr_storage *addr);

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buf[64];
} redp2p_sha256_t;

static const uint32_t redp2p_sha256_k[64] = {
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

#define REDP2P_SHA256_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define REDP2P_SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define REDP2P_SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define REDP2P_SHA256_S0(x) (REDP2P_SHA256_ROR(x, 2) ^ REDP2P_SHA256_ROR(x, 13) ^ REDP2P_SHA256_ROR(x, 22))
#define REDP2P_SHA256_S1(x) (REDP2P_SHA256_ROR(x, 6) ^ REDP2P_SHA256_ROR(x, 11) ^ REDP2P_SHA256_ROR(x, 25))
#define REDP2P_SHA256_s0(x) (REDP2P_SHA256_ROR(x, 7) ^ REDP2P_SHA256_ROR(x, 18) ^ ((x) >> 3))
#define REDP2P_SHA256_s1(x) (REDP2P_SHA256_ROR(x, 17) ^ REDP2P_SHA256_ROR(x, 19) ^ ((x) >> 10))

/**
 * Sha256 transform.
 * @return Status code.
 */
static void redp2p_sha256_transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int t;
    for (t = 0; t < 16; t++)
        W[t] = ((uint32_t)block[t*4]) << 24 |
            ((uint32_t)block[t*4+1]) << 16 |
            ((uint32_t)block[t*4+2]) << 8 |
            block[t*4+3];
    for (t = 16; t < 64; t++)
        W[t] = REDP2P_SHA256_s1(W[t-2]) + W[t-7] + REDP2P_SHA256_s0(W[t-15]) + W[t-16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (t = 0; t < 64; t++) {
        T1 = h + REDP2P_SHA256_S1(e) + REDP2P_SHA256_CH(e, f, g) + redp2p_sha256_k[t] + W[t];
        T2 = REDP2P_SHA256_S0(a) + REDP2P_SHA256_MAJ(a, b, c);
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
static void redp2p_sha256_init(redp2p_sha256_t *ctx) {
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
static void redp2p_sha256_update(redp2p_sha256_t *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count & 63] = data[i];
        ctx->count++;
        if ((ctx->count & 63) == 0)
            redp2p_sha256_transform(ctx->state, ctx->buf);
    }
}

/**
 * Sha256 final.
 * @return Status code.
 */
static void redp2p_sha256_final(redp2p_sha256_t *ctx, unsigned char hash[32]) {
    uint64_t bits = ctx->count * 8;
    int idx = (int)(ctx->count & 63);
    int i;

    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buf[idx++] = 0;
        redp2p_sha256_transform(ctx->state, ctx->buf);
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
    redp2p_sha256_transform(ctx->state, ctx->buf);
    for (i = 0; i < 8; i++) {
        hash[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (unsigned char)ctx->state[i];
    }
}

/**
 * Computes one HMAC-SHA256 digest.
 * @param key     Shared password material.
 * @param msg     Input message bytes.
 * @param msg_len Input message length.
 * @param hash    Output digest buffer.
 * @return None.
 */
static void redp2p_hmac_sha256(const char *key, const unsigned char *msg,
    size_t msg_len, unsigned char hash[32])
{
    redp2p_sha256_t ctx;
    unsigned char key_block[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[32];
    size_t key_len;
    size_t i;

    memset(key_block, 0, sizeof(key_block));
    key_len = key ? strlen(key) : 0;
    if (key_len > sizeof(key_block)) {
        redp2p_sha256_init(&ctx);
        redp2p_sha256_update(&ctx, (const unsigned char *)key, key_len);
        redp2p_sha256_final(&ctx, key_block);
    } else if (key_len > 0) {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < sizeof(key_block); i++) {
        ipad[i] = (unsigned char)(key_block[i] ^ 0x36);
        opad[i] = (unsigned char)(key_block[i] ^ 0x5c);
    }
    redp2p_sha256_init(&ctx);
    redp2p_sha256_update(&ctx, ipad, sizeof(ipad));
    redp2p_sha256_update(&ctx, msg, msg_len);
    redp2p_sha256_final(&ctx, inner);
    redp2p_sha256_init(&ctx);
    redp2p_sha256_update(&ctx, opad, sizeof(opad));
    redp2p_sha256_update(&ctx, inner, sizeof(inner));
    redp2p_sha256_final(&ctx, hash);
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
static void redp2p_hash_register_once(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, unsigned char hash[32])
{
    unsigned char msg[REDP2P_ID_MAX + 33];
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
    redp2p_hmac_sha256(pass ? pass : "", msg, pos, hash);
}

/**
 * Encodes a digest as lowercase hex.
 * @param hash     Input digest bytes.
 * @param hash_len Digest length in bytes.
 * @param out      Output hex buffer.
 * @param out_cap  Output buffer capacity.
 * @return 1 on success, 0 on failure.
 */
static int redp2p_hex_encode(const unsigned char *hash, size_t hash_len,
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
static int redp2p_count_leading_zero_bits(const unsigned char hash[32]);

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
static int redp2p_solve_register_pow(redp2p_t *ctx, const char *pass, const char *nonce_hex,
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
        redp2p_hash_register_once(pass, nonce_hex, id, buf, hash);
        if (redp2p_count_leading_zero_bits(hash) >= bits) {
            memcpy(solution_hex, buf, sizeof(buf));
            return redp2p_hex_encode(hash, sizeof(hash), proof_hex, proof_cap);
        }
        counter++;
        if (counter == 0) break;
        if ((counter & 0xfffff) == 0 && redp2p_is_stop_requested(ctx)) break;
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
static int redp2p_verify_register_pow(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, const char *proof_hex, int bits)
{
    unsigned char hash[32];
    char expected[65];
    int diff, k;

    if (!proof_hex || strlen(proof_hex) != 64) return 0;
    redp2p_hash_register_once(pass, nonce_hex, id, solution_hex, hash);
    if (!redp2p_hex_encode(hash, sizeof(hash), expected, sizeof(expected))) return 0;
    diff = 0;
    for (k = 0; k < 64; k++)
        diff |= (proof_hex[k] ^ expected[k]);
    if (diff != 0) return 0;
    return redp2p_count_leading_zero_bits(hash) >= bits;
}

/**
 * Counts leading zero bits in one digest.
 * @param hash Input digest bytes.
 * @return Count of leading zero bits.
 */
static int redp2p_count_leading_zero_bits(const unsigned char hash[32]) {
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
    char id[REDP2P_ID_MAX + 1];
    char pass[REDP2P_PASS_MAX + 1];
} redp2p_vip_entry_t;

/**
 * Pending call.
 * Summary: Stores one request-driven punch introduction awaiting pickup.
 */
typedef struct {
    char caller_id[REDP2P_ID_MAX + 1];
    char target_id[REDP2P_ID_MAX + 1];
    char sess_id[REDP2P_CTRL_SESSION_MAX + 1];
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    int n_candidates;
    uint64_t ts;
} redp2p_pending_call_t;

/**
 * Stores one in-flight index HTTP connection and its partial request buffer.
 */
typedef struct {
    redp2p_fd_t fd;
    char buf[REDP2P_HTTP_BUF_MAX + 1];
    int buf_len;
    uint64_t ts;
} redp2p_index_conn_t;

struct redp2p {
    redp2p_peer_t *peers;
    size_t n_peers;
    size_t peers_alloc;
    size_t n_peers_cap;
    size_t nonvip_cap;
    int seats_set;
    redp2p_vip_entry_t *vips;
    size_t n_vips;
    size_t vips_cap;
    redp2p_index_conn_t *conns;
    int n_conns;
    int conns_cap;
    char key[REDP2P_KEY_STR_SZ];
    char pass[REDP2P_PASS_MAX + 1];
    int pow_bits;
    unsigned short bind_port;
    int explicit_port;
    int proto;
    int sweep;
#ifdef _WIN32
    CRITICAL_SECTION mutex;
#else
    pthread_mutex_t mutex;
#endif
    char stun_url[512];
    char err_buf[256];
    int fault_drop_counter;
    int fault_reorder_counter;
    unsigned long prune_interval_s;
    unsigned long etimeout_sec;
    unsigned long heartbeat_s;
    unsigned long punch_poll_ms;
    redp2p_pending_call_t pending_calls[REDP2P_MAX_PENDING_CALLS];
    int n_pending_calls;
    _Atomic int stop_requested;
};

/**
 * Returns whether one context requested stop.
 * @param ctx Context to inspect.
 * @return 1 when stop was requested, 0 otherwise.
 */
static int redp2p_is_stop_requested(redp2p_t *ctx) {
    return ctx && atomic_load(&ctx->stop_requested);
}

typedef struct redp2p_udp_consumer_session {
    redp2p_fd_t fd;
    redp2p_fd_t tcp_fd;
    struct sockaddr_storage client_addr;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    redp2p_stream_state_t stream;
} redp2p_udp_consumer_session_t;

typedef struct {
    redp2p_t *ctx;
    const char *index_host;
    const char *self_id;
    const char *target_id;
    const char *udp_any_host;
    unsigned short index_port;
    redp2p_fd_t local_fd;
    redp2p_fd_t tcp_listen_fd;
    redp2p_udp_consumer_session_t *sessions;
    int n_sessions;
    int cap_sessions;
    int platform_initialized;
    redp2p_candidate_t peer_candidates[REDP2P_PEER_CANDIDATES_MAX];
    int n_peer_candidates;
} redp2p_consumer_runtime_t;

typedef struct redp2p_udp_server_session {
    redp2p_fd_t backend_fd;
    redp2p_fd_t tcp_fd;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    redp2p_stream_state_t stream;
} redp2p_udp_server_session_t;

typedef struct {
    redp2p_t *borrowed_ctx;
    const char *borrowed_index_host;
    const char *borrowed_self_id;
    const char *borrowed_udp_any_host;
    unsigned short index_port;
    redp2p_fd_t owned_udp_fd;
    redp2p_udp_server_session_t *owned_sessions;
    int session_count;
    int session_capacity;
    uint64_t last_heartbeat;
    uint64_t last_punch_poll;
} redp2p_publisher_runtime_t;

#ifdef _WIN32
typedef HANDLE redp2p_thread_t;
#define REDP2P_THREAD_RET unsigned __stdcall
#else
typedef pthread_t redp2p_thread_t;
#define REDP2P_THREAD_RET void *
#endif

static int redp2p_sock_read(redp2p_fd_t fd, char *buf, int len);
static int redp2p_write_all(redp2p_fd_t fd, const char *buf, int len);
static void redp2p_shutdown_write(redp2p_fd_t fd);
static socklen_t redp2p_sockaddr_len(const struct sockaddr_storage *addr);
static int redp2p_candidate_sockaddr(const redp2p_candidate_t *candidate,
    struct sockaddr_storage *out);
static int redp2p_is_space(char ch);
static char *redp2p_trim(char *text);
static size_t redp2p_find_vip(redp2p_t *ctx, const char *id);
static int redp2p_add_vip(redp2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap);
static const char *redp2p_get_register_pass(redp2p_t *ctx, const char *id);
static uint32_t redp2p_load_u32_le(const unsigned char *p);

/**
 * Reports whether detailed stream logs are enabled.
 * @return 1 when stream debug logging is enabled, 0 otherwise.
 */
static int redp2p_stream_debug_enabled(void) {
    const char *env;

    env = getenv("REDP2P_DEBUG_STREAM");
    return env && env[0] != '\0' && strcmp(env, "0") != 0;
}

/**
 * Emits one conditional debug log line for stream internals.
 * @return None.
 */
static void redp2p_stream_log(const char *fmt, ...) {
    va_list ap;

    if (!redp2p_stream_debug_enabled()) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/**
 * Returns the configured debug drop cadence for KCP datagrams.
 * @return Drop cadence, or 0 when disabled.
 */
static int redp2p_stream_debug_drop_every(void) {
    const char *env;
    long every;

    env = getenv("REDP2P_DEBUG_STREAM_DROP_EVERY");
    if (!redp2p_parse_u(env, 1, 1000000, &every)) return 0;
    return (int)every;
}

/**
 * Returns the configured debug reorder cadence for KCP datagrams.
 * @return Reorder cadence, or 0 when disabled.
 */
static int redp2p_stream_debug_reorder_every(void) {
    const char *env;
    long every;

    env = getenv("REDP2P_DEBUG_STREAM_REORDER_EVERY");
    if (!redp2p_parse_u(env, 1, 1000000, &every)) return 0;
    return (int)every;
}

/**
 * Decides whether to drop one complete outgoing KCP datagram for testing.
 * @param ctx Context containing the fault counter.
 * @return 1 when the datagram should be dropped, 0 otherwise.
 */
static int redp2p_stream_should_drop(redp2p_t *ctx) {
    int every;

    every = redp2p_stream_debug_drop_every();
    if (every <= 0) return 0;
    ctx->fault_drop_counter++;
    return (ctx->fault_drop_counter % every) == 0;
}

/**
 * Decides whether to delay one complete KCP datagram for reordering tests.
 * @param ctx Context containing the fault counter.
 * @return 1 when the datagram should be delayed, 0 otherwise.
 */
static int redp2p_stream_should_reorder(redp2p_t *ctx) {
    int every;

    every = redp2p_stream_debug_reorder_every();
    if (every <= 0) return 0;
    ctx->fault_reorder_counter++;
    return (ctx->fault_reorder_counter % every) == 0;
}

/**
 * Lock.
 * @return Status code.
 */
static void redp2p_lock(redp2p_t *ctx) {
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
static void redp2p_unlock(redp2p_t *ctx) {
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
static uint32_t redp2p_load_u32_le(const unsigned char *p) {
    return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) |
        ((uint32_t)p[3] << 24);
}

/**
 * Stores one little-endian u32.
 * @return None.
 */
static void redp2p_store_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/**
 * Returns a millisecond timestamp.
 * @return Monotonic-ish timestamp in milliseconds.
 */
static uint64_t redp2p_now_ms(void) {
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
static uint64_t redp2p_now_s(void) {
    return redp2p_now_ms() / 1000;
}

#ifdef REDP2P_TEST_RANDOM
static unsigned char redp2p_test_random_bytes[256];
static size_t redp2p_test_random_len;
static size_t redp2p_test_random_pos;
static int redp2p_test_random_fail;
#endif

/**
 * Fills a buffer with secure random bytes.
 * @return 0 on success, -1 on error.
 */
static int redp2p_fill_random(unsigned char *buf, size_t len) {
#ifdef REDP2P_TEST_RANDOM
    if (redp2p_test_random_fail) return -1;
    if (redp2p_test_random_len > 0) {
        size_t i;
        for (i = 0; i < len; i++) {
            buf[i] = redp2p_test_random_bytes[redp2p_test_random_pos %
                redp2p_test_random_len];
            redp2p_test_random_pos++;
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

#ifdef REDP2P_TEST_RANDOM
/**
 * Configures deterministic random bytes for test builds.
 * @param bytes Byte stream to repeat.
 * @param len   Byte stream length.
 * @return None.
 */
void redp2p_test_random_set(const unsigned char *bytes, size_t len) {
    if (!bytes || len == 0) {
        redp2p_test_random_len = 0;
        redp2p_test_random_pos = 0;
        return;
    }
    if (len > sizeof(redp2p_test_random_bytes))
        len = sizeof(redp2p_test_random_bytes);
    memcpy(redp2p_test_random_bytes, bytes, len);
    redp2p_test_random_len = len;
    redp2p_test_random_pos = 0;
    redp2p_test_random_fail = 0;
}

/**
 * Configures random-source failure for test builds.
 * @param fail Non-zero forces failure.
 * @return None.
 */
void redp2p_test_random_set_fail(int fail) {
    redp2p_test_random_fail = fail ? 1 : 0;
}
#endif

/**
 * Decodes one hex nibble.
 * @return Nibble value, or -1 on error.
 */
static int redp2p_hex_decode_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Decodes a fixed-size hex string.
 * @return 1 on success, 0 on error.
 */
static int redp2p_hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;

    if (!hex || !out) return 0;
    for (i = 0; i < out_len; i++) {
        int hi = redp2p_hex_decode_nibble(hex[i * 2]);
        int lo = redp2p_hex_decode_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/**
 * Generates one secure stream session identifier.
 * @return 1 on success, 0 on error.
 */
static int redp2p_stream_make_session_id(unsigned char out[REDP2P_STREAM_SESSION_ID_SZ],
    char hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1])
{
    if (redp2p_fill_random(out, REDP2P_STREAM_SESSION_ID_SZ) != 0) return 0;
    return redp2p_hex_encode(out, REDP2P_STREAM_SESSION_ID_SZ, hex,
        REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
}

/**
 * Encodes one REDP2P TCP envelope around an optional KCP datagram.
 * @return Encoded byte length, or 0 when the payload is too large.
 */
static size_t redp2p_stream_pack(uint8_t type, uint8_t role, uint8_t protocol,
    const unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ],
    const void *payload, size_t payload_len, unsigned char *out)
{
    if (payload_len > REDP2P_STREAM_KCP_MTU) return 0;
    redp2p_store_u32_le(out, REDP2P_STREAM_MAGIC);
    out[4] = REDP2P_STREAM_VERSION;
    out[5] = type;
    out[6] = role;
    out[7] = protocol;
    memcpy(out + 8, session_id, REDP2P_STREAM_SESSION_ID_SZ);
    if (payload_len > 0) memcpy(out + REDP2P_STREAM_ENVELOPE_SZ, payload,
        payload_len);
    return REDP2P_STREAM_ENVELOPE_SZ + payload_len;
}

/**
 * Decodes and validates one REDP2P TCP envelope.
 * @return 1 on success, 0 when the datagram is not a valid envelope.
 */
static int redp2p_stream_unpack(const unsigned char *buf, size_t len,
    redp2p_stream_envelope_t *envelope)
{
    if (!buf || !envelope || len < REDP2P_STREAM_ENVELOPE_SZ ||
        len > REDP2P_STREAM_MAX_FRAME)
        return 0;
    if (redp2p_load_u32_le(buf) != REDP2P_STREAM_MAGIC ||
        buf[4] != REDP2P_STREAM_VERSION ||
        buf[5] < REDP2P_STREAM_TYPE_HELLO ||
        buf[5] > REDP2P_STREAM_TYPE_KEEPALIVE ||
        (buf[6] != REDP2P_STREAM_ROLE_INITIATOR &&
        buf[6] != REDP2P_STREAM_ROLE_RESPONDER) ||
        buf[7] != REDP2P_PROTO_TCP)
        return 0;
    envelope->type = buf[5];
    envelope->role = buf[6];
    envelope->protocol = buf[7];
    memcpy(envelope->session_id, buf + 8, REDP2P_STREAM_SESSION_ID_SZ);
    envelope->payload = buf + REDP2P_STREAM_ENVELOPE_SZ;
    envelope->payload_len = len - REDP2P_STREAM_ENVELOPE_SZ;
    if (envelope->type != REDP2P_STREAM_TYPE_KCP && envelope->payload_len != 0)
        return 0;
    return 1;
}

/**
 * Sends one already encoded stream datagram.
 * @return 0 on success, -1 on socket failure.
 */
static int redp2p_stream_send_datagram(redp2p_stream_adapter_t *adapter,
    const unsigned char *frame, size_t frame_len)
{
    socklen_t peer_len;

    peer_len = redp2p_sockaddr_len(&adapter->peer_addr);
    if (peer_len == 0 || sendto(adapter->fd, (const char *)frame, frame_len, 0,
        (const struct sockaddr *)&adapter->peer_addr, peer_len) < 0)
        return -1;
    return 0;
}

/**
 * Emits one complete KCP datagram through the REDP2P session envelope.
 * @return 0 on success, -1 after a transport failure.
 */
static int redp2p_stream_kcp_output(const char *buf, int len, ikcpcb *kcp,
    void *user)
{
    redp2p_stream_adapter_t *adapter;
    unsigned char frame[REDP2P_STREAM_MAX_FRAME];
    size_t frame_len;

    (void)kcp;
    adapter = (redp2p_stream_adapter_t *)user;
    if (!adapter || len <= 0 || len > REDP2P_STREAM_KCP_MTU) return -1;
    frame_len = redp2p_stream_pack(REDP2P_STREAM_TYPE_KCP, adapter->role,
        adapter->protocol, adapter->session_id, buf, (size_t)len, frame);
    if (frame_len == 0) return -1;
    if (redp2p_stream_should_drop(adapter->ctx)) {
        redp2p_stream_log("redp2p: stream dropped one KCP datagram\n");
        return 0;
    }
    if (!adapter->fault_pending_used &&
        redp2p_stream_should_reorder(adapter->ctx))
    {
        redp2p_stream_log("redp2p: stream delayed one KCP datagram\n");
        memcpy(adapter->fault_pending, frame, frame_len);
        adapter->fault_pending_len = frame_len;
        adapter->fault_pending_used = 1;
        return 0;
    }
    if (redp2p_stream_send_datagram(adapter, frame, frame_len) != 0 ||
        (adapter->fault_pending_used &&
        redp2p_stream_send_datagram(adapter, adapter->fault_pending,
            adapter->fault_pending_len) != 0))
    {
        adapter->send_error = 1;
        return -1;
    }
    adapter->fault_pending_used = 0;
    return 0;
}

/**
 * Derives the session-local KCP routing value from the full REDP2P identifier.
 * @return Deterministic 32-bit KCP conversation value.
 */
static uint32_t redp2p_stream_conv(
    const unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ])
{
    return redp2p_load_u32_le(session_id) ^ redp2p_load_u32_le(session_id + 4) ^
        redp2p_load_u32_le(session_id + 8) ^
        redp2p_load_u32_le(session_id + 12);
}

/**
 * Initializes one conservative stream-mode KCP session and REDP2P adapter.
 * @return 0 on success, -1 on allocation or KCP configuration failure.
 */
static int redp2p_stream_init(redp2p_t *ctx, redp2p_stream_state_t *st,
    int initiator, redp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    const unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ],
    const char *session_hex, uint8_t transport_protocol)
{
    uint64_t now;

    memset(st, 0, sizeof(*st));
    st->adapter = (redp2p_stream_adapter_t *)calloc(1, sizeof(*st->adapter));
    if (!st->adapter) {
        redp2p_set_error(ctx, "stream: KCP adapter allocation failed");
        return -1;
    }
    st->adapter->ctx = ctx;
    st->adapter->fd = fd;
    st->adapter->peer_addr = *peer_addr;
    st->adapter->role = initiator ? REDP2P_STREAM_ROLE_INITIATOR :
        REDP2P_STREAM_ROLE_RESPONDER;
    st->adapter->protocol = transport_protocol;
    memcpy(st->adapter->session_id, session_id, REDP2P_STREAM_SESSION_ID_SZ);
    st->kcp = ikcp_create(redp2p_stream_conv(session_id), st->adapter);
    if (!st->kcp || ikcp_setmtu(st->kcp, REDP2P_STREAM_KCP_MTU) != 0 ||
        ikcp_wndsize(st->kcp, REDP2P_STREAM_SEND_WINDOW,
            REDP2P_STREAM_RECV_WINDOW) != 0 ||
        ikcp_nodelay(st->kcp, 0, REDP2P_STREAM_KCP_INTERVAL_MS,
            REDP2P_STREAM_KCP_FAST_RESEND, 0) != 0)
    {
        if (st->kcp) ikcp_release(st->kcp);
        free(st->adapter);
        memset(st, 0, sizeof(*st));
        redp2p_set_error(ctx, "stream: KCP initialization failed");
        return -1;
    }
    st->kcp->stream = 1;
    ikcp_setoutput(st->kcp, redp2p_stream_kcp_output);
    st->enabled = 1;
    st->initiator = initiator;
    st->transport_protocol = transport_protocol;
    memcpy(st->session_id, session_id, REDP2P_STREAM_SESSION_ID_SZ);
    if (session_hex) memcpy(st->session_hex, session_hex,
        REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
    now = redp2p_now_ms();
    st->last_tx_ms = now;
    st->last_keepalive_ms = now;
    st->next_update_ms = (uint32_t)now;
    return 0;
}

/**
 * Reports whether the local TCP side may queue more bytes in KCP.
 * @return 1 when local TCP reads may continue, 0 otherwise.
 */
static int redp2p_stream_can_send_data(const redp2p_stream_state_t *st) {
    return st->ready && !st->local_eof && st->kcp &&
        ikcp_waitsnd(st->kcp) < REDP2P_STREAM_MAX_WAIT_SEND;
}

/**
 * Sends one REDP2P tunnel control envelope outside KCP.
 * @return 0 on success, -1 on socket failure.
 */
static int redp2p_stream_send_control(redp2p_t *ctx, redp2p_stream_state_t *st,
    uint8_t type)
{
    unsigned char frame[REDP2P_STREAM_ENVELOPE_SZ];
    size_t frame_len;

    frame_len = redp2p_stream_pack(type, st->adapter->role,
        st->transport_protocol, st->session_id, NULL, 0, frame);
    if (frame_len == 0 ||
        redp2p_stream_send_datagram(st->adapter, frame, frame_len) != 0)
    {
        redp2p_set_error(ctx, "stream: UDP control send failed");
        return -1;
    }
    st->last_tx_ms = redp2p_now_ms();
    return 0;
}

/**
 * Notifies an established peer of terminal stream failure once.
 * @return None.
 */
static void redp2p_stream_fail(redp2p_t *ctx, redp2p_stream_state_t *st) {
    if (!st || !st->ready || st->reset_sent || st->reset_received) return;
    st->reset_sent = 1;
    redp2p_stream_send_control(ctx, st, REDP2P_STREAM_TYPE_RESET);
}

/**
 * Drains all currently reconstructed KCP bytes into the local TCP socket.
 * @return 0 on success, -1 on KCP or local socket failure.
 */
static int redp2p_stream_drain(redp2p_t *ctx, redp2p_stream_state_t *st,
    redp2p_fd_t tcp_fd)
{
    unsigned char buf[REDP2P_BUF];
    int available;
    int received;

    for (;;) {
        available = ikcp_peeksize(st->kcp);
        if (available < 0) return 0;
        if (available > (int)sizeof(buf)) {
            redp2p_set_error(ctx, "stream: KCP receive chunk exceeds buffer");
            return -1;
        }
        received = ikcp_recv(st->kcp, (char *)buf, (int)sizeof(buf));
        if (received < 0) {
            redp2p_set_error(ctx, "stream: KCP receive failed");
            return -1;
        }
        if (received > 0 && redp2p_write_all(tcp_fd, (const char *)buf,
            received) != 0)
        {
            redp2p_set_error(ctx, "stream: local TCP write failed");
            return -1;
        }
    }
}

/**
 * Dispatches one validated session datagram through handshake or KCP.
 * @return 0 on success, -1 on protocol, transport, or local socket failure.
 */
static int redp2p_stream_process_packet(redp2p_t *ctx,
    redp2p_stream_state_t *st, redp2p_fd_t tcp_fd,
    const unsigned char *buf, size_t len)
{
    redp2p_stream_envelope_t envelope;
    uint8_t expected_role;
    int input_result;

    if (!redp2p_stream_unpack(buf, len, &envelope)) return 0;
    expected_role = st->initiator ? REDP2P_STREAM_ROLE_RESPONDER :
        REDP2P_STREAM_ROLE_INITIATOR;
    if (envelope.role != expected_role ||
        envelope.protocol != st->transport_protocol ||
        memcmp(envelope.session_id, st->session_id,
            REDP2P_STREAM_SESSION_ID_SZ) != 0)
        return 0;
    if (envelope.type == REDP2P_STREAM_TYPE_HELLO && !st->initiator) {
        if (redp2p_stream_send_control(ctx, st,
            REDP2P_STREAM_TYPE_HELLO_ACK) != 0)
            return -1;
        st->ready = 1;
        redp2p_stream_log("redp2p: tcp session %s KCP ready\n",
            st->session_hex);
        return 0;
    }
    if (envelope.type == REDP2P_STREAM_TYPE_HELLO_ACK && st->initiator) {
        st->ready = 1;
        redp2p_stream_log("redp2p: tcp session %s KCP ready\n",
            st->session_hex);
        return 0;
    }
    if (!st->ready) return 0;
    if (envelope.type == REDP2P_STREAM_TYPE_KCP) {
        input_result = ikcp_input(st->kcp, (const char *)envelope.payload,
            (long)envelope.payload_len);
        if (input_result != 0) {
            redp2p_set_error(ctx, "stream: KCP input failed (%d)", input_result);
            return -1;
        }
        st->next_update_ms = (uint32_t)redp2p_now_ms();
        return redp2p_stream_drain(ctx, st, tcp_fd);
    }
    if (envelope.type == REDP2P_STREAM_TYPE_CLOSE) {
        if (redp2p_stream_drain(ctx, st, tcp_fd) != 0) return -1;
        if (!st->remote_close) redp2p_shutdown_write(tcp_fd);
        st->remote_close = 1;
        return redp2p_stream_send_control(ctx, st,
            REDP2P_STREAM_TYPE_CLOSE_ACK);
    }
    if (envelope.type == REDP2P_STREAM_TYPE_CLOSE_ACK) {
        st->close_acked = 1;
        return 0;
    }
    if (envelope.type == REDP2P_STREAM_TYPE_RESET) {
        st->reset_received = 1;
        redp2p_set_error(ctx, "stream: peer reset");
        return -1;
    }
    return 0;
}

/**
 * Reads one local TCP chunk and queues its bytes in KCP stream mode.
 * @return 0 on success, -1 on local socket or KCP failure.
 */
static int redp2p_stream_pump_tcp(redp2p_t *ctx,
    redp2p_stream_state_t *st, redp2p_fd_t tcp_fd)
{
    unsigned char buf[REDP2P_BUF];
    int n;
    int sent;

    if (!redp2p_stream_can_send_data(st)) return 0;
    n = redp2p_sock_read(tcp_fd, (char *)buf, (int)sizeof(buf));
    if (n < 0) {
        if (REDP2P_LASTERR() == REDP2P_EWOULD) return 0;
        redp2p_set_error(ctx, "stream: local TCP read failed");
        return -1;
    }
    if (n == 0) {
        st->local_eof = 1;
        return 0;
    }
    sent = ikcp_send(st->kcp, (const char *)buf, n);
    if (sent != n) {
        redp2p_set_error(ctx, "stream: KCP send failed");
        return -1;
    }
    st->next_update_ms = (uint32_t)redp2p_now_ms();
    return 0;
}

/**
 * Advances one KCP session and REDP2P tunnel lifecycle when due.
 * @return 0 on success, -1 on transport failure.
 */
static int redp2p_stream_tick(redp2p_t *ctx, redp2p_stream_state_t *st)
{
    uint64_t now;
    uint32_t current;

    if (!st->enabled) return 0;
    now = redp2p_now_ms();
    current = (uint32_t)now;
    if (st->initiator && !st->ready &&
        (!st->hello_sent || now - st->last_hello_ms >= REDP2P_STREAM_HELLO_MS))
    {
        if (redp2p_stream_send_control(ctx, st,
            REDP2P_STREAM_TYPE_HELLO) != 0)
            return -1;
        st->hello_sent = 1;
        st->last_hello_ms = now;
    }
    if (st->ready && (int32_t)(current - st->next_update_ms) >= 0) {
        ikcp_update(st->kcp, current);
        st->next_update_ms = ikcp_check(st->kcp, current);
    }
    if (st->adapter->send_error) {
        redp2p_set_error(ctx, "stream: KCP UDP output failed");
        return -1;
    }
    if (st->ready && st->local_eof && !st->close_acked &&
        ikcp_waitsnd(st->kcp) == 0 &&
        (!st->close_sent || now - st->last_close_ms >= REDP2P_STREAM_CLOSE_MS))
    {
        if (redp2p_stream_send_control(ctx, st, REDP2P_STREAM_TYPE_CLOSE) != 0)
            return -1;
        st->close_sent = 1;
        st->last_close_ms = now;
    }
    if (st->ready && now - st->last_keepalive_ms >=
        (uint64_t)REDP2P_KEEPALIVE_S * 1000u)
    {
        if (redp2p_stream_send_control(ctx, st,
            REDP2P_STREAM_TYPE_KEEPALIVE) != 0)
            return -1;
        st->last_keepalive_ms = now;
    }
    return 0;
}

/**
 * Returns the next KCP update delay for select scheduling.
 * @return Milliseconds until work is due, capped at one second.
 */
static uint32_t redp2p_stream_wait_ms(const redp2p_stream_state_t *st,
    uint64_t now)
{
    uint32_t current;
    int32_t difference;

    if (!st || !st->enabled) return 1000;
    if (!st->ready) {
        if (!st->initiator) return 1000;
        if (!st->hello_sent ||
            now - st->last_hello_ms >= REDP2P_STREAM_HELLO_MS)
            return 0;
        return (uint32_t)(REDP2P_STREAM_HELLO_MS -
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
static int redp2p_stream_is_done(const redp2p_stream_state_t *st) {
    return st->local_eof && st->close_acked && st->remote_close && st->kcp &&
        ikcp_waitsnd(st->kcp) == 0;
}

/**
 * Releases KCP and wipes all per-session stream material.
 * @return None.
 */
static void redp2p_stream_wipe(redp2p_stream_state_t *st) {
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
static void redp2p_server_session_close(redp2p_udp_server_session_t *sess) {
    if (!sess) return;
    if (sess->backend_fd != REDP2P_FD_INVALID) {
        REDP2P_FD_CLOSE(sess->backend_fd);
        sess->backend_fd = REDP2P_FD_INVALID;
    }
    if (sess->tcp_fd != REDP2P_FD_INVALID) {
        REDP2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = REDP2P_FD_INVALID;
    }
    if (sess->is_tcp) redp2p_stream_wipe(&sess->stream);
    sess->active = 0;
}

/**
 * Closes one consumer-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void redp2p_consumer_session_close(redp2p_udp_consumer_session_t *sess) {
    if (!sess) return;
    if (sess->tcp_fd != REDP2P_FD_INVALID) {
        REDP2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = REDP2P_FD_INVALID;
    }
    if (!REDP2P_ISERR(sess->fd)) {
        REDP2P_FD_CLOSE(sess->fd);
        sess->fd = REDP2P_FD_INVALID;
    }
    if (sess->is_tcp) redp2p_stream_wipe(&sess->stream);
    sess->active = 0;
}

#ifdef _WIN32

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int redp2p_platform_init(void) {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0 ? 0 : -1;
}

/**
 * Platform cleanup.
 * @return None.
 */
void redp2p_platform_cleanup(void) { WSACleanup(); }

#else

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int redp2p_platform_init(void) { return 0; }

/**
 * Platform cleanup.
 * @return None.
 */
void redp2p_platform_cleanup(void) {}

#endif

/**
 * Set nonblock.
 * @return 0 on success, -1 on error.
 */
int redp2p_set_nonblock(redp2p_fd_t fd) {
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
int redp2p_set_block(redp2p_fd_t fd) {
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
int redp2p_resolve(
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
static socklen_t redp2p_sockaddr_len(const struct sockaddr_storage *addr) {
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
static unsigned short redp2p_sockaddr_port(
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
static int redp2p_sockaddr_set_port(struct sockaddr_storage *addr,
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
static int redp2p_sockaddr_equal(const struct sockaddr_storage *a,
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
static int redp2p_sendto_addr(redp2p_fd_t fd, const void *buf, size_t len,
    const struct sockaddr_storage *addr)
{
    socklen_t addr_len;

    addr_len = redp2p_sockaddr_len(addr);
    if (addr_len == 0) return -1;
    return (int)sendto(fd, buf, len, 0, (const struct sockaddr *)addr,
        addr_len);
}

/**
 * Reports whether a host string is an IPv6 literal.
 * @param host Host string.
 * @return 1 for IPv6 literals, 0 otherwise.
 */
static int redp2p_host_is_ipv6_literal(const char *host) {
    struct in6_addr addr;

    return host && inet_pton(AF_INET6, host, &addr) == 1;
}

/**
 * Extract addr.
 * @return None.
 */
void redp2p_extract_addr(
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
int redp2p_send_reply(
    redp2p_fd_t fd,
    const struct sockaddr_in *to,
    socklen_t tolen,
    const char *msg)
{
    return sendto(fd, msg, strlen(msg), 0,
        (const struct sockaddr *)to, tolen) > 0
        ? REDP2P_OK : REDP2P_ENET;
}

/**
 * Send recv.
 * @return 0 on success, -1 on error.
 */
int redp2p_send_recv(
    redp2p_fd_t fd,
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

    if (redp2p_resolve(srv_host, srv_port, SOCK_DGRAM, &srv, &srv_len) != 0)
        return REDP2P_ENET;

    if (sendto(fd, send_msg, strlen(send_msg), 0,
        (const struct sockaddr *)&srv, srv_len) < 0)
        return REDP2P_ENET;

    if (!recv_buf || recv_cap == 0) return REDP2P_OK;

    deadline = redp2p_now_ms() + (uint64_t)timeout_sec * 1000u;
    while (redp2p_now_ms() < deadline) {
        uint64_t remaining = deadline - redp2p_now_ms();

        FD_ZERO(&fds);
        if (!redp2p_fdset_add(fd, &fds, NULL)) return REDP2P_ENET;
        tv.tv_sec = (long)(remaining / 1000u);
        tv.tv_usec = (long)((remaining % 1000u) * 1000u);
        n = select((int)(fd + 1), &fds, NULL, NULL, &tv);
        if (n <= 0) return REDP2P_ETIMEOUT;
        srclen = sizeof(from);
        n = (int)recvfrom(fd, recv_buf, (int)(recv_cap - 1), 0,
            (struct sockaddr *)&from, &srclen);
        if (n < 0) return REDP2P_ENET;
        if (!redp2p_sockaddr_equal(&from, &srv)) continue;
        recv_buf[n] = '\0';
        return REDP2P_OK;
    }
    return REDP2P_ETIMEOUT;
}

/**
 * Adds one descriptor to one select set with descriptor-range validation.
 * Summary: Rejects descriptors that cannot be represented by fd_set.
 * @param fd    Descriptor to add.
 * @param set   Select set to update.
 * @param maxfd Current maximum descriptor, updated on success.
 * @return 1 when added, 0 when rejected.
 */
static int redp2p_fdset_add(redp2p_fd_t fd, fd_set *set, int *maxfd) {
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
 * @return Valid descriptor, or REDP2P_FD_INVALID on failure.
 */
redp2p_fd_t redp2p_create_socket(
    const char *bind_host,
    unsigned short bind_port)
{
    redp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    if (redp2p_platform_init() != 0) return REDP2P_FD_INVALID;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)bind_port);
    if (getaddrinfo(bind_host, port_str, &hints, &ai) != 0)
        return REDP2P_FD_INVALID;

    fd = REDP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (REDP2P_ISERR(fd)) continue;
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
        REDP2P_FD_CLOSE(fd);
        fd = REDP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Create tcp listener.
 * @return 0 on success, -1 on error.
 */
static redp2p_fd_t redp2p_create_tcp_listener(
    const char *bind_host,
    unsigned short bind_port)
{
    redp2p_fd_t fd;
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
        return REDP2P_FD_INVALID;
    fd = REDP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (REDP2P_ISERR(fd)) continue;
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
        REDP2P_FD_CLOSE(fd);
        fd = REDP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Connect local tcp.
 * @return 0 on success, -1 on error.
 */
static redp2p_fd_t redp2p_connect_local_tcp(unsigned short port) {
    redp2p_fd_t fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (REDP2P_ISERR(fd)) return REDP2P_FD_INVALID;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        REDP2P_FD_CLOSE(fd);
        return REDP2P_FD_INVALID;
    }
    return fd;
}

/**
 * Sock read.
 * @return 0 on success, -1 on error.
 */
static int redp2p_sock_read(redp2p_fd_t fd, char *buf, int len) {
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
static int redp2p_sock_write(redp2p_fd_t fd, const char *buf, int len) {
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
static int redp2p_write_all(redp2p_fd_t fd, const char *buf, int len) {
    int off;
    int n;

    off = 0;
    while (off < len) {
        n = redp2p_sock_write(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += n;
    }
    return 0;
}

/**
 * Shuts down the local write side of one TCP socket.
 * @return None.
 */
static void redp2p_shutdown_write(redp2p_fd_t fd) {
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
static redp2p_fd_t redp2p_tcp_connect(const char *host, unsigned short port) {
    redp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &ai) != 0)
        return REDP2P_FD_INVALID;
    fd = REDP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (REDP2P_ISERR(fd)) continue;
        if (connect(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0)
            break;
        REDP2P_FD_CLOSE(fd);
        fd = REDP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Reports whether raw control bytes are safe for C-string parsing.
 * @param data Raw control bytes.
 * @param len  Byte count.
 * @return 1 when safe, 0 when a prohibited control byte is present.
 */
static int redp2p_control_bytes_valid(const char *data, size_t len) {
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
static int redp2p_tcp_readline(redp2p_fd_t fd, char *buf, int cap, int timeout_sec) {
    int total = 0;
    int n;
    char byte;

    if (cap < 1) return -1;

    for (;;) {
        fd_set fds;
        struct timeval tv;

        FD_ZERO(&fds);
        if (!redp2p_fdset_add(fd, &fds, NULL)) return -1;
        tv.tv_sec = (timeout_sec > 0 && total == 0) ? timeout_sec : 1;
        tv.tv_usec = 0;

        n = select(fd + 1, &fds, NULL, NULL, &tv);
        if (n <= 0) return -1;

        n = redp2p_sock_read(fd, &byte, 1);
        if (n <= 0) return -2;

        if (byte == '\n') {
            buf[total] = '\0';
            return total;
        }
        if (byte == '\r') continue;
        if (!redp2p_control_bytes_valid(&byte, 1)) return -3;
        if (total >= cap - 1) return -4;
        buf[total++] = byte;
    }
}

/**
 * Maps one index JSON error code to a library result code.
 * @param code Index reply error code.
 * @return REDP2P_* result code.
 */
static int redp2p_http_map_error(const char *code)
{
    if (!code) return REDP2P_EPROTO;
    if (strcmp(code, "bad_request") == 0 || strcmp(code, "busy") == 0)
        return REDP2P_EPROTO;
    if (strcmp(code, "invalid_id") == 0)
        return REDP2P_EINVAL;
    if (strcmp(code, "auth_failed") == 0 || strcmp(code, "invalid_key") == 0)
        return REDP2P_EAUTH;
    if (strcmp(code, "not_found") == 0)
        return REDP2P_ENOENT;
    if (strcmp(code, "table_full") == 0)
        return REDP2P_EFULL;
    if (strcmp(code, "internal") == 0)
        return REDP2P_ERROR;
    return REDP2P_EPROTO;
}

/**
 * Reads one bounded chunk of one index HTTP response body.
 * @param fd  Response socket.
 * @param buf Output buffer.
 * @param cap Output buffer capacity.
 * @return Bytes read, or a negative value on timeout or failure.
 */
static int redp2p_http_read_some(redp2p_fd_t fd, char *buf, int cap)
{
    fd_set fds;
    struct timeval tv;
    int n;

    if (cap < 1) return -1;
    FD_ZERO(&fds);
    if (!redp2p_fdset_add(fd, &fds, NULL)) return -1;
    tv.tv_sec = REDP2P_HTTP_TIMEOUT_S;
    tv.tv_usec = 0;
    n = select((int)fd + 1, &fds, NULL, NULL, &tv);
    if (n <= 0) return -1;
    return redp2p_sock_read(fd, buf, cap);
}

/**
 * Issues one HTTP/1.1 JSON request to the index and parses its reply.
 * @param ctx           Context for error details, or NULL.
 * @param phase         Diagnostic phase prefix.
 * @param host          Index host.
 * @param port          Index port.
 * @param request       Request JSON value, serialized but not freed here.
 * @param response_out  Optional output JSON value owned by the caller.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_http_client(redp2p_t *ctx, const char *phase,
    const char *host, unsigned short port, JSON_Value *request,
    JSON_Value **response_out)
{
    char head[REDP2P_HTTP_LINE_MAX * 6];
    char body[REDP2P_HTTP_BODY_MAX + 1];
    char line[REDP2P_HTTP_LINE_MAX];
    redp2p_fd_t fd;
    size_t body_size;
    long content_length;
    int status;
    int line_result;
    int off;
    int i;
    int n;

    if (!phase || !host || !host[0] || port == 0 || !request)
        return REDP2P_EINVAL;
    if (response_out) *response_out = NULL;
    body_size = json_serialization_size(request);
    if (body_size == 0 || body_size > sizeof(body)) {
        redp2p_set_error(ctx, "%s: index request is too large", phase);
        return REDP2P_EPROTO;
    }
    fd = redp2p_tcp_connect(host, port);
    if (REDP2P_ISERR(fd)) {
        redp2p_set_error(ctx, "%s: index connect %s:%u failed",
            phase, host, (unsigned)port);
        return REDP2P_ENET;
    }
    if (json_serialize_to_buffer(request, body, sizeof(body)) != JSONSuccess) {
        REDP2P_FD_CLOSE(fd);
        redp2p_set_error(ctx, "%s: index request serialization failed", phase);
        return REDP2P_ERROR;
    }
    n = snprintf(head, sizeof(head),
        "POST /redp2p/ HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n", host, (unsigned)(body_size - 1));
    if (n < 0 || (size_t)n >= sizeof(head) ||
        redp2p_write_all(fd, head, n) != 0 ||
        redp2p_write_all(fd, body, (int)(body_size - 1)) != 0)
    {
        REDP2P_FD_CLOSE(fd);
        redp2p_set_error(ctx, "%s: index request write failed", phase);
        return REDP2P_ENET;
    }
    line_result = redp2p_tcp_readline(fd, line, (int)sizeof(line),
        REDP2P_HTTP_TIMEOUT_S);
    if (line_result < 0) {
        REDP2P_FD_CLOSE(fd);
        redp2p_set_error(ctx, line_result == -1 ?
            "%s: index response timed out" : "%s: index response failed",
            phase);
        return line_result == -1 ? REDP2P_ETIMEOUT : REDP2P_ENET;
    }
    if (strncmp(line, "HTTP/", 5) != 0) {
        REDP2P_FD_CLOSE(fd);
        redp2p_set_error(ctx, "%s: malformed index status line", phase);
        return REDP2P_EPROTO;
    }
    {
        const char *cursor;
        int d;

        cursor = strchr(line, ' ');
        status = 0;
        if (!cursor) {
            REDP2P_FD_CLOSE(fd);
            redp2p_set_error(ctx, "%s: malformed index status line", phase);
            return REDP2P_EPROTO;
        }
        while (*cursor == ' ') cursor++;
        for (d = 0; d < 3 && cursor[d] >= '0' && cursor[d] <= '9'; d++)
            status = status * 10 + (cursor[d] - '0');
        if (d != 3) {
            REDP2P_FD_CLOSE(fd);
            redp2p_set_error(ctx, "%s: malformed index status line", phase);
            return REDP2P_EPROTO;
        }
    }
    content_length = -1;
    for (i = 0; i < REDP2P_HTTP_HEADERS_MAX; i++) {
        char *colon;

        line_result = redp2p_tcp_readline(fd, line, (int)sizeof(line),
            REDP2P_HTTP_TIMEOUT_S);
        if (line_result < 0) {
            REDP2P_FD_CLOSE(fd);
            redp2p_set_error(ctx, line_result == -1 ?
                "%s: index response timed out" : "%s: index response failed",
                phase);
            return line_result == -1 ? REDP2P_ETIMEOUT : REDP2P_ENET;
        }
        if (line_result == 0) break;
        colon = strchr(line, ':');
        if (colon) {
            char name[32];
            const char *value;

            if ((size_t)(colon - line) >= sizeof(name)) {
                REDP2P_FD_CLOSE(fd);
                redp2p_set_error(ctx, "%s: malformed index response headers",
                    phase);
                return REDP2P_EPROTO;
            }
            memcpy(name, line, (size_t)(colon - line));
            name[colon - line] = '\0';
            value = colon + 1;
            while (*value == ' ' || *value == '\t') value++;
            if (redp2p_ascii_casecmp(name, "Content-Length") == 0) {
                if (!redp2p_parse_u(value, 0, REDP2P_HTTP_BODY_MAX,
                    &content_length))
                {
                    REDP2P_FD_CLOSE(fd);
                    redp2p_set_error(ctx,
                        "%s: malformed index response length", phase);
                    return REDP2P_EPROTO;
                }
            } else if (redp2p_ascii_casecmp(name, "Transfer-Encoding") == 0) {
                REDP2P_FD_CLOSE(fd);
                redp2p_set_error(ctx,
                    "%s: unsupported index response encoding", phase);
                return REDP2P_EPROTO;
            }
        }
    }
    if (content_length < 0) content_length = 0;
    off = 0;
    while (off < content_length) {
        line_result = redp2p_http_read_some(fd, body + off,
            (int)content_length - off);
        if (line_result <= 0) {
            REDP2P_FD_CLOSE(fd);
            redp2p_set_error(ctx, line_result == -1 ?
                "%s: index response timed out" : "%s: index response failed",
                phase);
            return line_result == -1 ? REDP2P_ETIMEOUT : REDP2P_ENET;
        }
        off += line_result;
    }
    body[off] = '\0';
    REDP2P_FD_CLOSE(fd);
    if (status == 200) {
        JSON_Value *parsed;

        parsed = json_parse_string(body);
        if (!parsed || json_value_get_type(parsed) != JSONObject) {
            if (parsed) json_value_free(parsed);
            redp2p_set_error(ctx, "%s: malformed index response", phase);
            return REDP2P_EPROTO;
        }
        if (response_out) *response_out = parsed;
        else json_value_free(parsed);
        return REDP2P_OK;
    }
    {
        JSON_Value *parsed;
        char code[REDP2P_HTTP_LINE_MAX];
        const char *code_ref;

        parsed = json_parse_string(body);
        code_ref = NULL;
        if (parsed) {
            if (json_value_get_type(parsed) == JSONObject)
                code_ref = json_object_get_string(json_value_get_object(parsed),
                    "error");
            if (code_ref) {
                snprintf(code, sizeof(code), "%s", code_ref);
                code_ref = code;
            }
            json_value_free(parsed);
        }
        if (code_ref)
            redp2p_set_error(ctx, "%s: index request failed (%s)", phase,
                code_ref);
        else
            redp2p_set_error(ctx, "%s: index request failed (HTTP %d)", phase,
                status);
        return code_ref ? redp2p_http_map_error(code_ref) :
            (status == 503 ? REDP2P_EFULL : REDP2P_EPROTO);
    }
}

/**
 * Writes one HTTP/1.1 response and closes semantics for the caller.
 * @param fd           Socket to write.
 * @param status       HTTP status code.
 * @param reason       Status reason phrase.
 * @param content_type Response Content-Type.
 * @param body         Response body.
 * @return REDP2P_OK on success, or a negative error code.
 */
static int redp2p_http_write_response(redp2p_fd_t fd, int status,
    const char *reason, const char *content_type, const char *body)
{
    char head[REDP2P_HTTP_LINE_MAX * 6];
    int n;

    if (!reason || !content_type || !body) return REDP2P_EINVAL;
    n = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, reason, content_type, (int)strlen(body));
    if (n < 0 || (size_t)n >= sizeof(head)) return REDP2P_ERROR;
    if (redp2p_write_all(fd, head, n) != 0) return REDP2P_ENET;
    if (redp2p_write_all(fd, body, (int)strlen(body)) != 0) return REDP2P_ENET;
    return REDP2P_OK;
}

/**
 * Returns whether the byte is ASCII whitespace.
 * @param ch Input byte.
 * @return 1 when whitespace, 0 otherwise.
 */
static int redp2p_is_space(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
        ch == '\f' || ch == '\v';
}

/**
 * Returns whether the identifier contains only alphanumeric characters.
 * @param id Identifier to validate.
 * @return 1 when valid, 0 otherwise.
 */
int redp2p_is_valid_id(const char *id) {
    size_t i;

    if (!id || !id[0]) return 0;
    for (i = 0; id[i]; i++) {
        if (i >= REDP2P_ID_MAX) return 0;
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
static int redp2p_is_pass_char(char ch) {
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
int redp2p_is_valid_pass_token(const char *pass) {
    size_t i;

    if (!pass || !pass[0]) return 0;
    for (i = 0; pass[i]; i++) {
        if (i >= REDP2P_PASS_MAX) return 0;
        if (!redp2p_is_pass_char(pass[i])) return 0;
    }
    return 1;
}

/**
 * Trims leading and trailing ASCII whitespace in place.
 * @param text Mutable string buffer.
 * @return Pointer to the first non-whitespace byte.
 */
static char *redp2p_trim(char *text) {
    char *end;

    if (!text) return NULL;
    while (*text && redp2p_is_space(*text)) text++;
    end = text + strlen(text);
    while (end > text && redp2p_is_space(end[-1])) end--;
    *end = '\0';
    return text;
}

/**
 * Finds one VIP seat by identifier.
 * @param ctx Open context.
 * @param id Reserved seat identifier.
 * @return VIP index on success, SIZE_MAX when missing.
 */
static size_t redp2p_find_vip(redp2p_t *ctx, const char *id) {
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
static void redp2p_update_nonvip_cap(redp2p_t *ctx) {
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
 * @return REDP2P_OK on success, REDP2P_ERROR on allocation failure.
 */
static int redp2p_ensure_peer_storage(redp2p_t *ctx, size_t need) {
    redp2p_peer_t *peers;
    size_t cap;
    size_t limit;

    if (!ctx) return REDP2P_ERROR;
    limit = SIZE_MAX / sizeof(*ctx->peers);
    if (ctx->seats_set) limit = ctx->n_peers_cap;
    if (need > limit) return REDP2P_EFULL;
    if (need <= ctx->peers_alloc) return REDP2P_OK;
    cap = ctx->peers_alloc > 0 ? ctx->peers_alloc : 8;
    if (cap > limit) cap = limit;
    while (cap < need) {
        if (cap > limit / 2) {
            cap = limit;
        } else {
            cap *= 2;
        }
    }
    if (cap > SIZE_MAX / sizeof(*ctx->peers)) return REDP2P_ERROR;
    peers = (redp2p_peer_t *)realloc(ctx->peers, cap * sizeof(*ctx->peers));
    if (!peers) return REDP2P_ERROR;
    ctx->peers = peers;
    ctx->peers_alloc = cap;
    return REDP2P_OK;
}

/**
 * Counts online peers that do not have a reserved VIP seat.
 * @param ctx Open context.
 * @return Number of online non-VIP peers.
 */
static size_t redp2p_count_nonvip_peers(redp2p_t *ctx) {
    size_t i;
    size_t count;

    if (!ctx) return 0;
    count = 0;
    for (i = 0; i < ctx->n_peers; i++) {
        if (redp2p_find_vip(ctx, ctx->peers[i].id) == SIZE_MAX) count++;
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
 * @return REDP2P_OK on success, REDP2P_ERROR on validation failure.
 */
static int redp2p_add_vip(redp2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap)
{
    redp2p_vip_entry_t *vips;
    size_t cap;

    if (!ctx || !id || !pass) return REDP2P_ERROR;
    if (!redp2p_is_valid_id(id)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "REDP2P_VIP invalid id '%s'", id);
        return REDP2P_ERROR;
    }
    if (!redp2p_is_valid_pass_token(pass)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "REDP2P_VIP invalid password for id '%s'", id);
        return REDP2P_ERROR;
    }
    if (redp2p_find_vip(ctx, id) != SIZE_MAX) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "REDP2P_VIP redefines reserved id '%s'", id);
        return REDP2P_ERROR;
    }
    if (ctx->n_vips >= ctx->vips_cap) {
        if (ctx->vips_cap > SIZE_MAX / 2) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "REDP2P_VIP table capacity overflow");
            return REDP2P_ERROR;
        }
        cap = ctx->vips_cap > 0 ? ctx->vips_cap * 2 : 8;
        if (cap > SIZE_MAX / sizeof(*ctx->vips)) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "REDP2P_VIP table allocation overflow");
            return REDP2P_ERROR;
        }
        vips = (redp2p_vip_entry_t *)realloc(ctx->vips,
            cap * sizeof(*ctx->vips));
        if (!vips) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "failed to allocate REDP2P_VIP table");
            return REDP2P_ERROR;
        }
        ctx->vips = vips;
        ctx->vips_cap = cap;
    }
    strncpy(ctx->vips[ctx->n_vips].id, id, REDP2P_ID_MAX);
    ctx->vips[ctx->n_vips].id[REDP2P_ID_MAX] = '\0';
    strncpy(ctx->vips[ctx->n_vips].pass, pass, REDP2P_PASS_MAX);
    ctx->vips[ctx->n_vips].pass[REDP2P_PASS_MAX] = '\0';
    ctx->n_vips++;
    return REDP2P_OK;
}

/**
 * Returns the registration password for one identifier.
 * @param ctx Open context.
 * @param id Service identifier.
 * @return VIP password when reserved, otherwise the global password.
 */
static const char *redp2p_get_register_pass(redp2p_t *ctx, const char *id) {
    size_t idx;

    if (!ctx) return "";
    idx = redp2p_find_vip(ctx, id);
    if (idx != SIZE_MAX) return ctx->vips[idx].pass;
    return ctx->pass;
}

/**
 * Open.
 * @return 0 on success, -1 on error.
 */
int redp2p_open(redp2p_t **out) {
    redp2p_t *ctx;
    if (!out) return REDP2P_ERROR;
    ctx = (redp2p_t *)calloc(1, sizeof(redp2p_t));
    if (!ctx) return REDP2P_ERROR;
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
    ctx->proto = REDP2P_PROTO_TCP;
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    ctx->conns = NULL;
    ctx->n_conns = 0;
    ctx->conns_cap = 0;
    ctx->n_pending_calls = 0;
    ctx->prune_interval_s = REDP2P_PRUNE_INTERVAL_S;
    ctx->etimeout_sec = REDP2P_ETIMEOUT_SEC;
    ctx->heartbeat_s = REDP2P_HEARTBEAT_S;
    ctx->punch_poll_ms = REDP2P_PUNCH_POLL_MS;
    {
        const char *env = getenv("REDP2P_PRUNE_INTERVAL_S");
        if (env) {
            long v = 0;
            if (redp2p_parse_u(env, 1, 3600, &v) == REDP2P_OK)
                ctx->prune_interval_s = (unsigned long)v;
        }
        env = getenv("REDP2P_ETIMEOUT_SEC");
        if (env) {
            long v = 0;
            if (redp2p_parse_u(env, 1, 86400, &v) == REDP2P_OK)
                ctx->etimeout_sec = (unsigned long)v;
        }
        env = getenv("REDP2P_HEARTBEAT_S");
        if (env) {
            long v = 0;
            if (redp2p_parse_u(env, 1, 3600, &v) == REDP2P_OK)
                ctx->heartbeat_s = (unsigned long)v;
        }
        env = getenv("REDP2P_PUNCH_POLL_MS");
        if (env) {
            long v = 0;
            if (redp2p_parse_u(env, 10, 60000, &v) == REDP2P_OK)
                ctx->punch_poll_ms = (unsigned long)v;
        }
    }
    ctx->stop_requested = 0;
#ifdef _WIN32
    InitializeCriticalSection(&ctx->mutex);
#else
    pthread_mutex_init(&ctx->mutex, NULL);
#endif

    *out = ctx;
    return REDP2P_OK;
}

/**
 * Close.
 * @return 0 on success, -1 on error.
 */
int redp2p_close(redp2p_t *ctx) {
    int i;
    if (!ctx) return REDP2P_ERROR;
    if (ctx->conns) {
        for (i = 0; i < ctx->n_conns; i++)
            REDP2P_FD_CLOSE(ctx->conns[i].fd);
        free(ctx->conns);
    }
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
    return REDP2P_OK;
}

/**
 * Requests clean termination for the current blocking operation on one context.
 * @param ctx Context to stop.
 * @return 0 on success, -1 on error.
 */
int redp2p_stop(redp2p_t *ctx) {
    if (!ctx) return REDP2P_EINVAL;
    atomic_store(&ctx->stop_requested, 1);
    return REDP2P_OK;
}

/**
 * Checks whether one context was requested to stop.
 * @return Nonzero if a stop was requested, zero otherwise.
 */
int redp2p_stop_requested(redp2p_t *ctx) {
    return ctx && atomic_load(&ctx->stop_requested);
}

/**
 * Return string for status code.
 * @return Status string.
 */
const char *redp2p_strerror(int code) {
    switch (code) {
        case REDP2P_OK:       return "OK";
        case REDP2P_ERROR:    return "general error";
        case REDP2P_ENET:     return "network error";
        case REDP2P_ENOENT:   return "peer not found";
        case REDP2P_ETIMEOUT: return "timeout";
        case REDP2P_EFULL:    return "peer table full";
        case REDP2P_EINVAL:   return "invalid argument";
        case REDP2P_EPROTO:   return "protocol error";
        case REDP2P_EAUTH:    return "authentication failed";
        case REDP2P_EVERSION: return "unsupported protocol version";
        case REDP2P_EPUNCH:   return "direct connectivity failed";
        default:              return "unknown error";
    }
}

/**
 * Records one per-context detail error message.
 * @return None.
 */
static void redp2p_set_error(redp2p_t *ctx, const char *fmt, ...) {
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
const char *redp2p_get_error(redp2p_t *ctx) {
    if (!ctx) return "";
    return ctx->err_buf;
}

/**
 * Returns one caller-owned options struct with safe defaults.
 * Summary: Index port and sweep are populated; callers own the returned struct.
 * @return Default options struct.
 */
redp2p_options_t redp2p_options_default(void) {
    redp2p_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.seats = 0;
    opts.pow = 0;
    opts.sweep = 20;
    return opts;
}

/**
 * Loads REDP2P_* environment values into one options struct with strict rules.
 * Summary: Invalid numeric values are ignored and defaults are retained.
 * Initialize with redp2p_options_default and free with redp2p_options_free.
 * @param opts Options struct to populate.
 * @return None.
 */
void redp2p_options_load_env(redp2p_options_t *opts) {
    const char *val;
    long num;
    size_t seats;

    if (!opts) return;

    val = getenv("REDP2P_SEATS");
    if (redp2p_parse_size(val, &seats) &&
        seats <= SIZE_MAX / sizeof(redp2p_peer_t))
        opts->seats = seats;

    val = getenv("REDP2P_POW");
    if (val && redp2p_parse_env(val, 0, REDP2P_POW_MAX, &num))
        opts->pow = (int)num;

    val = getenv("REDP2P_SWEEP");
    if (val && redp2p_parse_env(val, 0, REDP2P_SWEEP_MAX, &num))
        opts->sweep = (int)num;

    val = getenv("REDP2P_PASS");
    if (val) {
        crypto_wipe(opts->pass, sizeof(opts->pass));
        strncpy(opts->pass, val, REDP2P_PASS_MAX);
        opts->pass[REDP2P_PASS_MAX] = '\0';
    }

    val = getenv("REDP2P_VIP");
    if (val) {
        size_t len = strlen(val);
        if (opts->vip) crypto_wipe(opts->vip, strlen(opts->vip));
        free(opts->vip);
        opts->vip = (char *)malloc(len + 1);
        if (opts->vip) memcpy(opts->vip, val, len + 1);
    }

    val = getenv("REDP2P_STUN");
    if (val) {
        strncpy(opts->stun_url, val, sizeof(opts->stun_url) - 1);
        opts->stun_url[sizeof(opts->stun_url) - 1] = '\0';
    }
}

/**
 * Options free.
 * @return None.
 */
void redp2p_options_free(redp2p_options_t *opts) {
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
int redp2p_set_seats(redp2p_t *ctx, size_t seats) {
    if (!ctx) return REDP2P_EINVAL;
    if (seats > SIZE_MAX / sizeof(*ctx->peers)) {
        redp2p_set_error(ctx, "seats exceeds the platform allocation range");
        return REDP2P_EINVAL;
    }
    ctx->n_peers_cap = seats;
    ctx->seats_set = 1;
    redp2p_update_nonvip_cap(ctx);
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Set pow.
 * @return 0 on success, -1 on error.
 */
int redp2p_set_pow(redp2p_t *ctx, int bits) {
    if (!ctx) return REDP2P_EINVAL;
    if (bits < 0 || bits > REDP2P_POW_MAX) {
        redp2p_set_error(ctx, "pow must be between 0 and %d", REDP2P_POW_MAX);
        return REDP2P_EINVAL;
    }
    ctx->pow_bits = bits;
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Configures the local service or listener port used by pub and con.
 * Summary: Marks the port as explicit for precedence over arguments.
 * @param ctx  Open context.
 * @param port Local bind port.
 * @return 0 on success, -1 on error.
 */
int redp2p_set_port(redp2p_t *ctx, unsigned short port) {
    if (!ctx) return REDP2P_EINVAL;
    if (port == 0) {
        redp2p_set_error(ctx, "port must be between 1 and 65535");
        return REDP2P_EINVAL;
    }
    ctx->bind_port = port;
    ctx->explicit_port = 1;
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Set protocol.
 * @return 0 on success, -1 on error.
 */
int redp2p_set_protocol(redp2p_t *ctx, int proto) {
    if (!ctx) return REDP2P_EINVAL;
    if (proto != REDP2P_PROTO_TCP && proto != REDP2P_PROTO_UDP) {
        redp2p_set_error(ctx, "protocol must be REDP2P_PROTO_TCP or REDP2P_PROTO_UDP");
        return REDP2P_EINVAL;
    }
    ctx->proto = proto;
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Set sweep count.
 * @return Status code.
 */
int redp2p_set_sweep(redp2p_t *ctx, int sweep) {
    if (!ctx) return REDP2P_EINVAL;
    if (sweep < 0 || sweep > REDP2P_SWEEP_MAX) {
        redp2p_set_error(ctx, "sweep must be between 0 and %d", REDP2P_SWEEP_MAX);
        return REDP2P_EINVAL;
    }
    ctx->sweep = sweep;
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Resolves the effective local port for pub or con.
 * Summary: A nonzero argument overrides a default context port, while a nonzero
 * argument conflicting with an explicitly set context port is rejected.
 * @param ctx        Open context.
 * @param arg_port  Port argument from redp2p_wait or redp2p_connect.
 * @param out        Effective port output.
 * @return REDP2P_OK on success, REDP2P_ERROR on conflicting ports.
 */
static int redp2p_resolve_port(redp2p_t *ctx, unsigned short arg_port,
    unsigned short *out)
{
    if (arg_port == 0) {
        *out = ctx->bind_port;
        return REDP2P_OK;
    }
    if (ctx->explicit_port && ctx->bind_port != 0 &&
        ctx->bind_port != arg_port)
        return REDP2P_ERROR;
    *out = arg_port;
    return REDP2P_OK;
}

/**
 * Stores the shared register password.
 * @param ctx  Open context.
 * @param pass Shared password string.
 * @return 0 on success, -1 on error.
 */
int redp2p_set_pass(redp2p_t *ctx, const char *pass) {
    if (!ctx) return REDP2P_EINVAL;
    if (!pass || (pass[0] && !redp2p_is_valid_pass_token(pass))) {
        redp2p_set_error(ctx, "registration password contains invalid bytes");
        return REDP2P_EINVAL;
    }
    strncpy(ctx->pass, pass, REDP2P_PASS_MAX);
    ctx->pass[REDP2P_PASS_MAX] = '\0';
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Parses the VIP seat map from one whitespace-separated string.
 * @param ctx Open context.
 * @param vip Whitespace-separated id/pass pairs.
 * @param err Output error buffer.
 * @param err_cap Output error buffer capacity.
 * @return REDP2P_OK on success, REDP2P_ERROR on parse failure.
 */
int redp2p_set_vip(
redp2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
)
{
    char *copy;
    char *cursor;

    if (!ctx) return REDP2P_ERROR;
    if (ctx->vips)
        crypto_wipe(ctx->vips, ctx->vips_cap * sizeof(*ctx->vips));
    free(ctx->vips);
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    redp2p_update_nonvip_cap(ctx);
    if (!vip || !vip[0]) return REDP2P_OK;
    copy = (char *)malloc(strlen(vip) + 1);
    if (!copy) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "failed to allocate REDP2P_VIP buffer");
        return REDP2P_ERROR;
    }
    strcpy(copy, vip);
    cursor = redp2p_trim(copy);
    while (cursor && *cursor) {
        char *id;
        char *pass;

        id = cursor;
        while (*cursor && !redp2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && redp2p_is_space(*cursor)) cursor++;
        if (!*cursor) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "REDP2P_VIP has odd token count");
            crypto_wipe(copy, strlen(vip) + 1);
            free(copy);
            if (ctx->vips)
                crypto_wipe(ctx->vips,
                    ctx->vips_cap * sizeof(*ctx->vips));
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            redp2p_update_nonvip_cap(ctx);
            return REDP2P_ERROR;
        }
        pass = cursor;
        while (*cursor && !redp2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && redp2p_is_space(*cursor)) cursor++;
        if (redp2p_add_vip(ctx, id, pass, err, err_cap) != REDP2P_OK) {
            crypto_wipe(copy, strlen(vip) + 1);
            free(copy);
            if (ctx->vips)
                crypto_wipe(ctx->vips,
                    ctx->vips_cap * sizeof(*ctx->vips));
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            redp2p_update_nonvip_cap(ctx);
            return REDP2P_ERROR;
        }
    }
    crypto_wipe(copy, strlen(vip) + 1);
    free(copy);
    redp2p_update_nonvip_cap(ctx);
    return REDP2P_OK;
}

/**
 * Find peer.
 * @return Peer index on success, SIZE_MAX when missing.
 */
static size_t redp2p_find_peer(redp2p_t *ctx, const char *id) {
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
static void redp2p_evict_stale(redp2p_t *ctx) {
    uint64_t now;
    size_t i;

    now = redp2p_now_s();
    i = ctx->n_peers;
    while (i > 0) {
        i--;
        if (now - ctx->peers[i].last_seen > ctx->etimeout_sec) {
            if (i < ctx->n_peers - 1) {
                memmove(&ctx->peers[i], &ctx->peers[i + 1],
                    (ctx->n_peers - i - 1) * sizeof(ctx->peers[0]));
            }
            ctx->n_peers--;
        }
    }
}

/**
 * Reports whether one peer record is expired by TTL.
 * @param ctx   Open index context.
 * @param index Peer index.
 * @return 1 when expired or out of range, 0 when fresh.
 */
static int redp2p_peer_is_stale(redp2p_t *ctx, size_t index) {
    uint64_t now;

    if (index >= ctx->n_peers) return 1;
    now = redp2p_now_s();
    return now - ctx->peers[index].last_seen > ctx->etimeout_sec;
}

/**
 * Generate key.
 * @return Status code.
 */
static int redp2p_generate_key(char *out) {
    unsigned char random_bytes[REDP2P_KEY_SZ / 2];

    if (!out) return 0;
    if (redp2p_fill_random(random_bytes, sizeof(random_bytes)) != 0)
        return 0;
    return redp2p_hex_encode(random_bytes, sizeof(random_bytes), out,
        REDP2P_KEY_SZ + 1);
}

/**
 * Add peer.
 * @return 0 on success, -1 on error.
 */
static int redp2p_add_peer(redp2p_t *ctx, const char *id)
{
    size_t id_len;
    size_t idx;
    int is_vip;

    idx = redp2p_find_peer(ctx, id);
    if (idx != SIZE_MAX) {
        ctx->peers[idx].last_seen = redp2p_now_s();
        return REDP2P_OK;
    }

    is_vip = redp2p_find_vip(ctx, id) != SIZE_MAX;
    if (ctx->seats_set && ctx->n_peers >= ctx->n_peers_cap)
        return REDP2P_EFULL;
    if (ctx->n_peers >= SIZE_MAX / sizeof(*ctx->peers))
        return REDP2P_ERROR;
    if (ctx->seats_set && !is_vip &&
        redp2p_count_nonvip_peers(ctx) >= ctx->nonvip_cap)
        return REDP2P_EFULL;
    if (redp2p_ensure_peer_storage(ctx, ctx->n_peers + 1) != REDP2P_OK)
        return REDP2P_ERROR;

    id_len = strlen(id);
    if (id_len > REDP2P_ID_MAX)
        id_len = REDP2P_ID_MAX;
    memcpy(ctx->peers[ctx->n_peers].id, id, id_len);
    ctx->peers[ctx->n_peers].id[id_len] = '\0';

    ctx->peers[ctx->n_peers].last_seen = redp2p_now_s();
    if (!redp2p_generate_key(ctx->peers[ctx->n_peers].key))
        return REDP2P_ERROR;
    ctx->peers[ctx->n_peers].proto = 0;
    ctx->peers[ctx->n_peers].udp_port = 0;
    ctx->peers[ctx->n_peers].n_candidates = 0;
    ctx->n_peers++;
    return REDP2P_OK;
}

/**
 * Remove peer.
 * @return 0 on success, -1 on error.
 */
static int redp2p_remove_peer(redp2p_t *ctx, const char *id) {
    size_t idx;

    idx = redp2p_find_peer(ctx, id);
    if (idx == SIZE_MAX) return REDP2P_ENOENT;
    if (idx < ctx->n_peers - 1) {
        memmove(&ctx->peers[idx], &ctx->peers[idx + 1],
            (ctx->n_peers - idx - 1) * sizeof(ctx->peers[0]));
    }
    ctx->n_peers--;
    return REDP2P_OK;
}

/**
 * Removes one pending call by index.
 * @param ctx Open index context.
 * @param idx Pending call index.
 * @return None.
 */
static void redp2p_pending_call_remove(redp2p_t *ctx, int idx) {
    if (idx < 0 || idx >= ctx->n_pending_calls) return;
    ctx->pending_calls[idx] = ctx->pending_calls[--ctx->n_pending_calls];
    crypto_wipe(&ctx->pending_calls[ctx->n_pending_calls],
        sizeof(ctx->pending_calls[ctx->n_pending_calls]));
}

/**
 * Copies a bounded string with NUL termination.
 * @param dst    Destination buffer.
 * @param dst_cap Destination capacity.
 * @param src    Source string.
 * @return None.
 */
static void redp2p_bounded_copy(char *dst, size_t dst_cap, const char *src) {
    size_t len;

    if (!dst || dst_cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    len = strlen(src);
    if (len >= dst_cap) len = dst_cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/**
 * Evicts expired pending calls.
 * @param ctx Open index context.
 * @return None.
 */
static void redp2p_pending_call_evict_stale(redp2p_t *ctx) {
    uint64_t now;
    int i;

    now = redp2p_now_s();
    for (i = 0; i < ctx->n_pending_calls; ) {
        if (now - ctx->pending_calls[i].ts > REDP2P_PENDING_CALL_TTL_S) {
            redp2p_pending_call_remove(ctx, i);
        } else {
            i++;
        }
    }
}

/**
 * Adds one bounded pending call.
 * @param ctx          Open index context.
 * @param caller_id    Requesting consumer identifier.
 * @param target_id    Target publisher identifier.
 * @param sess_id      Session identifier.
 * @param candidates   Caller candidate array.
 * @param n_candidates Caller candidate count.
 * @return 1 on success, 0 when the pending call store is full.
 */
static int redp2p_pending_call_add(redp2p_t *ctx, const char *caller_id,
    const char *target_id, const char *sess_id,
    const redp2p_candidate_t *candidates, int n_candidates)
{
    int idx;

    if (ctx->n_pending_calls >= REDP2P_MAX_PENDING_CALLS) return 0;
    idx = ctx->n_pending_calls++;
    redp2p_bounded_copy(ctx->pending_calls[idx].caller_id,
        sizeof(ctx->pending_calls[idx].caller_id), caller_id);
    redp2p_bounded_copy(ctx->pending_calls[idx].target_id,
        sizeof(ctx->pending_calls[idx].target_id), target_id);
    redp2p_bounded_copy(ctx->pending_calls[idx].sess_id,
        sizeof(ctx->pending_calls[idx].sess_id), sess_id);
    ctx->pending_calls[idx].n_candidates = n_candidates;
    if (n_candidates > 0) {
        memcpy(ctx->pending_calls[idx].candidates, candidates,
            (size_t)n_candidates * sizeof(candidates[0]));
    }
    ctx->pending_calls[idx].ts = redp2p_now_s();
    return 1;
}

/**
 * Collects and consumes all pending calls for one publisher identifier.
 * @param ctx       Open index context.
 * @param target_id Target publisher identifier.
 * @param out       Output pending call array.
 * @param out_n     Output pending call count.
 * @return None.
 */
static void redp2p_pending_call_take_all(redp2p_t *ctx,
    const char *target_id, redp2p_pending_call_t *out, int *out_n)
{
    int i;

    *out_n = 0;
    for (i = 0; i < ctx->n_pending_calls; ) {
        if (strcmp(ctx->pending_calls[i].target_id, target_id) == 0) {
            out[*out_n] = ctx->pending_calls[i];
            (*out_n)++;
            redp2p_pending_call_remove(ctx, i);
        } else {
            i++;
        }
    }
}

/**
 * Copies one colon-delimited field from a cursor.
 * @param cursor Input cursor updated after the field.
 * @param out    Output field buffer.
 * @param cap    Output field capacity.
 * @param delim  Required delimiter or NUL for final field.
 * @return 1 on success, 0 on malformed input.
 */
static int redp2p_parse_field(const char **cursor, char *out, size_t cap,
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
static int redp2p_is_hex_token(const char *text, size_t len) {
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
static int redp2p_is_session_token(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= REDP2P_CTRL_SESSION_MAX) return 0;
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
static int redp2p_is_punch_id(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= REDP2P_ID_MAX) return 0;
        if (!((text[i] >= 'a' && text[i] <= 'z') ||
            (text[i] >= 'A' && text[i] <= 'Z') ||
            (text[i] >= '0' && text[i] <= '9') || text[i] == '-'))
            return 0;
    }
    return 1;
}

/**
 * Maps one candidate type token to an internal type.
 * @param text Input candidate type token.
 * @param type Output candidate type.
 * @return 1 on success, 0 on unknown type.
 */
static int redp2p_parse_candidate_type(const char *text,
    redp2p_candidate_type_t *type)
{
    if (!text || !type) return 0;
    if (strcmp(text, "host") == 0) *type = REDP2P_CAND_HOST;
    else if (strcmp(text, "lan") == 0) *type = REDP2P_CAND_LAN;
    else if (strcmp(text, "public") == 0) *type = REDP2P_CAND_PUBLIC;
    else if (strcmp(text, "srflx") == 0) *type = REDP2P_CAND_SRFLX;
    else return 0;
    return 1;
}

/**
 * Returns the textual name for one local candidate type.
 * @param type Candidate type.
 * @return Candidate type name.
 */
static const char *redp2p_candidate_type_name(redp2p_candidate_type_t type) {
    if (type == REDP2P_CAND_LAN) return "lan";
    if (type == REDP2P_CAND_PUBLIC) return "public";
    if (type == REDP2P_CAND_SRFLX) return "srflx";
    return "host";
}

/**
 * Returns the address family for one candidate address.
 * @param candidate Candidate to inspect.
 * @return AF_INET, AF_INET6, or AF_UNSPEC.
 */
static int redp2p_candidate_family(const redp2p_candidate_t *candidate) {
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
static unsigned int redp2p_candidate_priority(
    const redp2p_candidate_t *candidate)
{
    int family;
    unsigned int base;

    if (!candidate) return 900u;
    family = redp2p_candidate_family(candidate);
    if (family == AF_INET6) base = 100u;
    else if (family == AF_INET) base = 200u;
    else return 900u;
    if (candidate->type == REDP2P_CAND_HOST) return base;
    if (candidate->type == REDP2P_CAND_LAN) return base + 10u;
    if (candidate->type == REDP2P_CAND_PUBLIC) return base + 20u;
    if (candidate->type == REDP2P_CAND_SRFLX) return base + 30u;
    if (candidate->type == REDP2P_CAND_PRFLX) return base + 40u;
    if (candidate->type == REDP2P_CAND_PREDICTED) return base + 50u;
    return 900u;
}

/**
 * Reports whether two candidates describe the same network endpoint.
 * @param a First candidate.
 * @param b Second candidate.
 * @return 1 when equivalent, 0 otherwise.
 */
static int redp2p_candidate_same_endpoint(const redp2p_candidate_t *a,
    const redp2p_candidate_t *b)
{
    struct sockaddr_storage aa;
    struct sockaddr_storage bb;

    if (!a || !b || a->port != b->port) return 0;
    if (redp2p_candidate_family(a) != redp2p_candidate_family(b)) return 0;
    if (!redp2p_candidate_sockaddr(a, &aa)) return 0;
    if (!redp2p_candidate_sockaddr(b, &bb)) return 0;
    return redp2p_sockaddr_equal(&aa, &bb);
}

/**
 * Compares two candidates by local priority and stable textual fields.
 * @param a First candidate.
 * @param b Second candidate.
 * @return Negative, zero, or positive comparison result.
 */
static int redp2p_candidate_compare(const redp2p_candidate_t *a,
    const redp2p_candidate_t *b)
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
static int redp2p_normalize_candidates(redp2p_candidate_t *candidates,
    int *count)
{
    int i;
    int n;

    if (!candidates || !count || *count < 0 || *count > REDP2P_CANDIDATES_MAX)
        return 0;
    n = 0;
    for (i = 0; i < *count; i++) {
        int j;
        if (candidates[i].port == 0) return 0;
        if (redp2p_candidate_family(&candidates[i]) == AF_UNSPEC) return 0;
        candidates[i].priority = redp2p_candidate_priority(&candidates[i]);
        if (candidates[i].priority >= 900u) return 0;
        for (j = 0; j < n; j++) {
            if (!redp2p_candidate_same_endpoint(&candidates[j], &candidates[i]))
                continue;
            if (redp2p_candidate_compare(&candidates[i], &candidates[j]) < 0)
                candidates[j] = candidates[i];
            break;
        }
        if (j == n) candidates[n++] = candidates[i];
    }
    for (i = 1; i < n; i++) {
        redp2p_candidate_t item = candidates[i];
        int j = i - 1;
        while (j >= 0 && redp2p_candidate_compare(&item, &candidates[j]) < 0) {
            candidates[j + 1] = candidates[j];
            j--;
        }
        candidates[j + 1] = item;
    }
    *count = n;
    return 1;
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
static int redp2p_parse_punch_packet(const char *text, const char *prefix,
    char sess_id[REDP2P_CTRL_SESSION_MAX + 1],
    char from_id[REDP2P_ID_MAX + 1], char to_id[REDP2P_ID_MAX + 1])
{
    const char *cursor;
    size_t prefix_len;

    if (!text || !prefix) return 0;
    prefix_len = strlen(prefix);
    if (strncmp(text, prefix, prefix_len) != 0) return 0;
    cursor = text + prefix_len;
    if (!redp2p_parse_field(&cursor, sess_id, REDP2P_CTRL_SESSION_MAX + 1,
        ':'))
        return 0;
    if (!redp2p_parse_field(&cursor, from_id, REDP2P_ID_MAX + 1, ':'))
        return 0;
    if (!redp2p_parse_field(&cursor, to_id, REDP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    while (to_id[0]) {
        size_t len = strlen(to_id);
        if (to_id[len - 1] != '\n' && to_id[len - 1] != '\r') break;
        to_id[len - 1] = '\0';
    }
    return redp2p_is_session_token(sess_id) && redp2p_is_punch_id(from_id) &&
        redp2p_is_punch_id(to_id);
}

#define REDP2P_STUN_ATTR_DATA 0x0013

/**
 * STUN put16.
 * @return None.
 */
static void redp2p_stun_put16(unsigned char *b, int o, int v) {
    b[o] = (unsigned char)(v >> 8); b[o + 1] = (unsigned char)(v);
}

/**
 * STUN length.
 * @return None.
 */
static void redp2p_stun_len(unsigned char *buf, int o) {
    redp2p_stun_put16(buf, 2, o - 20);
}

/**
 * STUN gen id.
 * @return None.
 */
static int redp2p_stun_gen_id(unsigned char id[12]) {
    return redp2p_fill_random(id, 12) == 0;
}

/**
 * STUN build.
 * @return offset after header.
 */
static int redp2p_stun_build(unsigned char *buf, int mt, const unsigned char id[12]) {
    memset(buf, 0, 20);
    redp2p_stun_put16(buf, 0, mt);
    redp2p_stun_put16(buf, 4, 0x2112); buf[6] = 0xA4; buf[7] = 0x42;
    memcpy(buf + 8, id, 12);
    return 20;
}

/**
 * STUN hdr.
 * @return message type, or -1 on error.
 */
static int redp2p_stun_hdr(const unsigned char *buf, int len, unsigned char id[12]) {
    if (len < 20) return -1;
    uint32_t mg = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
        ((uint32_t)buf[6] << 8) | buf[7];
    if (mg != REDP2P_STUN_MAGIC) return -1;
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
static int redp2p_stun_find(const unsigned char *buf, int len, int t, int *al) {
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
static int redp2p_stun_rd_xaddr(const unsigned char *buf, int o, int al,
    unsigned char id[12], char *addr, int acap, unsigned short *port)
{
    (void)id;
    if (al < 8) return -1;
    if (buf[o + 1] != 1) return -1;
    unsigned short xp = ((unsigned short)buf[o + 2] << 8) | buf[o + 3];
    uint32_t xa = ((uint32_t)buf[o + 4] << 24) | ((uint32_t)buf[o + 5] << 16) |
        ((uint32_t)buf[o + 6] << 8) | buf[o + 7];
    *port = xp ^ (unsigned short)(REDP2P_STUN_MAGIC >> 16);
    uint32_t a = xa ^ REDP2P_STUN_MAGIC;
    snprintf(addr, (size_t)acap, "%u.%u.%u.%u",
        (unsigned)(a >> 24) & 0xff, (unsigned)(a >> 16) & 0xff,
        (unsigned)(a >> 8) & 0xff, (unsigned)(a & 0xff));
    return 0;
}

/**
 * STUN binding.
 * Summary: Sends Binding Request and returns srflx ip:port for udp_fd.
 * @param ctx      REDP2P context.
 * @param udp_fd   Bound UDP socket.
 * @param out_ip   Output address buffer.
 * @param out_cap  Output address buffer size.
 * @param out_port Output port.
 * @return 0 on success, -1 on error.
 */
static int redp2p_stun_binding(redp2p_t *ctx, int udp_fd,
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
    if (!redp2p_parse_u(co + 1, 1, 65535, &lport)) return -1;
    port = (unsigned short)lport;

    if (redp2p_resolve(host, port, SOCK_DGRAM, &srv, &srv_len) != 0) return -1;
    if (srv.ss_family != AF_INET) return -1;

    if (!redp2p_stun_gen_id(tx_id)) return -1;
    off = redp2p_stun_build(tx, REDP2P_STUN_BINDING, tx_id);
    redp2p_stun_len(tx, off);

    if (sendto(udp_fd, (const char *)tx, (size_t)off, 0,
        (const struct sockaddr *)&srv, srv_len) < 0) return -1;

    FD_ZERO(&rfds);
    if (!redp2p_fdset_add(udp_fd, &rfds, NULL)) return -1;
    tv.tv_sec = 3; tv.tv_usec = 0;
    n = select(udp_fd + 1, &rfds, NULL, NULL, &tv);
    if (n <= 0) return -1;
    from_len = sizeof(from);
    rl = (int)recvfrom(udp_fd, (char *)rx, sizeof(rx), 0,
        (struct sockaddr *)&from, &from_len);
    if (rl < 20) return -1;
    if (!redp2p_sockaddr_equal(&from, &srv)) return -1;

    mt = redp2p_stun_hdr(rx, rl, rx_id);
    if (mt != REDP2P_STUN_BINDING_RESP) return -1;
    if (memcmp(tx_id, rx_id, sizeof(tx_id)) != 0) return -1;

    ao = redp2p_stun_find(rx, rl, REDP2P_STUN_ATTR_XOR_MAPPED_ADDR, &al);
    if (ao < 0) return -1;
    if (redp2p_stun_rd_xaddr(rx, ao, al, tx_id, out_ip, out_cap, out_port) != 0)
        return -1;
    return 0;
}

/**
 * Set stun url.
 * @return 0 on success, -1 on error.
 */
int redp2p_set_stun_url(redp2p_t *ctx, const char *url) {
    if (!ctx) return REDP2P_ERROR;
    if (url) {
        strncpy(ctx->stun_url, url, sizeof(ctx->stun_url) - 1);
        ctx->stun_url[sizeof(ctx->stun_url) - 1] = '\0';
    } else {
        ctx->stun_url[0] = '\0';
    }
    return REDP2P_OK;
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
int redp2p_gather_candidates(redp2p_t *ctx, int udp_fd,
    redp2p_candidate_t *out, int out_cap, int *out_count) {
    struct sockaddr_storage udp_sa;
    char stun_ip[REDP2P_ADDR_MAX + 1];
    unsigned short stun_port;
    socklen_t udp_sa_len = sizeof(udp_sa);

    stun_ip[0] = '\0';
    stun_port = 0;
    *out_count = 0;
    if (getsockname(udp_fd, (struct sockaddr *)&udp_sa, &udp_sa_len) == 0) {
        unsigned short udp_port = redp2p_sockaddr_port(&udp_sa);
        if (*out_count < out_cap) {
            out[*out_count].type = REDP2P_CAND_HOST;
            if (udp_sa.ss_family == AF_INET6)
                strcpy(out[*out_count].addr, "::1");
            else
                strcpy(out[*out_count].addr, "127.0.0.1");
            out[*out_count].port = udp_port;
            out[*out_count].priority = redp2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }

        redp2p_fd_t test_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (!REDP2P_ISERR(test_fd)) {
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
                        out[*out_count].type = REDP2P_CAND_LAN;
                        strcpy(out[*out_count].addr, local_ip);
                        out[*out_count].port = udp_port;
                        out[*out_count].priority = redp2p_candidate_priority(&out[*out_count]);
                        (*out_count)++;
                    }
                }
            }
            REDP2P_FD_CLOSE(test_fd);
        }

        if (ctx && ctx->stun_url[0]) {
            redp2p_stun_binding(ctx, udp_fd, stun_ip, (int)sizeof(stun_ip),
                &stun_port);
        }
        if (stun_ip[0] != '\0' && *out_count < out_cap) {
            unsigned short srflx_port = stun_port ? stun_port : udp_port;
            out[*out_count].type = REDP2P_CAND_SRFLX;
            snprintf(out[*out_count].addr, sizeof(out[*out_count].addr),
                "%.47s", stun_ip);
            out[*out_count].port = srflx_port;
            out[*out_count].priority = redp2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
    }
    if (!redp2p_normalize_candidates(out, out_count)) return REDP2P_ERROR;
    return REDP2P_OK;
}

/**
 * Converts a candidate into a socket address.
 * @param candidate Candidate to convert.
 * @param out       Output socket address.
 * @return 1 on success, 0 on malformed input.
 */
static int redp2p_candidate_sockaddr(const redp2p_candidate_t *candidate,
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
static int redp2p_punch_send_candidate(int udp_fd,
    const redp2p_candidate_t *candidate, const char *ping_msg,
    int *unsupported)
{
    struct sockaddr_storage cand_sa;
    socklen_t cand_len;

    if (!redp2p_candidate_sockaddr(candidate, &cand_sa)) {
        if (unsupported) (*unsupported)++;
        return 0;
    }
    cand_len = redp2p_sockaddr_len(&cand_sa);
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
 * @return REDP2P_OK on valid response, REDP2P_ETIMEOUT otherwise.
 */
static int redp2p_punch_wait_response(int udp_fd, const char *session_id,
    const char *from_id, const char *to_id, int wait_ms, uint64_t deadline_ms,
    struct sockaddr_storage *selected_addr, int *malformed, int *mismatched)
{
    uint64_t wait_deadline_ms;

    wait_deadline_ms = redp2p_now_ms() + (uint64_t)wait_ms;
    if (wait_deadline_ms > deadline_ms) wait_deadline_ms = deadline_ms;
    while (redp2p_now_ms() < wait_deadline_ms) {
        char recv_buf[1024];
        struct sockaddr_storage src_addr;
        socklen_t src_len = sizeof(src_addr);
        uint64_t now;
        int remaining_ms;
        fd_set readfds;
        struct timeval tv;
        int n;

        now = redp2p_now_ms();
        remaining_ms = (int)(wait_deadline_ms - now);
        FD_ZERO(&readfds);
        if (!redp2p_fdset_add(udp_fd, &readfds, NULL)) return REDP2P_ENET;
        tv.tv_sec = remaining_ms / 1000;
        tv.tv_usec = (remaining_ms % 1000) * 1000;
        if (select(udp_fd + 1, &readfds, NULL, NULL, &tv) <= 0)
            return REDP2P_ETIMEOUT;
        n = recvfrom(udp_fd, recv_buf, sizeof(recv_buf) - 1, 0,
            (struct sockaddr *)&src_addr, &src_len);
        if (n > 0) {
            char rx_sess[64] = {0};
            char rx_from[REDP2P_ID_MAX + 1] = {0};
            char rx_to[REDP2P_ID_MAX + 1] = {0};
            int is_ping;
            int is_pong;

            recv_buf[n] = '\0';
            is_pong = redp2p_parse_punch_packet(recv_buf,
                REDP2P_CTRTOK_PUNCH_PONG,
                rx_sess, rx_from, rx_to);
            is_ping = 0;
            if (!is_pong) {
                is_ping = redp2p_parse_punch_packet(recv_buf,
                    REDP2P_CTRTOK_PUNCH_PING, rx_sess, rx_from, rx_to);
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
                        REDP2P_CTRTOK_PUNCH_PONG, session_id, to_id, from_id);
                    sendto(udp_fd, pong_msg, strlen(pong_msg), 0,
                        (struct sockaddr *)&src_addr, src_len);
                }
                return REDP2P_OK;
            }
            if (mismatched) (*mismatched)++;
        }
    }
    return REDP2P_ETIMEOUT;
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
int redp2p_punch_select(redp2p_t *ctx, int sweep_limit, int udp_fd, const char *session_id, const char *from_id, const char *to_id, const redp2p_candidate_t *remote_candidates, int remote_candidate_count, struct sockaddr_storage *selected_addr) {
    char ping_msg[256];
    uint64_t deadline_ms;
    int direct_count;
    int sent_count;
    int malformed_count;
    int mismatch_count;
    int unsupported_count;

    (void)ctx;
    if (remote_candidate_count <= 0) {
        fprintf(stderr, "redp2p: punch failed: no candidates\n");
        return REDP2P_ERROR;
    }
    if (sweep_limit < 0) sweep_limit = 0;
    deadline_ms = redp2p_now_ms() + REDP2P_PUNCH_TOTAL_MS;
    direct_count = 0;
    sent_count = 0;
    malformed_count = 0;
    mismatch_count = 0;
    unsupported_count = 0;
    for (int c = 0; c < remote_candidate_count; c++) {
        if (remote_candidates[c].priority < 300u) direct_count++;
    }
    snprintf(ping_msg, sizeof(ping_msg), "%s%s:%s:%s\n",
        REDP2P_CTRTOK_PUNCH_PING, session_id, from_id, to_id);
    for (int i = 0; direct_count > 0 && i < REDP2P_PUNCH_DIRECT_ROUNDS; i++) {
        for (int c = 0; c < remote_candidate_count; c++) {
            if (remote_candidates[c].priority >= 300u) continue;
            sent_count += redp2p_punch_send_candidate(udp_fd,
                &remote_candidates[c], ping_msg, &unsupported_count);
        }
        if (redp2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
            REDP2P_PUNCH_DIRECT_WAIT_MS, deadline_ms, selected_addr,
            &malformed_count, &mismatch_count) == REDP2P_OK)
            return REDP2P_OK;
    }
    for (int sweep = 1; sweep <= sweep_limit && redp2p_now_ms() < deadline_ms;
        sweep++)
    {
        for (int sign = -1; sign <= 1 && redp2p_now_ms() < deadline_ms;
            sign += 2)
        {
            int offset = sweep * sign;
            for (int c = 0; c < remote_candidate_count; c++) {
                struct sockaddr_storage exact_sa;
                int test_port;

                sent_count += redp2p_punch_send_candidate(udp_fd,
                    &remote_candidates[c], ping_msg, &unsupported_count);
                if (!redp2p_candidate_sockaddr(&remote_candidates[c], &exact_sa))
                    continue;
                if (exact_sa.ss_family != AF_INET) continue;
                if (remote_candidates[c].type != REDP2P_CAND_SRFLX &&
                    remote_candidates[c].type != REDP2P_CAND_PUBLIC)
                    continue;
                test_port = remote_candidates[c].port + offset;
                if (test_port <= 0 || test_port > 65535) continue;
                redp2p_sockaddr_set_port(&exact_sa, (unsigned short)test_port);
                if (redp2p_sendto_addr(udp_fd, ping_msg, strlen(ping_msg),
                    &exact_sa) >= 0)
                    sent_count++;
            }
            if (redp2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
                REDP2P_PUNCH_SWEEP_WAIT_MS, deadline_ms, selected_addr,
                &malformed_count, &mismatch_count) == REDP2P_OK)
                return REDP2P_OK;
        }
    }
    if (sent_count == 0) {
        redp2p_set_error(ctx, "punch: no valid peer candidates");
        fprintf(stderr, "redp2p: punch failed: all candidates invalid or unsupported\n");
    } else if (malformed_count > 0) {
        redp2p_set_error(ctx, "punch: malformed peer response");
        fprintf(stderr, "redp2p: punch failed: malformed peer packet\n");
    } else if (mismatch_count > 0) {
        redp2p_set_error(ctx, "punch: peer session identity mismatch");
        fprintf(stderr, "redp2p: punch failed: session mismatch\n");
    } else if (unsupported_count > 0) {
        redp2p_set_error(ctx, "punch: peer address family unsupported");
        fprintf(stderr, "redp2p: punch failed: address family mismatch\n");
    } else if (redp2p_now_ms() >= deadline_ms) {
        redp2p_set_error(ctx, "punch: direct connectivity timed out");
        fprintf(stderr, "redp2p: punch failed: timeout\n");
    } else {
        redp2p_set_error(ctx, "punch: direct connectivity attempts exhausted");
        fprintf(stderr, "redp2p: punch failed: all attempts exhausted\n");
    }
    return REDP2P_EPUNCH;
}

typedef struct {
    redp2p_t *ctx;
    redp2p_fd_t listener_fd;
    fd_set readable_fds;
    int max_fd;
    int platform_initialized;
    uint64_t last_prune;
} redp2p_index_runtime_t;

/**
 * Appends one in-flight index connection to the bounded connection table.
 * @param ctx Locked index context.
 * @param fd  Socket whose descriptor ownership transfers on success.
 * @return REDP2P_OK on success, or REDP2P_EFULL when the table is full.
 */
static int redp2p_index_conn_add(redp2p_t *ctx, redp2p_fd_t fd) {
    redp2p_index_conn_t *new_conns;
    int new_cap;

    if (ctx->n_conns >= REDP2P_MAX_CONNECTIONS) return REDP2P_EFULL;
    if (ctx->n_conns >= ctx->conns_cap) {
        new_cap = ctx->conns_cap == 0 ? 16 : ctx->conns_cap * 2;
        if (new_cap > REDP2P_MAX_CONNECTIONS) new_cap = REDP2P_MAX_CONNECTIONS;
        new_conns = (redp2p_index_conn_t *)realloc(ctx->conns,
            (size_t)new_cap * sizeof(*ctx->conns));
        if (!new_conns) return REDP2P_ERROR;
        ctx->conns = new_conns;
        ctx->conns_cap = new_cap;
    }
    memset(&ctx->conns[ctx->n_conns], 0, sizeof(ctx->conns[ctx->n_conns]));
    ctx->conns[ctx->n_conns].fd = fd;
    ctx->conns[ctx->n_conns].ts = redp2p_now_ms();
    ctx->n_conns++;
    return REDP2P_OK;
}

/**
 * Closes and removes one in-flight index connection by index.
 * @param ctx   Locked index context.
 * @param index Connection index to remove.
 * @return None.
 */
static void redp2p_index_conn_remove(redp2p_t *ctx, int index) {
    if (index < 0 || index >= ctx->n_conns) return;
    REDP2P_FD_CLOSE(ctx->conns[index].fd);
    ctx->conns[index] = ctx->conns[--ctx->n_conns];
}

/**
 * Sends one JSON index response and releases the value.
 * @param fd     Request socket.
 * @param status HTTP status code.
 * @param reason Status reason phrase.
 * @param value  JSON response value, consumed.
 * @return REDP2P_OK on success, or a negative error code.
 */
static int redp2p_index_respond(redp2p_fd_t fd, int status,
    const char *reason, JSON_Value *value)
{
    char buf[REDP2P_BUF];
    size_t size;
    int result;

    if (!value) return REDP2P_ERROR;
    size = json_serialization_size(value);
    if (size == 0 || size >= sizeof(buf)) {
        json_value_free(value);
        return REDP2P_EFULL;
    }
    if (json_serialize_to_buffer(value, buf, sizeof(buf)) != JSONSuccess) {
        json_value_free(value);
        return REDP2P_ERROR;
    }
    json_value_free(value);
    result = redp2p_http_write_response(fd, status, reason,
        "application/json", buf);
    crypto_wipe(buf, sizeof(buf));
    return result;
}

/**
 * Sends one JSON index error reply.
 * @param fd     Request socket.
 * @param status HTTP status code.
 * @param code   JSON error code.
 * @return None.
 */
static void redp2p_index_respond_error(redp2p_fd_t fd, int status,
    const char *code)
{
    const char *reason;
    JSON_Value *value;
    JSON_Object *obj;

    switch (status) {
        case 400: reason = "Bad Request"; break;
        case 403: reason = "Forbidden"; break;
        case 404: reason = "Not Found"; break;
        case 500: reason = "Internal Server Error"; break;
        case 503: reason = "Service Unavailable"; break;
        default: reason = "Error"; break;
    }
    value = json_value_init_object();
    if (!value) return;
    obj = json_value_get_object(value);
    json_object_set_boolean(obj, "ok", 0);
    json_object_set_string(obj, "error", code);
    redp2p_index_respond(fd, status, reason, value);
}

/**
 * Rejects one JSON object containing duplicate field names.
 * @param obj Request object.
 * @return 1 when every field name is unique, 0 on a duplicate.
 */
static int redp2p_index_json_unique_fields(const JSON_Object *obj) {
    size_t count;
    size_t i;
    size_t j;

    count = json_object_get_count(obj);
    for (i = 0; i < count; i++) {
        const char *name;

        name = json_object_get_name(obj, i);
        for (j = i + 1; j < count; j++) {
            if (strcmp(name, json_object_get_name(obj, j)) == 0) return 0;
        }
    }
    return 1;
}

/**
 * Extracts and validates one bounded identifier field.
 * @param obj    Request object.
 * @param field  Field name.
 * @param id     Output identifier.
 * @param id_cap Output identifier capacity.
 * @return 1 on success, 0 when missing or of the wrong type, -1 when
 *         present but invalid.
 */
static int redp2p_index_require_id(JSON_Object *obj, const char *field,
    char *id, size_t id_cap)
{
    const char *value;

    if (!json_object_has_value_of_type(obj, field, JSONString)) return 0;
    value = json_object_get_string(obj, field);
    if (!value || strlen(value) >= id_cap || !redp2p_is_valid_id(value)) return -1;
    memcpy(id, value, strlen(value) + 1);
    return 1;
}

/**
 * Requires one valid identifier or replies with the matching error code.
 * @param req    Request object.
 * @param fd     Request socket.
 * @param id     Output identifier.
 * @param id_cap Output identifier capacity.
 * @return 1 on success, 0 after replying.
 */
static int redp2p_index_require_id_response(JSON_Object *req,
    redp2p_fd_t fd, char *id, size_t id_cap)
{
    int result;

    result = redp2p_index_require_id(req, "id", id, id_cap);
    if (result <= 0) {
        redp2p_index_respond_error(fd, 400,
            result == 0 ? "bad_request" : "invalid_id");
        return 0;
    }
    return 1;
}

/**
 * Extracts and validates one fixed-width hexadecimal token field.
 * @param obj    Request object.
 * @param field  Field name.
 * @param out    Output token.
 * @param out_cap Output token capacity.
 * @param hex_len Required hex length.
 * @return 1 on success, 0 on malformed input.
 */
static int redp2p_index_require_hex(JSON_Object *obj, const char *field,
    char *out, size_t out_cap, size_t hex_len)
{
    const char *value;

    if (!json_object_has_value_of_type(obj, field, JSONString)) return 0;
    value = json_object_get_string(obj, field);
    if (!value || out_cap <= hex_len || !redp2p_is_hex_token(value, hex_len))
        return 0;
    memcpy(out, value, hex_len);
    out[hex_len] = '\0';
    return 1;
}

/**
 * Parses one bounded JSON candidate array into candidate records.
 * @param obj       Request object.
 * @param field     Array field name.
 * @param out       Output candidate array.
 * @param out_count Output candidate count.
 * @return 1 on success, 0 on malformed input.
 */
static int redp2p_index_parse_candidates(JSON_Object *obj, const char *field,
    redp2p_candidate_t *out, int *out_count)
{
    JSON_Array *array;
    size_t count;
    size_t i;

    *out_count = 0;
    if (!json_object_has_value_of_type(obj, field, JSONArray)) return 1;
    array = json_object_get_array(obj, field);
    count = json_array_get_count(array);
    if (count > REDP2P_PEER_CANDIDATES_MAX) return 0;
    for (i = 0; i < count; i++) {
        JSON_Object *item;
        const char *type_text;
        const char *addr;
        double port;
        redp2p_candidate_type_t type;
        struct in_addr ipv4;
        struct in6_addr ipv6;

        item = json_array_get_object(array, i);
        if (!item) return 0;
        type_text = json_object_get_string(item, "type");
        addr = json_object_get_string(item, "addr");
        if (!type_text || !addr || strlen(addr) > REDP2P_ADDR_MAX) return 0;
        if (!redp2p_parse_candidate_type(type_text, &type)) return 0;
        if (type != REDP2P_CAND_HOST && type != REDP2P_CAND_LAN &&
            type != REDP2P_CAND_PUBLIC && type != REDP2P_CAND_SRFLX)
            return 0;
        if (inet_pton(AF_INET, addr, &ipv4) != 1 &&
            inet_pton(AF_INET6, addr, &ipv6) != 1)
            return 0;
        if (!json_object_has_value_of_type(item, "port", JSONNumber)) return 0;
        port = json_object_get_number(item, "port");
        if (port < 1.0 || port > 65535.0) return 0;
        memset(&out[*out_count], 0, sizeof(out[*out_count]));
        out[*out_count].type = type;
        snprintf(out[*out_count].addr, sizeof(out[*out_count].addr), "%s",
            addr);
        out[*out_count].port = (unsigned short)port;
        out[*out_count].priority = redp2p_candidate_priority(
            &out[*out_count]);
        (*out_count)++;
    }
    return 1;
}

/**
 * Appends one candidate array to a JSON reply object.
 * @param obj   Reply object.
 * @param field Output array field name.
 * @param cands Candidate array.
 * @param n     Candidate count.
 * @return None.
 */
static void redp2p_index_append_candidates(JSON_Object *obj,
    const char *field, const redp2p_candidate_t *cands, int n)
{
    JSON_Value *array_value;
    JSON_Array *array;
    int i;

    array_value = json_value_init_array();
    array = json_value_get_array(array_value);
    for (i = 0; i < n; i++) {
        JSON_Value *item_value;
        JSON_Object *item;

        item_value = json_value_init_object();
        item = json_value_get_object(item_value);
        json_object_set_string(item, "type",
            redp2p_candidate_type_name(cands[i].type));
        json_object_set_string(item, "addr", cands[i].addr);
        json_object_set_number(item, "port", (double)cands[i].port);
        json_array_append_value(array, item_value);
    }
    json_object_set_value(obj, field, array_value);
}

/**
 * Handles one challenge request, issuing a stateless proof challenge.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_challenge(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char id[REDP2P_ID_MAX + 1];
    unsigned char nonce[8];
    char nonce_hex[17];
    JSON_Value *reply;
    JSON_Object *out;

    memset(nonce, 0, sizeof(nonce));
    memset(nonce_hex, 0, sizeof(nonce_hex));
    if (!redp2p_index_require_id_response(req, fd, id, sizeof(id))) return;
    if (redp2p_fill_random(nonce, sizeof(nonce)) != 0 ||
        !redp2p_hex_encode(nonce, sizeof(nonce), nonce_hex,
            sizeof(nonce_hex)))
    {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(nonce_hex, sizeof(nonce_hex));
        redp2p_index_respond_error(fd, 500, "internal");
        return;
    }
    reply = json_value_init_object();
    if (!reply) {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(nonce_hex, sizeof(nonce_hex));
        redp2p_index_respond_error(fd, 500, "internal");
        return;
    }
    out = json_value_get_object(reply);
    json_object_set_boolean(out, "ok", 1);
    json_object_set_string(out, "nonce", nonce_hex);
    json_object_set_number(out, "bits", (double)ctx->pow_bits);
    crypto_wipe(nonce, sizeof(nonce));
    crypto_wipe(nonce_hex, sizeof(nonce_hex));
    redp2p_index_respond(fd, 200, "OK", reply);
}

/**
 * Handles one register request, verifying proof of work and upserting.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_register(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char id[REDP2P_ID_MAX + 1];
    char nonce[17];
    char solution[17];
    char proof[65];
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    const char *pass;
    double proto;
    double udp_port;
    int n_candidates;
    int add_result;

    memset(nonce, 0, sizeof(nonce));
    memset(solution, 0, sizeof(solution));
    memset(proof, 0, sizeof(proof));
    if (!redp2p_index_require_id_response(req, fd, id, sizeof(id))) {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(solution, sizeof(solution));
        crypto_wipe(proof, sizeof(proof));
        return;
    }
    if (!redp2p_index_require_hex(req, "nonce", nonce, sizeof(nonce), 16) ||
        !redp2p_index_require_hex(req, "solution", solution, sizeof(solution),
            8) ||
        !redp2p_index_require_hex(req, "proof", proof, sizeof(proof), 64))
    {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(solution, sizeof(solution));
        crypto_wipe(proof, sizeof(proof));
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    if (!json_object_has_value_of_type(req, "proto", JSONNumber) ||
        !json_object_has_value_of_type(req, "udp_port", JSONNumber))
    {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(solution, sizeof(solution));
        crypto_wipe(proof, sizeof(proof));
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    proto = json_object_get_number(req, "proto");
    udp_port = json_object_get_number(req, "udp_port");
    if ((proto != REDP2P_PROTO_TCP && proto != REDP2P_PROTO_UDP) ||
        udp_port < 1.0 || udp_port > 65535.0 ||
        !redp2p_index_parse_candidates(req, "candidates", candidates,
            &n_candidates))
    {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(solution, sizeof(solution));
        crypto_wipe(proof, sizeof(proof));
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    pass = redp2p_get_register_pass(ctx, id);
    if (!redp2p_verify_register_pow(pass, nonce, id, solution, proof,
        ctx->pow_bits))
    {
        crypto_wipe(nonce, sizeof(nonce));
        crypto_wipe(solution, sizeof(solution));
        crypto_wipe(proof, sizeof(proof));
        redp2p_index_respond_error(fd, 403, "auth_failed");
        return;
    }
    redp2p_evict_stale(ctx);
    add_result = redp2p_add_peer(ctx, id);
    if (add_result == REDP2P_OK) {
        size_t peer_index;

        peer_index = redp2p_find_peer(ctx, id);
        if (peer_index != SIZE_MAX) {
            JSON_Value *reply;
            JSON_Object *out;

            ctx->peers[peer_index].proto = (int)proto;
            ctx->peers[peer_index].udp_port = (unsigned short)udp_port;
            ctx->peers[peer_index].n_candidates = n_candidates;
            if (n_candidates > 0) {
                memcpy(ctx->peers[peer_index].candidates, candidates,
                    (size_t)n_candidates * sizeof(candidates[0]));
            }
            ctx->peers[peer_index].last_seen = redp2p_now_s();
            reply = json_value_init_object();
            if (!reply) {
                crypto_wipe(nonce, sizeof(nonce));
                crypto_wipe(solution, sizeof(solution));
                crypto_wipe(proof, sizeof(proof));
                redp2p_index_respond_error(fd, 500, "internal");
                return;
            }
            out = json_value_get_object(reply);
            json_object_set_boolean(out, "ok", 1);
            json_object_set_string(out, "key",
                ctx->peers[peer_index].key);
            crypto_wipe(nonce, sizeof(nonce));
            crypto_wipe(solution, sizeof(solution));
            crypto_wipe(proof, sizeof(proof));
            redp2p_index_respond(fd, 200, "OK", reply);
            return;
        }
        redp2p_remove_peer(ctx, id);
        redp2p_index_respond_error(fd, 500, "internal");
    } else if (add_result == REDP2P_EFULL) {
        redp2p_index_respond_error(fd, 503, "table_full");
    } else {
        redp2p_index_respond_error(fd, 500, "internal");
    }
    crypto_wipe(nonce, sizeof(nonce));
    crypto_wipe(solution, sizeof(solution));
    crypto_wipe(proof, sizeof(proof));
}

/**
 * Handles one heartbeat request, authenticating with the key only.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_heartbeat(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char id[REDP2P_ID_MAX + 1];
    char key[REDP2P_KEY_STR_SZ];
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    double proto;
    double udp_port;
    int n_candidates;
    size_t peer_index;

    memset(key, 0, sizeof(key));
    if (!redp2p_index_require_id_response(req, fd, id, sizeof(id))) {
        crypto_wipe(key, sizeof(key));
        return;
    }
    if (!redp2p_index_require_hex(req, "key", key, sizeof(key),
        REDP2P_KEY_SZ) ||
        !json_object_has_value_of_type(req, "proto", JSONNumber) ||
        !json_object_has_value_of_type(req, "udp_port", JSONNumber))
    {
        crypto_wipe(key, sizeof(key));
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    proto = json_object_get_number(req, "proto");
    udp_port = json_object_get_number(req, "udp_port");
    if ((proto != REDP2P_PROTO_TCP && proto != REDP2P_PROTO_UDP) ||
        udp_port < 1.0 || udp_port > 65535.0 ||
        !redp2p_index_parse_candidates(req, "candidates", candidates,
            &n_candidates))
    {
        crypto_wipe(key, sizeof(key));
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    redp2p_evict_stale(ctx);
    peer_index = redp2p_find_peer(ctx, id);
    if (peer_index == SIZE_MAX) {
        crypto_wipe(key, sizeof(key));
        redp2p_index_respond_error(fd, 404, "not_found");
        return;
    }
    if (strcmp(ctx->peers[peer_index].key, key) != 0) {
        crypto_wipe(key, sizeof(key));
        redp2p_index_respond_error(fd, 403, "invalid_key");
        return;
    }
    ctx->peers[peer_index].proto = (int)proto;
    ctx->peers[peer_index].udp_port = (unsigned short)udp_port;
    ctx->peers[peer_index].n_candidates = n_candidates;
    if (n_candidates > 0) {
        memcpy(ctx->peers[peer_index].candidates, candidates,
            (size_t)n_candidates * sizeof(candidates[0]));
    }
    ctx->peers[peer_index].last_seen = redp2p_now_s();
    crypto_wipe(key, sizeof(key));
    {
        JSON_Value *reply;
        JSON_Object *out;

        reply = json_value_init_object();
        if (!reply) {
            redp2p_index_respond_error(fd, 500, "internal");
            return;
        }
        out = json_value_get_object(reply);
        json_object_set_boolean(out, "ok", 1);
        redp2p_index_respond(fd, 200, "OK", reply);
    }
}

/**
 * Handles one lookup request, filtering expired records without writing.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_lookup(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char id[REDP2P_ID_MAX + 1];
    size_t peer_index;

    if (!redp2p_index_require_id_response(req, fd, id, sizeof(id))) return;
    peer_index = redp2p_find_peer(ctx, id);
    if (peer_index == SIZE_MAX || redp2p_peer_is_stale(ctx, peer_index)) {
        redp2p_index_respond_error(fd, 404, "not_found");
        return;
    }
    {
        JSON_Value *reply;
        JSON_Object *out;

        reply = json_value_init_object();
        if (!reply) {
            redp2p_index_respond_error(fd, 500, "internal");
            return;
        }
        out = json_value_get_object(reply);
        json_object_set_boolean(out, "ok", 1);
        json_object_set_string(out, "id", ctx->peers[peer_index].id);
        json_object_set_number(out, "proto",
            (double)ctx->peers[peer_index].proto);
        json_object_set_number(out, "udp_port",
            (double)ctx->peers[peer_index].udp_port);
        redp2p_index_append_candidates(out, "candidates",
            ctx->peers[peer_index].candidates,
            ctx->peers[peer_index].n_candidates);
        json_object_set_number(out, "last_seen",
            (double)ctx->peers[peer_index].last_seen);
        redp2p_index_respond(fd, 200, "OK", reply);
    }
}

/**
 * Handles one list request, returning non-expired publisher identifiers.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_list(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    JSON_Value *reply;
    JSON_Object *out;
    JSON_Value *array_value;
    JSON_Array *array;
    size_t i;

    (void)req;
    reply = json_value_init_object();
    if (!reply) {
        redp2p_index_respond_error(fd, 500, "internal");
        return;
    }
    out = json_value_get_object(reply);
    array_value = json_value_init_array();
    array = json_value_get_array(array_value);
    for (i = 0; i < ctx->n_peers; i++) {
        if (!redp2p_peer_is_stale(ctx, i))
            json_array_append_string(array, ctx->peers[i].id);
    }
    json_object_set_value(out, "ids", array_value);
    json_object_set_boolean(out, "ok", 1);
    redp2p_index_respond(fd, 200, "OK", reply);
}

/**
 * Handles one deregister request, requiring the stored registration key.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_deregister(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char id[REDP2P_ID_MAX + 1];
    char key[REDP2P_KEY_STR_SZ];
    size_t peer_index;

    memset(key, 0, sizeof(key));
    if (!redp2p_index_require_id_response(req, fd, id, sizeof(id))) {
        crypto_wipe(key, sizeof(key));
        return;
    }
    if (!redp2p_index_require_hex(req, "key", key, sizeof(key),
        REDP2P_KEY_SZ))
    {
        crypto_wipe(key, sizeof(key));
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    redp2p_evict_stale(ctx);
    peer_index = redp2p_find_peer(ctx, id);
    if (peer_index == SIZE_MAX ||
        strcmp(ctx->peers[peer_index].key, key) != 0)
    {
        crypto_wipe(key, sizeof(key));
        redp2p_index_respond_error(fd, 403, "invalid_key");
        return;
    }
    redp2p_remove_peer(ctx, id);
    crypto_wipe(key, sizeof(key));
    {
        JSON_Value *reply;
        JSON_Object *out;

        reply = json_value_init_object();
        if (!reply) {
            redp2p_index_respond_error(fd, 500, "internal");
            return;
        }
        out = json_value_get_object(reply);
        json_object_set_boolean(out, "ok", 1);
        redp2p_index_respond(fd, 200, "OK", reply);
    }
}

/**
 * Handles one prune request, physically removing expired records.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_punch_req(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char self_id[REDP2P_ID_MAX + 1];
    char target_id[REDP2P_ID_MAX + 1];
    char session[REDP2P_CTRL_SESSION_MAX + 1];
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    const char *session_str;
    int n_candidates;

    int self_result;
    int target_result;

    self_result = redp2p_index_require_id(req, "self_id", self_id,
        sizeof(self_id));
    target_result = redp2p_index_require_id(req, "target_id", target_id,
        sizeof(target_id));
    if (self_result == 0 || target_result == 0) {
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    if (self_result < 0 || target_result < 0) {
        redp2p_index_respond_error(fd, 400, "invalid_id");
        return;
    }
    if (!json_object_has_value_of_type(req, "session", JSONString)) {
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    session_str = json_object_get_string(req, "session");
    if (!session_str || strlen(session_str) >= sizeof(session) ||
        !redp2p_is_session_token(session_str) ||
        !redp2p_index_parse_candidates(req, "candidates", candidates,
            &n_candidates))
    {
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    memcpy(session, session_str, strlen(session_str) + 1);
    redp2p_pending_call_evict_stale(ctx);
    if (!redp2p_pending_call_add(ctx, self_id, target_id, session, candidates,
        n_candidates))
    {
        redp2p_index_respond_error(fd, 503, "busy");
        return;
    }
    {
        JSON_Value *reply;
        JSON_Object *out;

        reply = json_value_init_object();
        if (!reply) {
            redp2p_index_respond_error(fd, 500, "internal");
            return;
        }
        out = json_value_get_object(reply);
        json_object_set_boolean(out, "ok", 1);
        redp2p_index_respond(fd, 200, "OK", reply);
    }
}

/**
 * Handles one punch_poll request, returning and consuming pending calls.
 * @param ctx Locked index context.
 * @param fd  Request socket.
 * @param req Request JSON object.
 * @return None.
 */
static void redp2p_index_handle_punch_poll(redp2p_t *ctx, redp2p_fd_t fd,
    JSON_Object *req)
{
    char id[REDP2P_ID_MAX + 1];
    redp2p_pending_call_t calls[REDP2P_MAX_PENDING_CALLS];
    JSON_Value *reply;
    JSON_Object *out;
    JSON_Value *array_value;
    JSON_Array *array;
    int n_calls;
    int i;

    if (!redp2p_index_require_id_response(req, fd, id, sizeof(id))) return;
    redp2p_pending_call_evict_stale(ctx);
    redp2p_pending_call_take_all(ctx, id, calls, &n_calls);
    reply = json_value_init_object();
    if (!reply) {
        redp2p_index_respond_error(fd, 500, "internal");
        return;
    }
    out = json_value_get_object(reply);
    array_value = json_value_init_array();
    array = json_value_get_array(array_value);
    for (i = 0; i < n_calls; i++) {
        JSON_Value *call_value;
        JSON_Object *call;

        call_value = json_value_init_object();
        call = json_value_get_object(call_value);
        json_object_set_string(call, "self_id", calls[i].caller_id);
        json_object_set_string(call, "session", calls[i].sess_id);
        redp2p_index_append_candidates(call, "candidates",
            calls[i].candidates, calls[i].n_candidates);
        json_array_append_value(array, call_value);
    }
    json_object_set_value(out, "calls", array_value);
    json_object_set_boolean(out, "ok", 1);
    redp2p_index_respond(fd, 200, "OK", reply);
}

/**
 * Dispatches one complete HTTP request to its JSON index operation handler.
 * @param ctx  Locked index context.
 * @param fd   Request socket.
 * @param path Request path, ignored by the single-endpoint dispatch.
 * @param body Request body.
 * @return None.
 */
static void redp2p_index_dispatch(redp2p_t *ctx, redp2p_fd_t fd,
    const char *path, const char *body)
{
    JSON_Value *value;
    JSON_Object *req;
    const char *op;

    (void)path;
    value = json_parse_string(body);
    if (!value) {
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    if (json_value_get_type(value) != JSONObject) {
        json_value_free(value);
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    req = json_value_get_object(value);
    if (!redp2p_index_json_unique_fields(req)) {
        json_value_free(value);
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    if (!json_object_has_value_of_type(req, "op", JSONString)) {
        json_value_free(value);
        redp2p_index_respond_error(fd, 400, "bad_request");
        return;
    }
    op = json_object_get_string(req, "op");
    if (strcmp(op, "challenge") == 0)
        redp2p_index_handle_challenge(ctx, fd, req);
    else if (strcmp(op, "register") == 0)
        redp2p_index_handle_register(ctx, fd, req);
    else if (strcmp(op, "heartbeat") == 0)
        redp2p_index_handle_heartbeat(ctx, fd, req);
    else if (strcmp(op, "lookup") == 0)
        redp2p_index_handle_lookup(ctx, fd, req);
    else if (strcmp(op, "list") == 0)
        redp2p_index_handle_list(ctx, fd, req);
    else if (strcmp(op, "deregister") == 0)
        redp2p_index_handle_deregister(ctx, fd, req);
    else if (strcmp(op, "punch_req") == 0)
        redp2p_index_handle_punch_req(ctx, fd, req);
    else if (strcmp(op, "punch_poll") == 0)
        redp2p_index_handle_punch_poll(ctx, fd, req);
    else
        redp2p_index_respond_error(fd, 400, "bad_request");
    json_value_free(value);
}

/**
 * Scans one buffered HTTP request and reports whether it is complete.
 * @param ctx           Locked index context.
 * @param conn          In-flight request connection.
 * @param method        Output HTTP method.
 * @param method_cap    Method buffer capacity.
 * @param path          Output request path.
 * @param path_cap      Path buffer capacity.
 * @param body          Output request body, nul-terminated.
 * @param body_cap      Body buffer capacity.
 * @param http_status_out Optional HTTP status to reply on failure; 0 when the
 *                        request is complete, 1 when more input is needed.
 * @return 1 when the request is complete, 0 when more input is needed or on
 * a protocol violation (http_status_out set to a reply status).
 */
static int redp2p_index_request_parse(redp2p_index_conn_t *conn,
    char *method, int method_cap, char *path, int path_cap, char *body,
    int body_cap, int *http_status_out)
{
    char *header_end;
    char *line;
    const char *cursor;
    long content_length;
    int has_transfer_encoding;

    if (http_status_out) *http_status_out = 0;
    if (conn->buf_len <= 0) return 0;
    if (conn->buf_len >= (int)sizeof(conn->buf) - 1) {
        if (http_status_out) *http_status_out = 431;
        return 1;
    }
    conn->buf[conn->buf_len] = '\0';
    header_end = strstr(conn->buf, "\r\n\r\n");
    if (!header_end) {
        if (conn->buf_len >= REDP2P_HTTP_LINE_MAX * REDP2P_HTTP_HEADERS_MAX) {
            if (http_status_out) *http_status_out = 431;
            return 1;
        }
        return 0;
    }
    line = conn->buf;
    cursor = line;
    if (!redp2p_parse_field(&cursor, method, (size_t)method_cap, ' '))
        goto malformed;
    if (strcmp(method, "POST") != 0) {
        if (http_status_out) *http_status_out = 405;
        return 1;
    }
    if (!redp2p_parse_field(&cursor, path, (size_t)path_cap, ' '))
        goto malformed;
    if (strncmp(cursor, "HTTP/1.1", 8) != 0 &&
        strncmp(cursor, "HTTP/1.0", 8) != 0)
        goto malformed;
    content_length = -1;
    has_transfer_encoding = 0;
    cursor = strstr(line, "\r\n");
    if (!cursor) goto malformed;
    cursor += 2;
    while (cursor < header_end) {
        char *nl;
        char hline[REDP2P_HTTP_LINE_MAX];
        char *colon;
        size_t len;

        nl = strchr(cursor, '\n');
        if (!nl) break;
        len = (size_t)(nl - cursor);
        if (len == 1 && cursor[0] == '\r') break;
        if (len >= sizeof(hline)) goto malformed;
        memcpy(hline, cursor, len);
        hline[len] = '\0';
        if (len > 0 && hline[len - 1] == '\r') hline[len - 1] = '\0';
        colon = strchr(hline, ':');
        if (colon) {
            const char *value;
            char name[32];

            if ((size_t)(colon - hline) >= sizeof(name)) goto malformed;
            memcpy(name, hline, (size_t)(colon - hline));
            name[colon - hline] = '\0';
            value = colon + 1;
            while (*value == ' ' || *value == '\t') value++;
            if (redp2p_ascii_casecmp(name, "Content-Length") == 0) {
                if (!redp2p_parse_u(value, 0, body_cap - 1, &content_length))
                    goto malformed;
            } else if (redp2p_ascii_casecmp(name, "Transfer-Encoding") == 0) {
                has_transfer_encoding = 1;
            }
        }
        cursor = nl + 1;
    }
    if (has_transfer_encoding) {
        if (http_status_out) *http_status_out = 501;
        return 1;
    }
    if (content_length < 0) content_length = 0;
    if (content_length > body_cap - 1) {
        if (http_status_out) *http_status_out = 413;
        return 1;
    }
    if (conn->buf_len < (int)(header_end - conn->buf) + 4 + (int)content_length)
        return 0;
    if (content_length > 0) {
        memcpy(body, header_end + 4, (size_t)content_length);
    }
    body[content_length] = '\0';
    if (http_status_out) *http_status_out = 0;
    return 1;
malformed:
    if (http_status_out) *http_status_out = 400;
    return 1;
}

/**
 * Opens the index listener and records its owned runtime resources.
 * @param runtime Runtime receiving the listener and context reference.
 * @param ctx Index context.
 * @param host Listener host or NULL for the wildcard address.
 * @param port Listener port.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_index_runtime_initialize(
    redp2p_index_runtime_t *runtime,
    redp2p_t *ctx,
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
    runtime->listener_fd = REDP2P_FD_INVALID;
    runtime->last_prune = redp2p_now_s();
    if (redp2p_platform_init() != 0) {
        redp2p_set_error(ctx, "index: platform init failed");
        return REDP2P_ENET;
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
        redp2p_set_error(ctx, "index: resolve %s:%u failed (%s)",
            host ? host : "*", (unsigned)port, gai_strerror(result));
        redp2p_platform_cleanup();
        runtime->platform_initialized = 0;
        return REDP2P_ENET;
    }
    for (address = addresses; address; address = address->ai_next) {
        int reuse;

        runtime->listener_fd = socket(address->ai_family,
            address->ai_socktype, address->ai_protocol);
        if (REDP2P_ISERR(runtime->listener_fd)) continue;
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
        REDP2P_FD_CLOSE(runtime->listener_fd);
        runtime->listener_fd = REDP2P_FD_INVALID;
    }
    freeaddrinfo(addresses);
    if (REDP2P_ISERR(runtime->listener_fd)) {
        redp2p_set_error(ctx, "index: bind/listen %s:%u failed",
            host ? host : "*", (unsigned)port);
        redp2p_platform_cleanup();
        runtime->platform_initialized = 0;
        return REDP2P_ENET;
    }
    redp2p_set_nonblock(runtime->listener_fd);
    return REDP2P_OK;
}

/**
 * Builds the next readable descriptor set and evicts expired state.
 * @param runtime Initialized index runtime.
 * @return REDP2P_OK when ready, or REDP2P_ENET on failure.
 */
static int redp2p_index_prepare_fdset(redp2p_index_runtime_t *runtime) {
    redp2p_t *ctx;
    int i;

    ctx = runtime->ctx;
    FD_ZERO(&runtime->readable_fds);
    runtime->max_fd = -1;
    if (!redp2p_fdset_add(runtime->listener_fd, &runtime->readable_fds,
        &runtime->max_fd))
    {
        redp2p_set_error(ctx,
            "index: listener cannot be represented by fd_set");
        return REDP2P_ENET;
    }
    redp2p_lock(ctx);
    redp2p_pending_call_evict_stale(ctx);
    for (i = ctx->n_conns - 1; i >= 0; i--) {
        if (!redp2p_fdset_add(ctx->conns[i].fd, &runtime->readable_fds,
            &runtime->max_fd))
        {
            redp2p_set_error(ctx,
                "index: client descriptor cannot be represented by fd_set");
            redp2p_index_conn_remove(ctx, i);
        }
    }
    redp2p_unlock(ctx);
    return REDP2P_OK;
}

/**
 * Accepts at most one ready index client and transfers descriptor ownership.
 * @param runtime Initialized index runtime with a selected listener.
 * @return None.
 */
static void redp2p_index_accept_connection(redp2p_index_runtime_t *runtime) {
    struct sockaddr_storage client_address;
    socklen_t client_address_length;
    redp2p_fd_t client_fd;

    if (!FD_ISSET(runtime->listener_fd, &runtime->readable_fds)) return;
    client_address_length = sizeof(client_address);
    client_fd = accept(runtime->listener_fd,
        (struct sockaddr *)&client_address, &client_address_length);
    if (REDP2P_ISERR(client_fd)) return;
    redp2p_set_nonblock(client_fd);
    redp2p_lock(runtime->ctx);
    if (redp2p_index_conn_add(runtime->ctx, client_fd) != REDP2P_OK)
        REDP2P_FD_CLOSE(client_fd);
    redp2p_unlock(runtime->ctx);
}

/**
 * Processes readable client connections in reverse table order.
 * @param runtime Initialized index runtime with selected descriptors.
 * @return None.
 */
static void redp2p_index_process_connections(redp2p_index_runtime_t *runtime) {
    redp2p_t *ctx;
    int i;

    ctx = runtime->ctx;
    for (i = ctx->n_conns - 1; i >= 0; i--) {
        char method[16];
        char path[128];
        char body[REDP2P_HTTP_BODY_MAX + 1];
        int http_status;
        int nread;

        if (ctx->conns[i].buf_len > 0 &&
            redp2p_now_ms() - ctx->conns[i].ts > REDP2P_HTTP_TIMEOUT_S * 1000u)
        {
            redp2p_lock(ctx);
            redp2p_index_conn_remove(ctx, i);
            redp2p_unlock(ctx);
            continue;
        }
        if (!FD_ISSET(ctx->conns[i].fd, &runtime->readable_fds)) continue;
        nread = redp2p_sock_read(ctx->conns[i].fd,
            ctx->conns[i].buf + ctx->conns[i].buf_len,
            (int)sizeof(ctx->conns[i].buf) - 1 - ctx->conns[i].buf_len);
        if (nread <= 0) {
            redp2p_lock(ctx);
            redp2p_index_conn_remove(ctx, i);
            redp2p_unlock(ctx);
            continue;
        }
        ctx->conns[i].buf_len += nread;
        ctx->conns[i].buf[ctx->conns[i].buf_len] = '\0';
        method[0] = '\0';
        path[0] = '\0';
        body[0] = '\0';
        http_status = 0;
        redp2p_lock(ctx);
        if (redp2p_index_request_parse(&ctx->conns[i], method,
            (int)sizeof(method), path, (int)sizeof(path), body,
            (int)sizeof(body), &http_status))
        {
            if (http_status == 0) {
                redp2p_index_dispatch(ctx, ctx->conns[i].fd, path, body);
            } else {
                redp2p_http_write_response(ctx->conns[i].fd, http_status,
                    http_status == 413 ? "Payload Too Large" :
                    (http_status == 405 ? "Method Not Allowed" :
                    (http_status == 501 ? "Not Implemented" :
                    (http_status == 431 ? "Request Header Fields Too Large" :
                    "Bad Request"))),
                    "text/plain", REDP2P_CTRTOK_ERROR_MALFORMED);
            }
            redp2p_index_conn_remove(ctx, i);
        }
        redp2p_unlock(ctx);
    }
}

/**
 * Runs the blocking select loop until stop or a descriptor-set failure.
 * @param runtime Initialized index runtime.
 * @return REDP2P_OK on requested stop, or REDP2P_ENET on fd-set failure.
 */
static int redp2p_index_event_loop(redp2p_index_runtime_t *runtime) {
    struct timeval timeout;
    int ready_count;
    int result;

    for (;;) {
        if (runtime->ctx->stop_requested) {
            fprintf(stderr, "redp2p: shutdown requested\n");
            break;
        }
        result = redp2p_index_prepare_fdset(runtime);
        if (result != REDP2P_OK) return result;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        ready_count = select(runtime->max_fd + 1, &runtime->readable_fds,
            NULL, NULL, &timeout);
        if (ready_count < 0) {
            if (runtime->ctx->stop_requested) break;
            continue;
        }
        if (ready_count == 0) {
            uint64_t now = redp2p_now_s();
            if (now - runtime->last_prune >= runtime->ctx->prune_interval_s) {
                redp2p_lock(runtime->ctx);
                redp2p_evict_stale(runtime->ctx);
                redp2p_unlock(runtime->ctx);
                runtime->last_prune = now;
            }
            continue;
        }
        redp2p_index_accept_connection(runtime);
        redp2p_index_process_connections(runtime);
    }
    return REDP2P_OK;
}

/**
 * Releases all index-owned connections, listener, and platform state.
 * @param runtime Initialized index runtime.
 * @return None.
 */
static void redp2p_index_runtime_cleanup(redp2p_index_runtime_t *runtime) {
    int i;

    redp2p_lock(runtime->ctx);
    for (i = runtime->ctx->n_conns - 1; i >= 0; i--)
        redp2p_index_conn_remove(runtime->ctx, i);
    redp2p_unlock(runtime->ctx);
    if (!REDP2P_ISERR(runtime->listener_fd))
        REDP2P_FD_CLOSE(runtime->listener_fd);
    runtime->listener_fd = REDP2P_FD_INVALID;
    if (runtime->platform_initialized) redp2p_platform_cleanup();
    runtime->platform_initialized = 0;
    atomic_store(&runtime->ctx->stop_requested, 0);
}

/**
 * Serves the blocking request-driven index lifecycle.
 * @param ctx Index context.
 * @param host Listener host or NULL for the wildcard address.
 * @param port Listener port.
 * @return REDP2P_OK on requested stop, or a negative error code on failure.
 */
int redp2p_serve_index(
    redp2p_t *ctx,
    const char *host,
    unsigned short port)
{
    redp2p_index_runtime_t runtime;
    int result;

    if (!ctx) return REDP2P_EINVAL;
    redp2p_set_error(ctx, NULL);
    if (redp2p_is_stop_requested(ctx)) {
        atomic_store(&ctx->stop_requested, 0);
        return REDP2P_OK;
    }
    if (port == 0) {
        redp2p_set_error(ctx, "index: port must be between 1 and 65535");
        return REDP2P_EINVAL;
    }
    result = redp2p_index_runtime_initialize(&runtime, ctx, host, port);
    if (result != REDP2P_OK) return result;
    fprintf(stderr, "redp2p: index server listening on %s:%u\n",
        host ? host : "*", (unsigned)port);
    result = redp2p_index_event_loop(&runtime);
    redp2p_index_runtime_cleanup(&runtime);
    return result == REDP2P_OK ? REDP2P_OK : result;
}

typedef struct {
    char dir[768];
    char scoped[848];
    char legacy[848];
} redp2p_key_paths_t;

/**
 * Serializes access to persisted registration keys within this process.
 * @return None.
 */
static void redp2p_key_lock(void) {
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
static void redp2p_key_unlock(void) {
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
static void redp2p_key_scope_hash(const char *index_host,
    unsigned short index_port, const char *id, unsigned char out[32])
{
    static const unsigned char domain[] = "redp2p-key-v1";
    redp2p_sha256_t hash;
    unsigned char digest[32];
    unsigned char port[2];

    port[0] = (unsigned char)(index_port >> 8);
    port[1] = (unsigned char)index_port;
    redp2p_sha256_init(&hash);
    redp2p_sha256_update(&hash, domain, sizeof(domain));
    redp2p_sha256_update(&hash, (const unsigned char *)index_host,
        strlen(index_host) + 1);
    redp2p_sha256_update(&hash, port, sizeof(port));
    redp2p_sha256_update(&hash, (const unsigned char *)id, strlen(id) + 1);
    redp2p_sha256_final(&hash, digest);
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
 * @return REDP2P_OK on success or REDP2P_ERROR for invalid HOME/path length.
 */
static int redp2p_key_paths(redp2p_t *ctx, const char *index_host,
    unsigned short index_port, const char *id, redp2p_key_paths_t *paths)
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
        redp2p_set_error(ctx, "key: HOME is missing or empty");
        return REDP2P_ERROR;
    }
    n = snprintf(paths->dir, sizeof(paths->dir),
        "%s/.local/share/redp2p/keys", home);
    if (n < 0 || (size_t)n >= sizeof(paths->dir)) {
        redp2p_set_error(ctx, "key: HOME path is too long");
        return REDP2P_ERROR;
    }
    redp2p_key_scope_hash(index_host, index_port, id, digest);
    if (!redp2p_hex_encode(digest, sizeof(digest), filename,
        sizeof(filename)))
    {
        redp2p_set_error(ctx, "key: scope encoding failed");
        crypto_wipe(digest, sizeof(digest));
        crypto_wipe(filename, sizeof(filename));
        return REDP2P_ERROR;
    }
    n = snprintf(paths->scoped, sizeof(paths->scoped), "%s/%s",
        paths->dir, filename);
    if (n < 0 || (size_t)n >= sizeof(paths->scoped)) {
        redp2p_set_error(ctx, "key: scoped path is too long");
        crypto_wipe(digest, sizeof(digest));
        crypto_wipe(filename, sizeof(filename));
        return REDP2P_ERROR;
    }
    n = snprintf(paths->legacy, sizeof(paths->legacy), "%s/%s",
        paths->dir, id);
    if (n < 0 || (size_t)n >= sizeof(paths->legacy)) {
        redp2p_set_error(ctx, "key: legacy path is too long");
        crypto_wipe(digest, sizeof(digest));
        crypto_wipe(filename, sizeof(filename));
        return REDP2P_ERROR;
    }
    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(filename, sizeof(filename));
    return REDP2P_OK;
}

/**
 * Creates a directory hierarchy and rejects non-directory collisions.
 * @param path Mutable directory path.
 * @return 0 on success or -1 on failure with errno set where available.
 */
static int redp2p_mkdir_p(char *path) {
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
static int redp2p_key_parse(const char *data, size_t len,
    char key[REDP2P_KEY_STR_SZ])
{
    size_t i;

    if (len == REDP2P_KEY_SZ + 1 && data[len - 1] == '\n') len--;
    else if (len == REDP2P_KEY_SZ + 2 && data[len - 2] == '\r' &&
        data[len - 1] == '\n')
        len -= 2;
    if (len != REDP2P_KEY_SZ) return 0;
    for (i = 0; i < len; i++) {
        if (redp2p_hex_decode_nibble(data[i]) < 0) return 0;
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
 * @return REDP2P_OK, REDP2P_ENOENT, or REDP2P_ERROR.
 */
static int redp2p_load_key_windows(
redp2p_t *ctx,
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
            return REDP2P_ENOENT;
        redp2p_set_error(ctx, "key: cannot open persisted key (%lu)",
            (unsigned long)GetLastError());
        return REDP2P_ERROR;
    }
    if (!GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        redp2p_set_error(ctx, "key: persisted key is not a regular file");
        CloseHandle(file);
        return REDP2P_ERROR;
    }
    *total = 0;
    while (*total < capacity) {
        if (!ReadFile(file, data + *total, (DWORD)(capacity - *total),
            &got, NULL))
        {
            redp2p_set_error(ctx, "key: persisted key read failed (%lu)",
                (unsigned long)GetLastError());
            CloseHandle(file);
            return REDP2P_ERROR;
        }
        if (got == 0) break;
        *total += got;
    }
    if (!CloseHandle(file)) {
        redp2p_set_error(ctx, "key: persisted key close failed");
        return REDP2P_ERROR;
    }
    return REDP2P_OK;
}
#else
/**
 * Reads one POSIX key file without following symbolic links when supported.
 * @param ctx Context receiving error detail.
 * @param path Exact path to load.
 * @param data Output file bytes.
 * @param capacity Output buffer capacity.
 * @param total Output byte count.
 * @return REDP2P_OK, REDP2P_ENOENT, REDP2P_EPROTO, or REDP2P_ERROR.
 */
static int redp2p_load_key_posix(
redp2p_t *ctx,
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
        if (errno == ENOENT) return REDP2P_ENOENT;
        redp2p_set_error(ctx, "key: cannot open persisted key: %s",
            strerror(errno));
        return REDP2P_ERROR;
    }
    if (fstat(fd, &status) != 0) {
        redp2p_set_error(ctx, "key: cannot inspect persisted key: %s",
            strerror(errno));
        close(fd);
        return REDP2P_ERROR;
    }
    if (!S_ISREG(status.st_mode)) {
        redp2p_set_error(ctx, "key: persisted key is not a regular file");
        close(fd);
        return REDP2P_ERROR;
    }
    if (status.st_size < REDP2P_KEY_SZ ||
        status.st_size > REDP2P_KEY_SZ + 2)
    {
        redp2p_set_error(ctx, "key: persisted key has unexpected size");
        close(fd);
        return REDP2P_EPROTO;
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
            redp2p_set_error(ctx, "key: persisted key read failed: %s",
                strerror(errno));
            close(fd);
            return REDP2P_ERROR;
        }
        break;
    }
    if (close(fd) != 0) {
        redp2p_set_error(ctx, "key: persisted key close failed: %s",
            strerror(errno));
        return REDP2P_ERROR;
    }
    return REDP2P_OK;
}
#endif

/**
 * Loads and strictly validates one registration key path.
 * @param ctx Context receiving error detail.
 * @param path Exact path to load.
 * @param key Output key.
 * @return REDP2P_OK, REDP2P_ENOENT, REDP2P_EPROTO, or REDP2P_ERROR.
 */
static int redp2p_load_key_path(redp2p_t *ctx, const char *path,
    char key[REDP2P_KEY_STR_SZ])
{
    char data[REDP2P_KEY_SZ + 3];
    size_t total;
    int result;

#ifdef _WIN32
    result = redp2p_load_key_windows(ctx, path, data, sizeof(data), &total);
#else
    result = redp2p_load_key_posix(ctx, path, data, sizeof(data), &total);
#endif
    if (result != REDP2P_OK) {
        crypto_wipe(data, sizeof(data));
        return result;
    }
    if (!redp2p_key_parse(data, total, key)) {
        redp2p_set_error(ctx, "key: persisted key is malformed");
        crypto_wipe(data, sizeof(data));
        return REDP2P_EPROTO;
    }
    crypto_wipe(data, sizeof(data));
    return REDP2P_OK;
}

#ifdef _WIN32
/**
 * Durably replaces one Windows key file through a private temporary file.
 * @param ctx Context receiving error detail.
 * @param paths Scoped key paths.
 * @param temp Temporary key path.
 * @param content Complete key file content.
 * @param total Content byte count.
 * @return REDP2P_OK on replacement or REDP2P_ERROR on failure.
 */
static int redp2p_save_key_windows(
redp2p_t *ctx,
const redp2p_key_paths_t *paths,
const char *temp,
const char *content,
size_t total)
{
    HANDLE file;
    DWORD written;
    size_t offset;
    int result;

    result = REDP2P_ERROR;
    file = CreateFileA(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        redp2p_set_error(ctx, "key: temporary key create failed (%lu)",
            (unsigned long)GetLastError());
    } else {
        offset = 0;
        while (offset < total && WriteFile(file, content + offset,
            (DWORD)(total - offset), &written, NULL) && written > 0)
            offset += written;
        if (offset != total || !FlushFileBuffers(file)) {
            redp2p_set_error(ctx, "key: temporary key write failed (%lu)",
                (unsigned long)GetLastError());
        } else if (!CloseHandle(file)) {
            file = INVALID_HANDLE_VALUE;
            redp2p_set_error(ctx, "key: temporary key close failed");
        } else {
            file = INVALID_HANDLE_VALUE;
            if (MoveFileExA(temp, paths->scoped,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                result = REDP2P_OK;
            else
                redp2p_set_error(ctx, "key: atomic replacement failed (%lu)",
                    (unsigned long)GetLastError());
        }
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    if (result != REDP2P_OK) DeleteFileA(temp);
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
 * @return REDP2P_OK on replacement or REDP2P_ERROR on failure.
 */
static int redp2p_save_key_posix(
redp2p_t *ctx,
const redp2p_key_paths_t *paths,
const char *temp,
const char *content,
size_t total)
{
    int fd;
    int flags;
    size_t offset;
    int result;

    result = REDP2P_ERROR;
    flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    fd = open(temp, flags, 0600);
    if (fd < 0) {
        redp2p_set_error(ctx, "key: temporary key create failed: %s",
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
            redp2p_set_error(ctx, "key: temporary key write failed: %s",
                strerror(errno));
        } else if (close(fd) != 0) {
            fd = -1;
            redp2p_set_error(ctx, "key: temporary key close failed: %s",
                strerror(errno));
        } else {
            int dir_fd;

            fd = -1;
            if (rename(temp, paths->scoped) != 0) {
                redp2p_set_error(ctx, "key: atomic replacement failed: %s",
                    strerror(errno));
            } else {
                dir_fd = open(paths->dir, O_RDONLY
#ifdef O_DIRECTORY
                    | O_DIRECTORY
#endif
                );
                if (dir_fd < 0) {
                    redp2p_set_error(ctx,
                        "key: key directory sync failed: %s",
                        strerror(errno));
                } else if (fsync(dir_fd) != 0) {
                    redp2p_set_error(ctx,
                        "key: key directory sync failed: %s",
                        strerror(errno));
                    close(dir_fd);
                } else if (close(dir_fd) != 0) {
                    redp2p_set_error(ctx,
                        "key: key directory close failed: %s",
                        strerror(errno));
                } else {
                    result = REDP2P_OK;
                }
            }
        }
        if (fd >= 0) close(fd);
    }
    if (result != REDP2P_OK) unlink(temp);
    return result;
}
#endif

/**
 * Atomically persists one scoped registration key.
 * @param ctx Context receiving error detail.
 * @param paths Scoped key paths.
 * @param key Registration key.
 * @return REDP2P_OK on durable replacement or REDP2P_ERROR on failure.
 */
static int redp2p_save_key(redp2p_t *ctx, const redp2p_key_paths_t *paths,
    const char *key)
{
    unsigned char random[8];
    char suffix[17];
    char temp[896];
    char dir[sizeof(paths->dir)];
    char content[REDP2P_KEY_STR_SZ + 1];
    size_t total;
    int name_len;
    int result;

    memcpy(dir, paths->dir, sizeof(dir));
    if (redp2p_mkdir_p(dir) != 0) {
        redp2p_set_error(ctx, "key: cannot create key directory: %s",
            strerror(errno));
        crypto_wipe(dir, sizeof(dir));
        return REDP2P_ERROR;
    }
    name_len = -1;
    if (redp2p_fill_random(random, sizeof(random)) == 0 &&
        redp2p_hex_encode(random, sizeof(random), suffix, sizeof(suffix)))
        name_len = snprintf(temp, sizeof(temp), "%s/.%s.tmp", paths->dir,
            suffix);
    if (name_len < 0 || (size_t)name_len >= sizeof(temp))
    {
        redp2p_set_error(ctx, "key: cannot create temporary key name");
        crypto_wipe(random, sizeof(random));
        crypto_wipe(suffix, sizeof(suffix));
        crypto_wipe(temp, sizeof(temp));
        crypto_wipe(dir, sizeof(dir));
        return REDP2P_ERROR;
    }
    memcpy(content, key, REDP2P_KEY_SZ);
    content[REDP2P_KEY_SZ] = '\n';
    total = REDP2P_KEY_SZ + 1;
    redp2p_key_lock();
#ifdef _WIN32
    result = redp2p_save_key_windows(ctx, paths, temp, content, total);
#else
    result = redp2p_save_key_posix(ctx, paths, temp, content, total);
#endif
    redp2p_key_unlock();
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
 * @return REDP2P_OK when absent or removed, otherwise REDP2P_ERROR.
 */
static int redp2p_remove_key(redp2p_t *ctx, const char *path, const char *key) {
    char current[REDP2P_KEY_STR_SZ];
    int loaded;
    int result;

    redp2p_key_lock();
    loaded = redp2p_load_key_path(ctx, path, current);
    if (loaded == REDP2P_ENOENT) {
        crypto_wipe(current, sizeof(current));
        redp2p_key_unlock();
        return REDP2P_OK;
    }
    if (loaded != REDP2P_OK || strcmp(current, key) != 0) {
        if (loaded == REDP2P_OK)
            redp2p_set_error(ctx, "key: persisted key changed before removal");
        crypto_wipe(current, sizeof(current));
        redp2p_key_unlock();
        return REDP2P_ERROR;
    }
#ifdef _WIN32
    result = DeleteFileA(path) ? REDP2P_OK : REDP2P_ERROR;
    if (result != REDP2P_OK)
        redp2p_set_error(ctx, "key: persisted key removal failed (%lu)",
            (unsigned long)GetLastError());
#else
    result = unlink(path) == 0 ? REDP2P_OK : REDP2P_ERROR;
    if (result != REDP2P_OK)
        redp2p_set_error(ctx, "key: persisted key removal failed: %s",
            strerror(errno));
#endif
    crypto_wipe(current, sizeof(current));
    redp2p_key_unlock();
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
static int redp2p_deregister_with_key(
    redp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *id,
    const char *key)
{
    JSON_Value *request;
    JSON_Object *obj;
    int result;

    if (!key || key[0] == '\0') return REDP2P_ENOENT;
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "deregister: index request allocation failed");
        return REDP2P_ERROR;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "deregister");
    json_object_set_string(obj, "id", id);
    json_object_set_string(obj, "key", key);
    result = redp2p_http_client(ctx, "deregister", index_host, index_port,
        request, NULL);
    json_value_free(request);
    if (result != REDP2P_OK) return result;
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Deregister.
 * @return 0 on success, -1 on error.
 */
int redp2p_deregister(
    redp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *id)
{
    redp2p_key_paths_t paths;
    const char *loaded_path;
    char key[REDP2P_KEY_STR_SZ];
    int result;

    if (!ctx) return REDP2P_EINVAL;
    memset(key, 0, sizeof(key));
    redp2p_set_error(ctx, NULL);
    if (!index_host || !index_host[0]) {
        redp2p_set_error(ctx, "deregister: index host is missing");
        return REDP2P_EINVAL;
    }
    if (index_port == 0) {
        redp2p_set_error(ctx, "deregister: index port must be nonzero");
        return REDP2P_EINVAL;
    }
    if (!redp2p_is_valid_id(id)) {
        redp2p_set_error(ctx, "deregister: publisher id is invalid");
        return REDP2P_EINVAL;
    }
    result = redp2p_key_paths(ctx, index_host, index_port, id, &paths);
    if (result != REDP2P_OK) return result;
    redp2p_key_lock();
    result = redp2p_load_key_path(ctx, paths.scoped, key);
    loaded_path = paths.scoped;
    if (result == REDP2P_ENOENT) {
        result = redp2p_load_key_path(ctx, paths.legacy, key);
        loaded_path = paths.legacy;
    }
    redp2p_key_unlock();
    if (result == REDP2P_ENOENT) {
        redp2p_set_error(ctx, "deregister: no persisted key for publisher");
        crypto_wipe(key, sizeof(key));
        return REDP2P_ENOENT;
    }
    if (result == REDP2P_OK) {
        result = redp2p_deregister_with_key(ctx, index_host, index_port, id,
            key);
        if (result == REDP2P_OK)
            result = redp2p_remove_key(ctx, loaded_path, key);
    }
    crypto_wipe(key, sizeof(key));
    return result;
}

/**
 * List publishers.
 * @return 0 on success, negative error code on failure.
 */
int redp2p_list_publishers(
    redp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    redp2p_publisher_cb cb,
    void *userdata)
{
    JSON_Value *request;
    JSON_Value *response;
    JSON_Object *obj;
    JSON_Object *out;
    JSON_Array *ids;
    size_t count;
    size_t i;
    int result;

    if (!ctx || !index_host || !index_host[0] || !cb) return REDP2P_ERROR;
    redp2p_set_error(ctx, NULL);
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "list: index request allocation failed");
        return REDP2P_ERROR;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "list");
    response = NULL;
    result = redp2p_http_client(ctx, "list", index_host, index_port, request,
        &response);
    json_value_free(request);
    if (result != REDP2P_OK) return result;
    out = json_value_get_object(response);
    if (!out || !json_object_has_value_of_type(out, "ids", JSONArray)) {
        json_value_free(response);
        redp2p_set_error(ctx, "list: malformed index response");
        return REDP2P_EPROTO;
    }
    ids = json_object_get_array(out, "ids");
    count = json_array_get_count(ids);
    for (i = 0; i < count; i++) {
        const char *id;

        id = json_array_get_string(ids, i);
        if (!id || !redp2p_is_valid_id(id)) {
            json_value_free(response);
            redp2p_set_error(ctx, "list: malformed publisher id");
            return REDP2P_EPROTO;
        }
        cb(id, userdata);
    }
    json_value_free(response);
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Validates publisher inputs and opens its control and UDP transports.
 * @param runtime Runtime that borrows inputs and owns opened descriptors.
 * @param ctx Publisher context to borrow.
 * @param index_host Index host to borrow.
 * @param index_port Index control port.
 * @param self_id Publisher identifier to borrow.
 * @param bind_port Requested local backend port.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_initialize(
redp2p_publisher_runtime_t *runtime,
redp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
unsigned short bind_port)
{
    unsigned short effective_port;

    memset(runtime, 0, sizeof(*runtime));
    runtime->borrowed_ctx = ctx;
    runtime->borrowed_index_host = index_host;
    runtime->borrowed_self_id = self_id;
    runtime->index_port = index_port;
    runtime->owned_udp_fd = REDP2P_FD_INVALID;
    if (ctx->proto != REDP2P_PROTO_TCP && ctx->proto != REDP2P_PROTO_UDP) {
        redp2p_set_error(ctx, "wait: invalid transport protocol");
        return REDP2P_EINVAL;
    }
    if (redp2p_resolve_port(ctx, bind_port, &effective_port) != REDP2P_OK) {
        redp2p_set_error(ctx, "wait: conflicting local ports");
        return REDP2P_EINVAL;
    }
    if (effective_port == 0 || !index_host || !self_id ||
        !redp2p_is_valid_id(self_id) || index_port == 0)
    {
        redp2p_set_error(ctx, "wait: invalid index, service id, or local port");
        return REDP2P_EINVAL;
    }
    ctx->bind_port = effective_port;
    runtime->borrowed_udp_any_host = redp2p_host_is_ipv6_literal(index_host) ?
        "::" : "0.0.0.0";
    runtime->owned_udp_fd = redp2p_create_socket(
        runtime->borrowed_udp_any_host, 0);
    if (REDP2P_ISERR(runtime->owned_udp_fd)) {
        return REDP2P_ENET;
    }
    return REDP2P_OK;
}

/**
 * Completes the registration challenge, proof, and response exchange.
 * @param runtime Initialized publisher runtime.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_register(
redp2p_publisher_runtime_t *runtime)
{
    redp2p_t *ctx;
    JSON_Value *request;
    JSON_Value *response;
    JSON_Object *obj;
    JSON_Object *out;
    char nonce[17];
    char solution[17];
    char proof[65];
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    int candidate_count;
    int bits;
    int result;

    ctx = runtime->borrowed_ctx;
    memset(nonce, 0, sizeof(nonce));
    memset(solution, 0, sizeof(solution));
    memset(proof, 0, sizeof(proof));
    candidate_count = 0;
    if (redp2p_gather_candidates(ctx, runtime->owned_udp_fd, candidates,
        REDP2P_PEER_CANDIDATES_MAX, &candidate_count) != REDP2P_OK)
    {
        redp2p_set_error(ctx, "wait: local candidate gather failed");
        result = REDP2P_ENET;
        goto cleanup;
    }
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "wait: registration request allocation failed");
        result = REDP2P_ERROR;
        goto cleanup;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "challenge");
    json_object_set_string(obj, "id", runtime->borrowed_self_id);
    response = NULL;
    result = redp2p_http_client(ctx, "wait", runtime->borrowed_index_host,
        runtime->index_port, request, &response);
    json_value_free(request);
    if (result != REDP2P_OK) goto cleanup;
    out = json_value_get_object(response);
    if (!out || !redp2p_index_require_hex(out, "nonce", nonce,
        sizeof(nonce), 16) ||
        !json_object_has_value_of_type(out, "bits", JSONNumber))
    {
        json_value_free(response);
        redp2p_set_error(ctx, "wait: malformed registration challenge");
        result = REDP2P_EPROTO;
        goto cleanup;
    }
    bits = (int)json_object_get_number(out, "bits");
    json_value_free(response);
    fprintf(stderr, "redp2p: connecting...\n");
    if (!redp2p_solve_register_pow(ctx, ctx->pass, nonce,
        runtime->borrowed_self_id, bits, solution, sizeof(solution),
        proof, sizeof(proof)))
    {
        redp2p_set_error(ctx, "wait: registration proof solve failed");
        result = REDP2P_ERROR;
        goto cleanup;
    }
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "wait: registration request allocation failed");
        result = REDP2P_ERROR;
        goto cleanup;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "register");
    json_object_set_string(obj, "id", runtime->borrowed_self_id);
    json_object_set_string(obj, "nonce", nonce);
    json_object_set_string(obj, "solution", solution);
    json_object_set_string(obj, "proof", proof);
    json_object_set_number(obj, "proto", (double)ctx->proto);
    json_object_set_number(obj, "udp_port", (double)ctx->bind_port);
    redp2p_index_append_candidates(obj, "candidates", candidates,
        candidate_count);
    response = NULL;
    result = redp2p_http_client(ctx, "wait", runtime->borrowed_index_host,
        runtime->index_port, request, &response);
    json_value_free(request);
    if (result != REDP2P_OK) goto cleanup;
    out = json_value_get_object(response);
    if (!out || !redp2p_index_require_hex(out, "key", ctx->key,
        REDP2P_KEY_STR_SZ, REDP2P_KEY_SZ))
    {
        json_value_free(response);
        redp2p_set_error(ctx, "wait: malformed registration response");
        result = REDP2P_EPROTO;
        goto cleanup;
    }
    json_value_free(response);
    result = REDP2P_OK;

cleanup:
    crypto_wipe(nonce, sizeof(nonce));
    crypto_wipe(solution, sizeof(solution));
    crypto_wipe(proof, sizeof(proof));
    return result;
}

/**
 * Persists the registration key and rolls registration back on failure.
 * @param runtime Registered publisher runtime.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_persist_registration(
redp2p_publisher_runtime_t *runtime)
{
    redp2p_t *ctx;
    redp2p_key_paths_t paths;
    int path_result;

    ctx = runtime->borrowed_ctx;
    if (ctx->key[0] == '\0') {
        redp2p_set_error(ctx, "wait: registration returned no key");
        return REDP2P_EPROTO;
    }
    path_result = redp2p_key_paths(ctx, runtime->borrowed_index_host,
        runtime->index_port, runtime->borrowed_self_id, &paths);
    if (path_result != REDP2P_OK ||
        redp2p_save_key(ctx, &paths, ctx->key) != REDP2P_OK)
    {
        redp2p_deregister_with_key(NULL, runtime->borrowed_index_host,
            runtime->index_port, runtime->borrowed_self_id, ctx->key);
        if (path_result == REDP2P_OK)
            redp2p_remove_key(NULL, paths.scoped, ctx->key);
        ctx->key[0] = '\0';
        return REDP2P_ERROR;
    }
    return REDP2P_OK;
}

/**
 * Finds an active publisher session for one peer address and transport ID.
 * @param runtime Publisher runtime containing the session table.
 * @param peer_addr Peer address to match.
 * @param session_id TCP session identifier, or NULL for UDP.
 * @return Matching session index, or -1 when no session matches.
 */
static int redp2p_publisher_session_find(
const redp2p_publisher_runtime_t *runtime,
const struct sockaddr_storage *peer_addr,
const unsigned char *session_id)
{
    int i;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (!redp2p_sockaddr_equal(&runtime->owned_sessions[i].peer_addr,
            peer_addr))
            continue;
        if (!runtime->owned_sessions[i].is_tcp && !session_id) return i;
        if (runtime->owned_sessions[i].is_tcp && session_id &&
            memcmp(runtime->owned_sessions[i].stream.session_id, session_id,
                REDP2P_STREAM_SESSION_ID_SZ) == 0)
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
static int redp2p_publisher_session_insert(
redp2p_publisher_runtime_t *runtime,
redp2p_udp_server_session_t *session)
{
    redp2p_udp_server_session_t *new_sessions;
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
        new_sessions = (redp2p_udp_server_session_t *)realloc(
            runtime->owned_sessions,
            (size_t)new_capacity * sizeof(*runtime->owned_sessions));
        if (!new_sessions) {
            redp2p_server_session_close(session);
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
static void redp2p_publisher_session_close_all(
redp2p_publisher_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].is_tcp &&
            !redp2p_stream_is_done(&runtime->owned_sessions[i].stream))
        {
            redp2p_stream_fail(runtime->borrowed_ctx,
                &runtime->owned_sessions[i].stream);
        }
        redp2p_server_session_close(&runtime->owned_sessions[i]);
    }
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
static int redp2p_publisher_select_peer(
redp2p_publisher_runtime_t *runtime,
const char *connection_id,
const char *session_token,
redp2p_candidate_t *candidates,
int candidate_count,
struct sockaddr_storage *peer_addr)
{
    memset(peer_addr, 0, sizeof(*peer_addr));
    return redp2p_punch_select(runtime->borrowed_ctx,
        runtime->borrowed_ctx->sweep, runtime->owned_udp_fd, session_token,
        runtime->borrowed_self_id, connection_id, candidates, candidate_count,
        peer_addr) == REDP2P_OK;
}

/**
 * Opens a backend and creates a publisher session when the peer is new.
 * @param runtime Publisher runtime that owns created session resources.
 * @param session_hex Canonical TCP stream session token.
 * @param session_id Decoded TCP stream session identifier.
 * @param peer_addr Selected peer address.
 * @return 1 when the peer is ready, or 0 on a nonfatal backend failure.
 */
static int redp2p_publisher_open_session(
redp2p_publisher_runtime_t *runtime,
const char *session_hex,
const unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ],
const struct sockaddr_storage *peer_addr)
{
    redp2p_udp_server_session_t session;
    redp2p_t *ctx;

    ctx = runtime->borrowed_ctx;
    if (redp2p_publisher_session_find(runtime, peer_addr,
        ctx->proto == REDP2P_PROTO_TCP ? session_id : NULL) >= 0)
        return 1;
    memset(&session, 0, sizeof(session));
    session.backend_fd = REDP2P_FD_INVALID;
    session.tcp_fd = REDP2P_FD_INVALID;
    session.peer_addr = *peer_addr;
    session.last_rx = redp2p_now_s();
    session.last_ka = session.last_rx;
    session.is_tcp = ctx->proto == REDP2P_PROTO_TCP ? 1 : 0;
    if (session.is_tcp) {
        session.backend_fd = redp2p_connect_local_tcp(ctx->bind_port);
        if (REDP2P_ISERR(session.backend_fd)) {
            fprintf(stderr,
                "redp2p: local backend connect failed on 127.0.0.1:%u\n",
                (unsigned)ctx->bind_port);
            crypto_wipe(&session, sizeof(session));
            return 0;
        }
        if (redp2p_stream_init(ctx, &session.stream, 0,
            runtime->owned_udp_fd, peer_addr, session_id, session_hex,
            REDP2P_PROTO_TCP) != 0)
        {
            REDP2P_FD_CLOSE(session.backend_fd);
            crypto_wipe(&session, sizeof(session));
            return 0;
        }
    } else {
        session.backend_fd = redp2p_create_socket(
            runtime->borrowed_udp_any_host, 0);
        if (REDP2P_ISERR(session.backend_fd)) {
            crypto_wipe(&session, sizeof(session));
            return 0;
        }
    }
    session.active = 1;
    return redp2p_publisher_session_insert(runtime, &session) >= 0;
}

/**
 * Processes one publisher punch_poll reply containing pending calls.
 * @param runtime Publisher runtime owning UDP and session state.
 * @param out     Punch poll reply object.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_process_punch_calls(
redp2p_publisher_runtime_t *runtime,
JSON_Object *out)
{
    JSON_Array *calls;
    size_t count;
    size_t i;

    if (!out || !json_object_has_value_of_type(out, "calls", JSONArray)) {
        redp2p_set_error(runtime->borrowed_ctx,
            "wait: malformed punch poll response");
        return REDP2P_EPROTO;
    }
    calls = json_object_get_array(out, "calls");
    count = json_array_get_count(calls);
    for (i = 0; i < count; i++) {
        JSON_Object *call;
        const char *connection_id;
        const char *remote_token;
        redp2p_candidate_t remote_candidates[REDP2P_PEER_CANDIDATES_MAX];
        struct sockaddr_storage peer_addr;
        char session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1];
        unsigned char session_id[REDP2P_STREAM_SESSION_ID_SZ];
        int candidate_count;

        memset(session_hex, 0, sizeof(session_hex));
        memset(session_id, 0, sizeof(session_id));
        call = json_array_get_object(calls, i);
        if (!call) return REDP2P_EPROTO;
        connection_id = json_object_get_string(call, "self_id");
        remote_token = json_object_get_string(call, "session");
        if (!connection_id || !redp2p_is_valid_id(connection_id) ||
            !remote_token || !redp2p_is_session_token(remote_token) ||
            !redp2p_index_parse_candidates(call, "candidates",
                remote_candidates, &candidate_count))
            return REDP2P_EPROTO;
        if (runtime->borrowed_ctx->proto == REDP2P_PROTO_TCP) {
            if (!redp2p_is_hex_token(remote_token,
                REDP2P_STREAM_SESSION_ID_SZ * 2))
                continue;
            memcpy(session_hex, remote_token, REDP2P_STREAM_SESSION_ID_SZ * 2);
            session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2] = '\0';
            if (!redp2p_hex_decode(session_hex, session_id,
                sizeof(session_id)))
                continue;
        } else {
            snprintf(session_hex, sizeof(session_hex), "%s", remote_token);
        }
        if (!redp2p_publisher_select_peer(runtime, connection_id,
            session_hex, remote_candidates, candidate_count, &peer_addr))
            continue;
        if (!redp2p_publisher_open_session(runtime, session_hex,
            session_id, &peer_addr))
            continue;
        redp2p_sendto_addr(runtime->owned_udp_fd, REDP2P_CTRTOK_PUNCH_SERVER,
            strlen(REDP2P_CTRTOK_PUNCH_SERVER), &peer_addr);
    }
    return REDP2P_OK;
}

/**
 * Builds the publisher read set and closes unrepresentable backends.
 * @param runtime Publisher runtime containing all descriptors.
 * @param read_fds Output descriptor set.
 * @param max_fd Output highest descriptor.
 * @return 1 when selectable, 0 to retry, or REDP2P_ENET on fatal failure.
 */
static int redp2p_publisher_build_fdset(
redp2p_publisher_runtime_t *runtime,
fd_set *read_fds,
int *max_fd)
{
    redp2p_t *ctx;
    int failed;
    int i;

    ctx = runtime->borrowed_ctx;
    FD_ZERO(read_fds);
    *max_fd = -1;
    if (!redp2p_fdset_add(runtime->owned_udp_fd, read_fds, max_fd))
    {
        redp2p_set_error(ctx,
            "wait: essential descriptor cannot be represented by fd_set");
        return REDP2P_ENET;
    }
    failed = 0;
    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].backend_fd == REDP2P_FD_INVALID) continue;
        if (runtime->owned_sessions[i].is_tcp &&
            !redp2p_stream_can_send_data(&runtime->owned_sessions[i].stream))
            continue;
        if (redp2p_fdset_add(runtime->owned_sessions[i].backend_fd, read_fds,
            max_fd))
            continue;
        redp2p_set_error(ctx,
            "wait: backend descriptor cannot be represented by fd_set");
        if (runtime->owned_sessions[i].is_tcp)
            redp2p_stream_fail(ctx, &runtime->owned_sessions[i].stream);
        redp2p_server_session_close(&runtime->owned_sessions[i]);
        failed = 1;
    }
    return failed ? 0 : 1;
}

/**
 * Re-registers the publisher and refreshes its persisted key after expiry.
 * @param runtime Publisher runtime owning UDP and identity state.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_reregister(
redp2p_publisher_runtime_t *runtime)
{
    redp2p_t *ctx;
    redp2p_key_paths_t paths;
    int result;

    ctx = runtime->borrowed_ctx;
    result = redp2p_publisher_register(runtime);
    if (result != REDP2P_OK) return result;
    if (redp2p_key_paths(ctx, runtime->borrowed_index_host,
        runtime->index_port, runtime->borrowed_self_id, &paths) == REDP2P_OK &&
        redp2p_save_key(ctx, &paths, ctx->key) != REDP2P_OK)
    {
        redp2p_deregister_with_key(NULL, runtime->borrowed_index_host,
            runtime->index_port, runtime->borrowed_self_id, ctx->key);
        ctx->key[0] = '\0';
        return REDP2P_ERROR;
    }
    return REDP2P_OK;
}

/**
 * Sends one due publisher heartbeat, re-registering when the record expired.
 * @param runtime Publisher runtime owning UDP and identity state.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_heartbeat(
redp2p_publisher_runtime_t *runtime)
{
    redp2p_t *ctx;
    JSON_Value *request;
    JSON_Value *response;
    JSON_Object *obj;
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    int candidate_count;
    int result;

    ctx = runtime->borrowed_ctx;
    if (redp2p_now_s() - runtime->last_heartbeat < ctx->heartbeat_s)
        return REDP2P_OK;
    if (ctx->key[0] == '\0') return REDP2P_ENOENT;
    candidate_count = 0;
    if (redp2p_gather_candidates(ctx, runtime->owned_udp_fd, candidates,
        REDP2P_PEER_CANDIDATES_MAX, &candidate_count) != REDP2P_OK)
    {
        redp2p_set_error(ctx, "wait: local candidate gather failed");
        return REDP2P_ENET;
    }
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "wait: heartbeat request allocation failed");
        return REDP2P_ERROR;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "heartbeat");
    json_object_set_string(obj, "id", runtime->borrowed_self_id);
    json_object_set_string(obj, "key", ctx->key);
    json_object_set_number(obj, "proto", (double)ctx->proto);
    json_object_set_number(obj, "udp_port", (double)ctx->bind_port);
    redp2p_index_append_candidates(obj, "candidates", candidates,
        candidate_count);
    response = NULL;
    result = redp2p_http_client(ctx, "wait", runtime->borrowed_index_host,
        runtime->index_port, request, &response);
    json_value_free(request);
    if (response) json_value_free(response);
    if (result == REDP2P_OK || result == REDP2P_ENOENT ||
        result == REDP2P_EAUTH)
    {
        if (result != REDP2P_OK) result = redp2p_publisher_reregister(runtime);
        if (result == REDP2P_OK)
            runtime->last_heartbeat = redp2p_now_s();
    }
    return result;
}

/**
 * Polls the index for pending punch calls and processes them.
 * @param runtime Publisher runtime owning UDP and session state.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_publisher_punch_poll(
redp2p_publisher_runtime_t *runtime)
{
    redp2p_t *ctx;
    JSON_Value *request;
    JSON_Value *response;
    JSON_Object *obj;
    JSON_Object *out;
    int result;

    ctx = runtime->borrowed_ctx;
    if (redp2p_now_ms() - runtime->last_punch_poll < ctx->punch_poll_ms)
        return REDP2P_OK;
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "wait: punch poll request allocation failed");
        return REDP2P_ERROR;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "punch_poll");
    json_object_set_string(obj, "id", runtime->borrowed_self_id);
    response = NULL;
    result = redp2p_http_client(ctx, "wait", runtime->borrowed_index_host,
        runtime->index_port, request, &response);
    json_value_free(request);
    if (result != REDP2P_OK) {
        runtime->last_punch_poll = redp2p_now_ms();
        if (result == REDP2P_ETIMEOUT)
            return REDP2P_OK;
        return result;
    }
    out = json_value_get_object(response);
    result = redp2p_publisher_process_punch_calls(runtime, out);
    json_value_free(response);
    runtime->last_punch_poll = redp2p_now_ms();
    return result;
}

/**
 * Receives one peer datagram and forwards eligible payload to its backend.
 * @param runtime Publisher runtime owning UDP and session state.
 * @param read_fds Descriptor set returned by select.
 * @return 0 to continue, 1 to skip the iteration, or a negative error code.
 */
static int redp2p_publisher_receive_peer(
redp2p_publisher_runtime_t *runtime,
const fd_set *read_fds)
{
    redp2p_udp_server_session_t *session;
    struct sockaddr_storage from;
    struct sockaddr_in backend_addr;
    char buf[REDP2P_BUF + 1];
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
    redp2p_stream_envelope_t envelope;

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
        redp2p_set_error(runtime->borrowed_ctx,
            "wait: oversized peer datagram");
        return REDP2P_ENET;
    }
#endif
    if ((size_t)n >= sizeof(buf)) n = (int)(sizeof(buf) - 1);
    buf[n] = '\0';
    found = -1;
    if (runtime->borrowed_ctx->proto == REDP2P_PROTO_TCP) {
        if (redp2p_stream_unpack((const unsigned char *)buf, (size_t)n,
            &envelope))
        {
            found = redp2p_publisher_session_find(runtime, &from,
                envelope.session_id);
        }
    } else {
        found = redp2p_publisher_session_find(runtime, &from, NULL);
    }
    if (found < 0) {
        if (strncmp(buf, REDP2P_CTRTOK_PUNCH_PING,
            strlen(REDP2P_CTRTOK_PUNCH_PING)) == 0 &&
            redp2p_parse_punch_packet(buf, REDP2P_CTRTOK_PUNCH_PING,
                ping_session, ping_from, ping_to))
        {
            snprintf(pong, sizeof(pong), "%s%s:%s:%s",
                REDP2P_CTRTOK_PUNCH_PONG, ping_session, ping_to, ping_from);
            sendto(runtime->owned_udp_fd, pong, strlen(pong), 0,
                (const struct sockaddr *)&from, from_length);
        }
        return 0;
    }
    session = &runtime->owned_sessions[found];
    if (!session->is_tcp && (size_t)n > REDP2P_UDP_PAYLOAD_MAX) {
        redp2p_set_error(runtime->borrowed_ctx,
            "UDP datagram exceeds maximum payload size");
        return 1;
    }
    plain_keepalive = !session->is_tcp &&
        (size_t)n == strlen(REDP2P_CTRTOK_KA) &&
        memcmp(buf, REDP2P_CTRTOK_KA, strlen(REDP2P_CTRTOK_KA)) == 0;
    punch_control = strncmp(buf, REDP2P_CTRTOK_PUNCH,
        strlen(REDP2P_CTRTOK_PUNCH)) == 0 ||
        strncmp(buf, REDP2P_CTRTOK_PUNCH_PING,
        strlen(REDP2P_CTRTOK_PUNCH_PING)) == 0 ||
        strncmp(buf, REDP2P_CTRTOK_PUNCH_PONG,
        strlen(REDP2P_CTRTOK_PUNCH_PONG)) == 0;
    if (plain_keepalive) {
        session->last_rx = redp2p_now_s();
        return 0;
    }
    if (punch_control) return 1;
    if (session->is_tcp) {
        if (session->backend_fd != REDP2P_FD_INVALID &&
            redp2p_stream_process_packet(runtime->borrowed_ctx, &session->stream,
                session->backend_fd, (const unsigned char *)buf,
                (size_t)n) != 0)
        {
            redp2p_stream_fail(runtime->borrowed_ctx, &session->stream);
            redp2p_server_session_close(session);
        }
    } else {
        memset(&backend_addr, 0, sizeof(backend_addr));
        backend_addr.sin_family = AF_INET;
        backend_addr.sin_port = htons(runtime->borrowed_ctx->bind_port);
        inet_pton(AF_INET, "127.0.0.1", &backend_addr.sin_addr);
        sendto(session->backend_fd, (const char *)buf, (size_t)n, 0,
            (const struct sockaddr *)&backend_addr, sizeof(backend_addr));
    }
    session->last_rx = redp2p_now_s();
    return 0;
}

/**
 * Processes ready backend descriptors and forwards data to peers.
 * @param runtime Publisher runtime owning backend and peer descriptors.
 * @param read_fds Descriptor set returned by select.
 * @return None.
 */
static void redp2p_publisher_process_backends(
redp2p_publisher_runtime_t *runtime,
const fd_set *read_fds)
{
    struct sockaddr_in backend_from;
    char buf[REDP2P_BUF];
    socklen_t backend_from_length;
    int i;
    int n;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].backend_fd == REDP2P_FD_INVALID) continue;
        if (!FD_ISSET(runtime->owned_sessions[i].backend_fd, read_fds))
            continue;
        if (runtime->owned_sessions[i].is_tcp) {
            if (redp2p_stream_pump_tcp(runtime->borrowed_ctx,
                &runtime->owned_sessions[i].stream,
                runtime->owned_sessions[i].backend_fd) != 0)
            {
                redp2p_stream_fail(runtime->borrowed_ctx,
                    &runtime->owned_sessions[i].stream);
                redp2p_server_session_close(&runtime->owned_sessions[i]);
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
            ntohl(backend_from.sin_addr.s_addr) != REDP2P_IPV4_LOOPBACK)
            continue;
        redp2p_sendto_addr(runtime->owned_udp_fd, buf, (size_t)n,
            &runtime->owned_sessions[i].peer_addr);
        runtime->owned_sessions[i].last_rx = redp2p_now_s();
    }
}

/**
 * Advances publisher stream, keepalive, and disconnect state.
 * @param runtime Publisher runtime owning all sessions.
 * @return None.
 */
static void redp2p_publisher_maintain_sessions(
redp2p_publisher_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active) continue;
        if (runtime->owned_sessions[i].is_tcp) {
            if (redp2p_stream_tick(runtime->borrowed_ctx,
                &runtime->owned_sessions[i].stream) != 0)
            {
                redp2p_stream_fail(runtime->borrowed_ctx,
                    &runtime->owned_sessions[i].stream);
                redp2p_server_session_close(&runtime->owned_sessions[i]);
                continue;
            }
            if (redp2p_stream_is_done(&runtime->owned_sessions[i].stream)) {
                redp2p_server_session_close(&runtime->owned_sessions[i]);
                continue;
            }
        }
        if (redp2p_now_s() - runtime->owned_sessions[i].last_ka >
            REDP2P_KEEPALIVE_S)
        {
            if (!runtime->owned_sessions[i].is_tcp)
                redp2p_sendto_addr(runtime->owned_udp_fd, REDP2P_CTRTOK_KA,
                    strlen(REDP2P_CTRTOK_KA),
                    &runtime->owned_sessions[i].peer_addr);
            runtime->owned_sessions[i].last_ka = redp2p_now_s();
        }
        if (redp2p_now_s() - runtime->owned_sessions[i].last_rx >
            REDP2P_DISCONNECT_S)
            redp2p_server_session_close(&runtime->owned_sessions[i]);
    }
}

/**
 * Finds the nearest publisher-side KCP deadline.
 * @return Milliseconds until select should wake, capped at one second.
 */
static uint32_t redp2p_publisher_wait_ms(
    const redp2p_publisher_runtime_t *runtime)
{
    uint32_t wait_ms;
    uint32_t session_wait;
    uint64_t now;
    int i;

    wait_ms = 1000;
    now = redp2p_now_ms();
    {
        int64_t until_poll = (int64_t)runtime->last_punch_poll +
            runtime->borrowed_ctx->punch_poll_ms - (int64_t)now;

        if (until_poll < 1) until_poll = 1;
        if ((uint64_t)until_poll < wait_ms) wait_ms = (uint32_t)until_poll;
    }
    for (i = 0; i < runtime->session_count; i++) {
        if (!runtime->owned_sessions[i].active ||
            !runtime->owned_sessions[i].is_tcp)
            continue;
        session_wait = redp2p_stream_wait_ms(
            &runtime->owned_sessions[i].stream, now);
        if (session_wait < wait_ms) wait_ms = session_wait;
    }
    return wait_ms;
}

/**
 * Runs the publisher event loop in its established event order.
 * @param runtime Registered publisher runtime.
 * @return REDP2P_OK on shutdown, or a negative error code on failure.
 */
static int redp2p_publisher_event_loop(
redp2p_publisher_runtime_t *runtime)
{
    fd_set read_fds;
    struct timeval timeout;
    int stage_result;
    int max_fd;
    int selected;
    int result;
    uint32_t wait_ms;

    result = REDP2P_OK;
    runtime->last_heartbeat = redp2p_now_s();
    runtime->last_punch_poll = redp2p_now_ms();
    redp2p_set_nonblock(runtime->owned_udp_fd);
    while (!runtime->borrowed_ctx->stop_requested) {
        stage_result = redp2p_publisher_build_fdset(runtime, &read_fds, &max_fd);
        if (stage_result < 0) {
            result = stage_result;
            break;
        }
        if (stage_result == 0) continue;
        wait_ms = redp2p_publisher_wait_ms(runtime);
        timeout.tv_sec = (long)(wait_ms / 1000u);
        timeout.tv_usec = (long)((wait_ms % 1000u) * 1000u);
        selected = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (selected < 0) continue;
        if (runtime->borrowed_ctx->stop_requested) break;
        stage_result = redp2p_publisher_heartbeat(runtime);
        if (stage_result != REDP2P_OK && stage_result != REDP2P_ETIMEOUT) {
            result = stage_result;
            break;
        }
        stage_result = redp2p_publisher_punch_poll(runtime);
        if (stage_result != REDP2P_OK && stage_result != REDP2P_ETIMEOUT) {
            result = stage_result;
            break;
        }
        stage_result = redp2p_publisher_receive_peer(runtime, &read_fds);
        if (stage_result < 0) {
            result = stage_result;
            break;
        }
        if (stage_result > 0) {
            redp2p_publisher_maintain_sessions(runtime);
            continue;
        }
        redp2p_publisher_process_backends(runtime, &read_fds);
        redp2p_publisher_maintain_sessions(runtime);
    }
    redp2p_publisher_session_close_all(runtime);
    return result;
}

/**
 * Deregisters the publisher and removes its persisted key when accepted.
 * @param runtime Publisher runtime borrowing registration identity.
 * @param wait_result Current wait result, updated on key removal failure.
 * @return None.
 */
static void redp2p_publisher_remove_registration(
redp2p_publisher_runtime_t *runtime,
int *wait_result)
{
    redp2p_t *ctx;
    redp2p_key_paths_t paths;
    char prior_error[sizeof(runtime->borrowed_ctx->err_buf)];
    int deregistered;
    int removed;

    ctx = runtime->borrowed_ctx;
    if (ctx->key[0] != '\0') {
        memcpy(prior_error, ctx->err_buf, sizeof(prior_error));
        removed = REDP2P_OK;
        deregistered = redp2p_deregister_with_key(ctx,
            runtime->borrowed_index_host, runtime->index_port,
            runtime->borrowed_self_id, ctx->key);
        if (deregistered == REDP2P_OK) {
            if (redp2p_key_paths(ctx, runtime->borrowed_index_host,
                runtime->index_port, runtime->borrowed_self_id, &paths) !=
                REDP2P_OK ||
                redp2p_remove_key(ctx, paths.scoped, ctx->key) != REDP2P_OK)
            {
                removed = REDP2P_ERROR;
                *wait_result = REDP2P_ERROR;
            }
        }
        if (prior_error[0] != '\0' && deregistered == REDP2P_OK &&
            removed == REDP2P_OK)
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
static void redp2p_publisher_runtime_cleanup(
redp2p_publisher_runtime_t *runtime,
int reset_stop)
{
    redp2p_publisher_session_close_all(runtime);
    if (runtime->owned_sessions)
        crypto_wipe(runtime->owned_sessions,
            (size_t)runtime->session_capacity *
            sizeof(*runtime->owned_sessions));
    free(runtime->owned_sessions);
    runtime->owned_sessions = NULL;
    if (!REDP2P_ISERR(runtime->owned_udp_fd))
        REDP2P_FD_CLOSE(runtime->owned_udp_fd);
    runtime->owned_udp_fd = REDP2P_FD_INVALID;
    if (reset_stop)
        atomic_store(&runtime->borrowed_ctx->stop_requested, 0);
}

/**
 * Registers a publisher, serves sessions, and tears registration down.
 * @return 0 on success, or a negative error code on failure.
 */
int redp2p_wait(
    redp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *self_id,
    unsigned short bind_port)
{
    redp2p_publisher_runtime_t runtime;
    int wait_result;

    if (!ctx) return REDP2P_EINVAL;
    redp2p_set_error(ctx, NULL);
    if (redp2p_is_stop_requested(ctx)) {
        atomic_store(&ctx->stop_requested, 0);
        return REDP2P_OK;
    }
    wait_result = redp2p_publisher_initialize(&runtime, ctx, index_host,
        index_port, self_id, bind_port);
    if (wait_result != REDP2P_OK) return wait_result;
    wait_result = redp2p_publisher_register(&runtime);
    if (wait_result != REDP2P_OK) {
        redp2p_publisher_runtime_cleanup(&runtime, 0);
        return wait_result;
    }
    wait_result = redp2p_publisher_persist_registration(&runtime);
    if (wait_result != REDP2P_OK) {
        redp2p_publisher_runtime_cleanup(&runtime, 0);
        return wait_result;
    }
    redp2p_set_error(ctx, NULL);
    fprintf(stderr, "redp2p: published %s backend 127.0.0.1:%u as '%s'\n",
        ctx->proto == REDP2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)ctx->bind_port, self_id);
    wait_result = redp2p_publisher_event_loop(&runtime);
    redp2p_publisher_remove_registration(&runtime, &wait_result);
    redp2p_publisher_runtime_cleanup(&runtime, 1);
    return wait_result;
}

/**
 * Sends one HTTP punch request carrying the local candidates.
 * @param runtime Consumer runtime owning index, identity, and session settings.
 * @param session_hex Session token used by the punch exchange.
 * @param cands Local candidates.
 * @param cand_count Local candidate count.
 * @return REDP2P_OK on success, or a negative error code on failure.
 */
static int redp2p_send_punch_req_cands(
redp2p_consumer_runtime_t *runtime,
const char *session_hex,
const redp2p_candidate_t *cands,
int cand_count)
{
    redp2p_t *ctx;
    JSON_Value *request;
    JSON_Object *obj;
    int result;

    ctx = runtime->ctx;
    if (!cands || cand_count <= 0 ||
        cand_count > REDP2P_PEER_CANDIDATES_MAX || !session_hex)
        return REDP2P_EPROTO;
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "connect: punch request allocation failed");
        return REDP2P_ERROR;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "punch_req");
    json_object_set_string(obj, "self_id", runtime->self_id);
    json_object_set_string(obj, "target_id", runtime->target_id);
    json_object_set_string(obj, "session", session_hex);
    redp2p_index_append_candidates(obj, "candidates", cands, cand_count);
    result = redp2p_http_client(ctx, "connect", runtime->index_host,
        runtime->index_port, request, NULL);
    json_value_free(request);
    return result;
}

/**
 * Finds an active UDP session for one local client address.
 * @param runtime Consumer runtime containing the session table.
 * @param client_addr Local client address to match.
 * @return Matching session index, or -1 when no session matches.
 */
static int redp2p_consumer_session_find(
const redp2p_consumer_runtime_t *runtime,
const struct sockaddr_storage *client_addr)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (redp2p_sockaddr_equal(&runtime->sessions[i].client_addr,
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
static int redp2p_consumer_session_insert(
redp2p_consumer_runtime_t *runtime,
redp2p_udp_consumer_session_t *session)
{
    redp2p_udp_consumer_session_t *new_sessions;
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
        new_sessions = (redp2p_udp_consumer_session_t *)realloc(
            runtime->sessions, (size_t)new_cap * sizeof(*runtime->sessions));
        if (!new_sessions) {
            redp2p_consumer_session_close(session);
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
static void redp2p_consumer_session_close_all(
redp2p_consumer_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (runtime->sessions[i].is_tcp &&
            !redp2p_stream_is_done(&runtime->sessions[i].stream))
        {
            redp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
        }
        redp2p_consumer_session_close(&runtime->sessions[i]);
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
 * @return REDP2P_OK on success, or the existing establishment error code.
 */
static int redp2p_consumer_establish_peer(
redp2p_consumer_runtime_t *runtime,
int is_tcp,
redp2p_fd_t *out_fd,
struct sockaddr_storage *out_peer,
unsigned char session_bin[REDP2P_STREAM_SESSION_ID_SZ],
char session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1],
int *skip_iteration)
{
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    struct sockaddr_storage peer_addr;
    redp2p_fd_t peer_fd;
    int candidate_count;
    int result;
    size_t random_size;
    size_t hex_size;

    *out_fd = REDP2P_FD_INVALID;
    memset(out_peer, 0, sizeof(*out_peer));
    memset(session_bin, 0, REDP2P_STREAM_SESSION_ID_SZ);
    memset(session_hex, 0, REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
    if (skip_iteration) *skip_iteration = 0;

    if (is_tcp) {
        if (!redp2p_stream_make_session_id(session_bin, session_hex)) {
            if (skip_iteration) *skip_iteration = 1;
            crypto_wipe(session_bin, REDP2P_STREAM_SESSION_ID_SZ);
            crypto_wipe(session_hex, REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
            return REDP2P_ENET;
        }
    } else {
        random_size = 8;
        hex_size = 17;
        if (redp2p_fill_random(session_bin, random_size) != 0 ||
            !redp2p_hex_encode(session_bin, random_size, session_hex, hex_size))
        {
            if (skip_iteration) *skip_iteration = 1;
            crypto_wipe(session_bin, REDP2P_STREAM_SESSION_ID_SZ);
            crypto_wipe(session_hex, REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
            return REDP2P_ENET;
        }
    }

    peer_fd = redp2p_create_socket(runtime->udp_any_host, 0);
    candidate_count = 0;
    if (REDP2P_ISERR(peer_fd) ||
        redp2p_gather_candidates(runtime->ctx, peer_fd, candidates,
            REDP2P_PEER_CANDIDATES_MAX, &candidate_count) != REDP2P_OK)
    {
        if (skip_iteration) *skip_iteration = 1;
        crypto_wipe(session_bin, REDP2P_STREAM_SESSION_ID_SZ);
        crypto_wipe(session_hex, REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
        if (!REDP2P_ISERR(peer_fd)) REDP2P_FD_CLOSE(peer_fd);
        return REDP2P_ENET;
    }
    result = redp2p_send_punch_req_cands(runtime, session_hex, candidates,
        candidate_count);
    if (result != REDP2P_OK) {
        if (skip_iteration) *skip_iteration = 1;
        crypto_wipe(session_bin, REDP2P_STREAM_SESSION_ID_SZ);
        crypto_wipe(session_hex, REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
        REDP2P_FD_CLOSE(peer_fd);
        return result;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    result = redp2p_punch_select(runtime->ctx, runtime->ctx->sweep,
        (int)peer_fd,
        session_hex, runtime->self_id, runtime->target_id,
        runtime->peer_candidates, runtime->n_peer_candidates, &peer_addr);
    if (result != REDP2P_OK) {
        fprintf(stderr, "redp2p: udp punch failed\n");
        REDP2P_FD_CLOSE((int)peer_fd);
        crypto_wipe(session_bin, REDP2P_STREAM_SESSION_ID_SZ);
        crypto_wipe(session_hex, REDP2P_STREAM_SESSION_ID_SZ * 2 + 1);
        return result;
    }

    *out_fd = (int)peer_fd;
    *out_peer = peer_addr;
    return REDP2P_OK;
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
static int redp2p_consumer_tcp_session_init(
redp2p_consumer_runtime_t *runtime,
redp2p_udp_consumer_session_t *session,
redp2p_fd_t peer_fd,
const struct sockaddr_storage *peer_addr,
redp2p_fd_t client_fd,
const unsigned char session_bin[REDP2P_STREAM_SESSION_ID_SZ],
const char session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1])
{
    memset(session, 0, sizeof(*session));
    session->fd = peer_fd;
    session->tcp_fd = client_fd;
    session->peer_addr = *peer_addr;
    if (redp2p_stream_init(runtime->ctx, &session->stream, 1, peer_fd,
        peer_addr, session_bin, session_hex, REDP2P_PROTO_TCP) != 0)
        return -1;
    session->active = 1;
    session->is_tcp = 1;
    session->last_rx = redp2p_now_s();
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
static void redp2p_consumer_udp_session_init(
redp2p_udp_consumer_session_t *session,
redp2p_fd_t peer_fd,
const struct sockaddr_storage *peer_addr,
const struct sockaddr_storage *client_addr)
{
    memset(session, 0, sizeof(*session));
    session->fd = peer_fd;
    session->tcp_fd = REDP2P_FD_INVALID;
    session->peer_addr = *peer_addr;
    session->client_addr = *client_addr;
    session->last_rx = redp2p_now_s();
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
 * @return REDP2P_OK on success, or the existing initialization error code.
 */
static int redp2p_consumer_runtime_init(
redp2p_consumer_runtime_t *runtime,
redp2p_t *ctx,
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
    runtime->local_fd = REDP2P_FD_INVALID;
    runtime->tcp_listen_fd = REDP2P_FD_INVALID;
    *should_run = 0;
    redp2p_set_error(runtime->ctx, NULL);
    if (redp2p_is_stop_requested(runtime->ctx)) {
        atomic_store(&runtime->ctx->stop_requested, 0);
        return REDP2P_OK;
    }
    if (redp2p_resolve_port(runtime->ctx, bind_port, &effective_port) != REDP2P_OK) {
        redp2p_set_error(runtime->ctx, "connect: conflicting local ports");
        return REDP2P_EINVAL;
    }
    if (effective_port == 0 || !runtime->index_host || !runtime->self_id ||
        !runtime->target_id || !redp2p_is_valid_id(runtime->self_id) ||
        !redp2p_is_valid_id(runtime->target_id) || runtime->index_port == 0 ||
        (runtime->ctx->proto != REDP2P_PROTO_TCP &&
        runtime->ctx->proto != REDP2P_PROTO_UDP))
    {
        redp2p_set_error(runtime->ctx,
            "connect: invalid index, identity, protocol, or local port");
        return REDP2P_EINVAL;
    }
    runtime->ctx->bind_port = effective_port;
    if (redp2p_platform_init() != 0) {
        redp2p_set_error(runtime->ctx, "connect: platform init failed");
        return REDP2P_ENET;
    }
    runtime->platform_initialized = 1;
    runtime->udp_any_host = redp2p_host_is_ipv6_literal(runtime->index_host) ?
        "::" : "0.0.0.0";

    if (runtime->ctx->proto == REDP2P_PROTO_UDP) {
        runtime->local_fd = redp2p_create_socket("127.0.0.1",
            runtime->ctx->bind_port);
        if (REDP2P_ISERR(runtime->local_fd)) {
            redp2p_set_error(runtime->ctx, "connect: local UDP bind failed");
            return REDP2P_ENET;
        }
    } else {
        runtime->local_fd = redp2p_create_socket(runtime->udp_any_host, 0);
        if (REDP2P_ISERR(runtime->local_fd)) {
            redp2p_set_error(runtime->ctx,
                "connect: peer UDP socket setup failed");
            return REDP2P_ENET;
        }
        runtime->tcp_listen_fd = redp2p_create_tcp_listener("127.0.0.1",
            runtime->ctx->bind_port);
        if (REDP2P_ISERR(runtime->tcp_listen_fd)) {
            redp2p_set_error(runtime->ctx,
                "connect: local TCP bind/listen failed");
            return REDP2P_ENET;
        }
    }
    *should_run = 1;
    return REDP2P_OK;
}

/**
 * Resolves the target publisher and stores its candidates.
 * @param runtime Initialized consumer runtime.
 * @return REDP2P_OK on success, or the existing lookup error code.
 */
static int redp2p_consumer_initial_lookup(redp2p_consumer_runtime_t *runtime) {
    redp2p_t *ctx;
    JSON_Value *request;
    JSON_Value *response;
    JSON_Object *obj;
    JSON_Object *out;
    int result;

    ctx = runtime->ctx;
    request = json_value_init_object();
    if (!request) {
        redp2p_set_error(ctx, "connect: lookup request allocation failed");
        return REDP2P_ERROR;
    }
    obj = json_value_get_object(request);
    json_object_set_string(obj, "op", "lookup");
    json_object_set_string(obj, "id", runtime->target_id);
    response = NULL;
    result = redp2p_http_client(ctx, "connect", runtime->index_host,
        runtime->index_port, request, &response);
    json_value_free(request);
    if (result != REDP2P_OK) {
        if (result == REDP2P_ENOENT)
            redp2p_set_error(ctx, "connect: target publisher not found");
        return result;
    }
    out = json_value_get_object(response);
    runtime->n_peer_candidates = 0;
    if (!out ||
        !redp2p_index_parse_candidates(out, "candidates",
            runtime->peer_candidates, &runtime->n_peer_candidates))
    {
        json_value_free(response);
        redp2p_set_error(ctx, "connect: malformed lookup response");
        return REDP2P_EPROTO;
    }
    json_value_free(response);
    redp2p_set_error(ctx, NULL);
    return REDP2P_OK;
}

/**
 * Builds the consumer read set while closing unrepresentable sessions.
 * @param runtime Consumer runtime containing all descriptors.
 * @param fds Output descriptor set.
 * @param maxfd Output highest descriptor.
 * @return 1 when selectable, 0 after a session close, or -1 on fatal error.
 */
static int redp2p_consumer_fdset_build(
redp2p_consumer_runtime_t *runtime,
fd_set *fds,
int *maxfd)
{
    int failed;
    int i;

    FD_ZERO(fds);
    *maxfd = -1;
    if (!redp2p_fdset_add(runtime->local_fd, fds, maxfd)) {
        redp2p_set_error(runtime->ctx,
            "connect: local descriptor cannot be represented by fd_set");
        return -1;
    }
    if (!REDP2P_ISERR(runtime->tcp_listen_fd) &&
        !redp2p_fdset_add(runtime->tcp_listen_fd, fds, maxfd))
    {
        redp2p_set_error(runtime->ctx,
            "connect: listener cannot be represented by fd_set");
        return -1;
    }

    failed = 0;
    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (!redp2p_fdset_add(runtime->sessions[i].fd, fds, maxfd)) {
            redp2p_set_error(runtime->ctx,
                "connect: peer descriptor cannot be represented by fd_set");
            if (runtime->sessions[i].is_tcp) {
                redp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
            }
            redp2p_consumer_session_close(&runtime->sessions[i]);
            failed = 1;
            continue;
        }
        if (!runtime->sessions[i].is_tcp ||
            runtime->sessions[i].tcp_fd == REDP2P_FD_INVALID ||
            !redp2p_stream_can_send_data(&runtime->sessions[i].stream))
            continue;
        if (!redp2p_fdset_add(runtime->sessions[i].tcp_fd, fds, maxfd)) {
            redp2p_set_error(runtime->ctx,
                "connect: client descriptor cannot be represented by fd_set");
            redp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
            redp2p_consumer_session_close(&runtime->sessions[i]);
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
static int redp2p_consumer_tcp_accept(
redp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    unsigned char session_bin[REDP2P_STREAM_SESSION_ID_SZ];
    char session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    struct sockaddr_storage peer_addr;
    redp2p_udp_consumer_session_t session;
    redp2p_fd_t client_fd;
    redp2p_fd_t peer_fd;
    int skip_iteration;

    if (REDP2P_ISERR(runtime->tcp_listen_fd) ||
        !FD_ISSET(runtime->tcp_listen_fd, fds))
        return 0;
    client_fd = accept(runtime->tcp_listen_fd, NULL, NULL);
    if (REDP2P_ISERR(client_fd)) return 0;
    if (redp2p_consumer_establish_peer(runtime, 1, &peer_fd, &peer_addr,
        session_bin, session_hex, &skip_iteration) != REDP2P_OK)
    {
        REDP2P_FD_CLOSE(client_fd);
        return skip_iteration;
    }
    if (redp2p_consumer_tcp_session_init(runtime, &session, peer_fd, &peer_addr,
        client_fd, session_bin, session_hex) != 0)
    {
        REDP2P_FD_CLOSE(peer_fd);
        REDP2P_FD_CLOSE(client_fd);
        crypto_wipe(session_bin, sizeof(session_bin));
        crypto_wipe(session_hex, sizeof(session_hex));
        return 1;
    }
    crypto_wipe(session_bin, sizeof(session_bin));
    crypto_wipe(session_hex, sizeof(session_hex));
    return redp2p_consumer_session_insert(runtime, &session) < 0 ? 1 : 0;
}

/**
 * Receives one local UDP datagram and finds or creates its peer session.
 * @param runtime Consumer runtime owning UDP sessions.
 * @param fds Selected descriptor set.
 * @return 1 when processing may continue, or 0 after oversized input.
 */
static int redp2p_consumer_udp_receive(
redp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    unsigned char session_bin[REDP2P_STREAM_SESSION_ID_SZ];
    char session_hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    char buf[REDP2P_BUF];
    struct sockaddr_storage from;
    struct sockaddr_storage peer_addr;
    redp2p_udp_consumer_session_t session;
    redp2p_fd_t peer_fd;
    socklen_t fromlen;
    int found;
    int n;

    if (!REDP2P_ISERR(runtime->tcp_listen_fd) ||
        !FD_ISSET(runtime->local_fd, fds))
        return 1;
    fromlen = sizeof(from);
    n = (int)recvfrom(runtime->local_fd, buf, sizeof(buf), 0,
        (struct sockaddr *)&from, &fromlen);
    if (n < 0) return 1;
    if ((size_t)n > REDP2P_UDP_PAYLOAD_MAX) {
        redp2p_set_error(runtime->ctx,
            "UDP datagram exceeds maximum payload size");
        return 0;
    }

    found = redp2p_consumer_session_find(runtime, &from);
    if (found < 0 && redp2p_consumer_establish_peer(runtime, 0, &peer_fd,
        &peer_addr, session_bin, session_hex, NULL) == REDP2P_OK)
    {
        redp2p_consumer_udp_session_init(&session, peer_fd, &peer_addr, &from);
        crypto_wipe(session_bin, sizeof(session_bin));
        crypto_wipe(session_hex, sizeof(session_hex));
        found = redp2p_consumer_session_insert(runtime, &session);
    }
    if (found >= 0) {
        redp2p_sendto_addr(runtime->sessions[found].fd, buf, (size_t)n,
            &runtime->sessions[found].peer_addr);
        runtime->sessions[found].last_rx = redp2p_now_s();
    }
    return 1;
}

/**
 * Pumps readable local TCP clients into their peer streams.
 * @param runtime Consumer runtime containing TCP sessions.
 * @param fds Selected descriptor set.
 * @return None.
 */
static void redp2p_consumer_tcp_pump(
redp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    int i;

    if (REDP2P_ISERR(runtime->tcp_listen_fd)) return;
    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (!FD_ISSET(runtime->sessions[i].tcp_fd, fds)) continue;
        if (redp2p_stream_pump_tcp(runtime->ctx,
            &runtime->sessions[i].stream, runtime->sessions[i].tcp_fd) != 0)
        {
            redp2p_stream_fail(runtime->ctx, &runtime->sessions[i].stream);
            redp2p_consumer_session_close(&runtime->sessions[i]);
        }
    }
}

/**
 * Receives selected peer packets in session-table order.
 * @param runtime Consumer runtime containing peer sessions.
 * @param fds Selected descriptor set.
 * @return None.
 */
static void redp2p_consumer_peer_receive(
redp2p_consumer_runtime_t *runtime,
const fd_set *fds)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        char buf[REDP2P_BUF];
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
            (size_t)n > REDP2P_UDP_PAYLOAD_MAX)
        {
            redp2p_set_error(runtime->ctx,
                "UDP datagram exceeds maximum payload size");
            continue;
        }
        if (!redp2p_sockaddr_equal(&from, &runtime->sessions[i].peer_addr))
            continue;
        plain_keepalive = !runtime->sessions[i].is_tcp &&
            (size_t)n == strlen(REDP2P_CTRTOK_KA) &&
            memcmp(buf, REDP2P_CTRTOK_KA, strlen(REDP2P_CTRTOK_KA)) == 0;
        punch_control = ((size_t)n >= strlen(REDP2P_CTRTOK_PUNCH) &&
            strncmp(buf, REDP2P_CTRTOK_PUNCH,
                strlen(REDP2P_CTRTOK_PUNCH)) == 0) ||
            ((size_t)n >= strlen(REDP2P_CTRTOK_PUNCH_PING) &&
            strncmp(buf, REDP2P_CTRTOK_PUNCH_PING,
                strlen(REDP2P_CTRTOK_PUNCH_PING)) == 0) ||
            ((size_t)n >= strlen(REDP2P_CTRTOK_PUNCH_PONG) &&
            strncmp(buf, REDP2P_CTRTOK_PUNCH_PONG,
                strlen(REDP2P_CTRTOK_PUNCH_PONG)) == 0);
        if (plain_keepalive) {
            runtime->sessions[i].last_rx = redp2p_now_s();
        } else if (punch_control) {
            continue;
        } else {
            if (runtime->sessions[i].is_tcp) {
                if (runtime->sessions[i].tcp_fd != REDP2P_FD_INVALID &&
                    redp2p_stream_process_packet(runtime->ctx,
                        &runtime->sessions[i].stream,
                        runtime->sessions[i].tcp_fd,
                        (const unsigned char *)buf, (size_t)n) != 0)
                {
                    redp2p_stream_fail(runtime->ctx,
                        &runtime->sessions[i].stream);
                    redp2p_consumer_session_close(&runtime->sessions[i]);
                }
            } else {
                redp2p_sendto_addr(runtime->local_fd, buf, (size_t)n,
                    &runtime->sessions[i].client_addr);
            }
            runtime->sessions[i].last_rx = redp2p_now_s();
        }
    }
}

/**
 * Advances stream state, keepalives, and idle expiry in table order.
 * @param runtime Consumer runtime containing active sessions.
 * @return None.
 */
static void redp2p_consumer_session_maintain(
redp2p_consumer_runtime_t *runtime)
{
    int i;

    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active) continue;
        if (runtime->sessions[i].is_tcp) {
            if (redp2p_stream_tick(runtime->ctx,
                &runtime->sessions[i].stream) != 0)
            {
                redp2p_stream_fail(runtime->ctx,
                    &runtime->sessions[i].stream);
                redp2p_consumer_session_close(&runtime->sessions[i]);
                continue;
            }
            if (redp2p_stream_is_done(&runtime->sessions[i].stream)) {
                redp2p_consumer_session_close(&runtime->sessions[i]);
                continue;
            }
        }
        if (redp2p_now_s() - runtime->sessions[i].last_ka >
            REDP2P_KEEPALIVE_S)
        {
            if (!runtime->sessions[i].is_tcp) {
                redp2p_sendto_addr(runtime->sessions[i].fd, REDP2P_CTRTOK_KA,
                    strlen(REDP2P_CTRTOK_KA),
                    &runtime->sessions[i].peer_addr);
            }
            runtime->sessions[i].last_ka = redp2p_now_s();
        }
        if (redp2p_now_s() - runtime->sessions[i].last_rx >
            REDP2P_DISCONNECT_S)
        {
            redp2p_consumer_session_close(&runtime->sessions[i]);
        }
    }
}

/**
 * Finds the nearest consumer-side KCP deadline.
 * @return Milliseconds until select should wake, capped at one second.
 */
static uint32_t redp2p_consumer_wait_ms(
    const redp2p_consumer_runtime_t *runtime)
{
    uint32_t wait_ms;
    uint32_t session_wait;
    uint64_t now;
    int i;

    wait_ms = 1000;
    now = redp2p_now_ms();
    for (i = 0; i < runtime->n_sessions; i++) {
        if (!runtime->sessions[i].active || !runtime->sessions[i].is_tcp)
            continue;
        session_wait = redp2p_stream_wait_ms(&runtime->sessions[i].stream, now);
        if (session_wait < wait_ms) wait_ms = session_wait;
    }
    return wait_ms;
}

/**
 * Runs the consumer event loop with the existing phase ordering.
 * @param runtime Initialized and target-validated consumer runtime.
 * @return REDP2P_OK on stop, or REDP2P_ENET on fatal descriptor failure.
 */
static int redp2p_consumer_loop(redp2p_consumer_runtime_t *runtime) {
    int result;

    result = REDP2P_OK;
    fprintf(stderr, "redp2p: %s edge adapter on 127.0.0.1:%u for %s\n",
        runtime->ctx->proto == REDP2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)runtime->ctx->bind_port, runtime->target_id);
    redp2p_set_nonblock(runtime->local_fd);
    if (!REDP2P_ISERR(runtime->tcp_listen_fd))
        redp2p_set_nonblock(runtime->tcp_listen_fd);

    while (!runtime->ctx->stop_requested) {
        fd_set fds;
        struct timeval tv;
        int fdset_result;
        int maxfd;
        int selected;
        uint32_t wait_ms;

        fdset_result = redp2p_consumer_fdset_build(runtime, &fds, &maxfd);
        if (fdset_result < 0) {
            result = REDP2P_ENET;
            break;
        }
        if (fdset_result == 0) continue;
        wait_ms = redp2p_consumer_wait_ms(runtime);
        tv.tv_sec = (long)(wait_ms / 1000u);
        tv.tv_usec = (long)((wait_ms % 1000u) * 1000u);
        selected = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (selected < 0) continue;
        if (runtime->ctx->stop_requested) break;

        if (redp2p_consumer_tcp_accept(runtime, &fds)) {
            redp2p_consumer_session_maintain(runtime);
            continue;
        }
        if (!REDP2P_ISERR(runtime->tcp_listen_fd)) {
            redp2p_consumer_tcp_pump(runtime, &fds);
        } else if (!redp2p_consumer_udp_receive(runtime, &fds)) {
            redp2p_consumer_session_maintain(runtime);
            continue;
        }
        redp2p_consumer_peer_receive(runtime, &fds);
        redp2p_consumer_session_maintain(runtime);
    }
    return result;
}

/**
 * Releases every resource owned by one consumer runtime.
 * @param runtime Consumer runtime to release.
 * @param reset_stop Non-zero consumes the context stop request.
 * @return None.
 */
static void redp2p_consumer_runtime_cleanup(
redp2p_consumer_runtime_t *runtime,
int reset_stop)
{
    redp2p_consumer_session_close_all(runtime);
    if (runtime->sessions) {
        crypto_wipe(runtime->sessions,
            (size_t)runtime->cap_sessions * sizeof(*runtime->sessions));
    }
    free(runtime->sessions);
    runtime->sessions = NULL;
    runtime->n_sessions = 0;
    runtime->cap_sessions = 0;
    if (!REDP2P_ISERR(runtime->local_fd)) {
        REDP2P_FD_CLOSE(runtime->local_fd);
        runtime->local_fd = REDP2P_FD_INVALID;
    }
    if (!REDP2P_ISERR(runtime->tcp_listen_fd)) {
        REDP2P_FD_CLOSE(runtime->tcp_listen_fd);
        runtime->tcp_listen_fd = REDP2P_FD_INVALID;
    }
    if (runtime->platform_initialized) {
        redp2p_platform_cleanup();
        runtime->platform_initialized = 0;
    }
    if (reset_stop) atomic_store(&runtime->ctx->stop_requested, 0);
}

/**
 * Runs the consumer lifecycle for one local edge adapter.
 * @return Existing public REDP2P result code.
 */
int redp2p_connect(
redp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port)
{
    redp2p_consumer_runtime_t runtime;
    int loop_ran;
    int result;
    int should_run;

    if (!ctx) return REDP2P_EINVAL;
    loop_ran = 0;

    result = redp2p_consumer_runtime_init(&runtime, ctx, index_host, index_port,
        self_id, target_id, bind_port, &should_run);
    if (result != REDP2P_OK || !should_run) {
        redp2p_consumer_runtime_cleanup(&runtime, 0);
        return result;
    }
    result = redp2p_consumer_initial_lookup(&runtime);
    if (result == REDP2P_OK) {
        loop_ran = 1;
        result = redp2p_consumer_loop(&runtime);
    }
    redp2p_consumer_runtime_cleanup(&runtime, loop_ran);
    return result;
}

#ifdef REDP2P_TEST_RANDOM
/**
 * Generates one registration key through the test-visible path.
 * @param out Output key buffer.
 * @return 1 on success, 0 on error.
 */
int redp2p_test_generate_key(char *out) {
    return redp2p_generate_key(out);
}

/**
 * Generates one STUN transaction identifier through the test-visible path.
 * @param out Output transaction identifier.
 * @return 1 on success, 0 on error.
 */
int redp2p_test_stun_gen_id(unsigned char out[12]) {
    return redp2p_stun_gen_id(out);
}

/**
 * Generates one stream session identifier through the test-visible path.
 * @param out Output binary identifier.
 * @param hex Output hex identifier.
 * @return 1 on success, 0 on error.
 */
int redp2p_test_stream_make_session_id(
unsigned char out[REDP2P_STREAM_SESSION_ID_SZ],
char hex[REDP2P_STREAM_SESSION_ID_SZ * 2 + 1]
)
{
    return redp2p_stream_make_session_id(out, hex);
}

/**
 * Generates one register challenge nonce through the test-visible path.
 * @param hex Output hex nonce.
 * @return 1 on success, 0 on error.
 */
int redp2p_test_pow_nonce(char hex[17]) {
    unsigned char nonce[8];

    if (redp2p_fill_random(nonce, sizeof(nonce)) != 0) return 0;
    return redp2p_hex_encode(nonce, sizeof(nonce), hex, 17);
}

/**
 * Generates one UDP session identifier through the test-visible path.
 * @param hex Output hex session identifier.
 * @return 1 on success, 0 on error.
 */
int redp2p_test_udp_session_id(char hex[17]) {
    unsigned char session_id[8];

    if (redp2p_fill_random(session_id, sizeof(session_id)) != 0) return 0;
    return redp2p_hex_encode(session_id, sizeof(session_id), hex, 17);
}

/**
 * Compares STUN transaction identifiers through the test-visible path.
 * @param expected Expected transaction identifier.
 * @param actual   Actual transaction identifier.
 * @return 1 when equal, 0 otherwise.
 */
int redp2p_test_stun_id_matches(const unsigned char expected[12],
const unsigned char actual[12])
{
    return memcmp(expected, actual, 12) == 0;
}
#endif
