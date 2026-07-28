/**
 * rp2p.h - RedP2P.
 * Summary: Public API for TCP rendezvous control and direct peer UDP transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef RP2P_H
#define RP2P_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rp2p rp2p_t;

#define RP2P_OK          0
#define RP2P_ERROR      -1
#define RP2P_ENET       -2
#define RP2P_ENOENT     -3
#define RP2P_ETIMEOUT   -4
#define RP2P_EFULL      -5
#define RP2P_EINVAL     -6
#define RP2P_EPROTO     -7
#define RP2P_EAUTH      -8
#define RP2P_EVERSION   -9
#define RP2P_EPUNCH    -10

#define RP2P_ID_MAX         63
#define RP2P_ADDR_MAX       47
#define RP2P_BUF          4096
#define RP2P_PORT_DEFAULT  9876
#define RP2P_HEARTBEAT_S     15
#define RP2P_KEY_SZ          16
#define RP2P_KEY_STR_SZ      33
#define RP2P_PASS_MAX       255
#define RP2P_UDP_PAYLOAD_MAX 1412

#define RP2P_PROTO_TCP 1
#define RP2P_PROTO_UDP 2

#define RP2P_STUN_MAGIC 0x2112A442
#define RP2P_STUN_ATTR_MAPPED_ADDR     0x0001
#define RP2P_STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define RP2P_STUN_BINDING      0x0001
#define RP2P_STUN_BINDING_RESP 0x0101

typedef struct rp2p_options {
    int seats;
    int pow;
    char pass[RP2P_PASS_MAX + 1];
    char *vip;
    int sweep;
    char stun_url[256];
} rp2p_options_t;

typedef struct {
    char id[RP2P_ID_MAX + 1];
    char key[RP2P_KEY_STR_SZ];
    time_t last_seen;
} rp2p_peer_t;

/**
 * Candidate transport class.
 * Summary: Ranks direct candidates before public or observed candidates.
 */
typedef enum {
    RP2P_CAND_HOST = 1,
    RP2P_CAND_LAN,
    RP2P_CAND_PUBLIC,
    RP2P_CAND_SRFLX,
    RP2P_CAND_PRFLX,
    RP2P_CAND_PREDICTED,
    RP2P_CAND_PROXY
} rp2p_candidate_type_t;

/**
 * Candidate endpoint exchanged through the TCP rendezvous control channel.
 * Summary: The priority is local-only and is recomputed after parsing.
 */
typedef struct {
    rp2p_candidate_type_t type;
    char addr[RP2P_ADDR_MAX + 1];
    unsigned short port;
    unsigned int priority;
} rp2p_candidate_t;

/**
 * Publisher listing callback.
 * @param id Publisher identifier registered in the index.
 * @param userdata Caller-owned pointer passed through unchanged.
 * @return None.
 */
typedef void (*rp2p_publisher_cb)(
const char *id,
void *userdata
);

/**
 * Returns initialized caller-owned runtime options.
 * @return Options value with documented defaults.
 */
rp2p_options_t rp2p_options_default(void);

/**
 * Loads publisher or consumer RP2P environment settings into options.
 * @param opts Caller-owned options initialized by rp2p_options_default.
 * @return None.
 */
void rp2p_options_load_env(rp2p_options_t *opts);

/**
 * Releases allocations owned by one options value.
 * @param opts Caller-owned options value.
 * @return None.
 */
void rp2p_options_free(rp2p_options_t *opts);

/**
 * Allocates one independent RP2P context.
 * @param out Receives the caller-owned context.
 * @return RP2P_OK on success or RP2P_ERROR on allocation failure.
 */
int rp2p_open(rp2p_t **out);

/**
 * Closes descriptors, wipes session state, and releases one context.
 * @param ctx Context returned by rp2p_open.
 * @return RP2P_OK on success or RP2P_ERROR for NULL.
 */
int rp2p_close(rp2p_t *ctx);

/**
 * Request clean termination for the current blocking operation on one context.
 * @param ctx Context to stop.
 * @return RP2P_OK on success or RP2P_EINVAL for NULL.
 */
int rp2p_stop(rp2p_t *ctx);

/**
 * Checks whether one context was requested to stop.
 * Summary: Thread-safe and async-signal-safe query of the stop flag.
 * @param ctx Context to query.
 * @return Nonzero if a stop was requested, zero otherwise.
 */
int rp2p_stop_requested(rp2p_t *ctx);

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t rp2p_version(void);

/**
 * Returns a stable static description for one RP2P status category.
 * @param code RP2P status code.
 * @return Static string requiring no release.
 */
const char *rp2p_strerror(int code);

/**
 * Returns the last per-context detail error message.
 * @param ctx Context to query.
 * @return Context-owned string valid until the next update or context close.
 */
const char *rp2p_get_error(rp2p_t *ctx);

/**
 * Validates one ASCII service identifier.
 * @param id Identifier to validate.
 * @return 1 when valid, 0 otherwise.
 */
int rp2p_is_valid_id(const char *id);

/**
 * Validates one terminal-safe password token.
 * @param pass Token to validate.
 * @return 1 when valid, 0 otherwise.
 */
int rp2p_is_valid_pass_token(const char *pass);

/**
 * INDEX SERVER
 * Binds a TCP socket and enters a blocking loop handling
 * REGISTER / DEREGISTER / LIST / LOOKUP / PUNCH_REQ2.
 * Never returns on success.
 * @return Negative error code on setup failure.
 */
int rp2p_serve_index(
rp2p_t *ctx,
const char *host,
unsigned short port
);

/**
 * CLIENT: Publish a local service through the rendezvous index.
 * Connects to the index over TCP, REGISTERs, and waits for PUNCH_CALL2
 * requests over the same TCP connection. Creates one backend session
 * per connecting client.
 * @return RP2P_OK on clean exit, or a negative error code.
 */
int rp2p_wait(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
unsigned short bind_port
);

/**
 * CLIENT: Expose a remote service on a local port.
 * Uses TCP for LOOKUP + PUNCH_REQ2 to the index. For TCP stream forwarding
 * over direct UDP, creates a local TCP listener and uses a direct peer UDP
 * path for the reliable stream. For UDP datagram forwarding, creates
 * a UDP socket and hole-punches directly to the publisher.
 * @return RP2P_OK on clean exit, or a negative error code.
 */
int rp2p_connect(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port
);

/**
 * CLIENT: Deregister from an index server over TCP.
 * Used by `rp2p del` and internally on shutdown.
 * @return RP2P_OK on success, or a negative error code.
 */
int rp2p_deregister(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *id
);

/**
 * CLIENT: List publishers registered in an index server over TCP.
 * Calls cb once for each active publisher id returned by the index.
 * @return RP2P_OK on success, or a negative error code.
 */
int rp2p_list_publishers(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
rp2p_publisher_cb cb,
void *userdata
);

/**
 * Sets the index publisher capacity.
 * @return RP2P_OK or RP2P_EINVAL.
 */
int rp2p_set_seats(rp2p_t *ctx, int seats);

/**
 * Sets registration proof difficulty.
 * @return RP2P_OK or RP2P_EINVAL.
 */
int rp2p_set_pow(rp2p_t *ctx, int bits);

/**
 * Sets the local nonzero service port.
 * @return RP2P_OK or RP2P_EINVAL.
 */
int rp2p_set_port(rp2p_t *ctx, unsigned short port);

/**
 * Selects TCP or UDP edge transport.
 * @return RP2P_OK or RP2P_EINVAL.
 */
int rp2p_set_protocol(rp2p_t *ctx, int proto);

/**
 * Sets publisher registration protection.
 * @return RP2P_OK or RP2P_EINVAL.
 */
int rp2p_set_pass(rp2p_t *ctx, const char *pass);

/**
 * Sets reserved publisher IDs and registration passwords.
 * @return RP2P_OK or a negative error category.
 */
int rp2p_set_vip(
rp2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
);

/**
 * Sets the bounded direct-punch port sweep range.
 * @return RP2P_OK or RP2P_EINVAL.
 */
int rp2p_set_sweep(
rp2p_t *ctx,
int sweep
);

/**
 * Sets or disables the optional STUN discovery URL.
 * @return RP2P_OK or a negative error category.
 */
int rp2p_set_stun_url(
rp2p_t *ctx,
const char *url
);

#ifdef __cplusplus
}
#endif

#endif
