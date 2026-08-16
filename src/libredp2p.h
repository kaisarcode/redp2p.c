/**
 * libredp2p.h - REDP2P.
 * Summary: Public API for TCP rendezvous control and direct peer UDP transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef REDP2P_H
#define REDP2P_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct redp2p redp2p_t;

#define REDP2P_OK          0
#define REDP2P_ERROR      -1
#define REDP2P_ENET       -2
#define REDP2P_ENOENT     -3
#define REDP2P_ETIMEOUT   -4
#define REDP2P_EFULL      -5
#define REDP2P_EINVAL     -6
#define REDP2P_EPROTO     -7
#define REDP2P_EAUTH      -8
#define REDP2P_EVERSION   -9
#define REDP2P_EPUNCH    -10

#define REDP2P_ID_MAX         63
#define REDP2P_ADDR_MAX       47
#define REDP2P_BUF          4096
#define REDP2P_PORT_DEFAULT  9876
#define REDP2P_HEARTBEAT_S     15
#define REDP2P_KEY_SZ          16
#define REDP2P_KEY_STR_SZ      33
#define REDP2P_PASS_MAX       255
#define REDP2P_KEYS_DIR_MAX   511
#define REDP2P_UDP_PAYLOAD_MAX 1412
#define REDP2P_PEER_CANDIDATES_MAX  8

#define REDP2P_PROTO_TCP 1
#define REDP2P_PROTO_UDP 2

#define REDP2P_STUN_MAGIC 0x2112A442
#define REDP2P_STUN_ATTR_MAPPED_ADDR     0x0001
#define REDP2P_STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define REDP2P_STUN_BINDING      0x0001
#define REDP2P_STUN_BINDING_RESP 0x0101

typedef struct redp2p_options {
    size_t seats;
    int pow;
    char pass[REDP2P_PASS_MAX + 1];
    char *vip;
    int sweep;
    char stun_url[256];
} redp2p_options_t;

/**
 * Candidate transport class.
 * Summary: Ranks direct candidates before public or observed candidates.
 */
typedef enum {
    REDP2P_CAND_HOST = 1,
    REDP2P_CAND_LAN,
    REDP2P_CAND_PUBLIC,
    REDP2P_CAND_SRFLX,
    REDP2P_CAND_PRFLX,
    REDP2P_CAND_PREDICTED,
    REDP2P_CAND_PROXY
} redp2p_candidate_type_t;

/**
 * Candidate endpoint exchanged through the coordination control channel.
 * Summary: The priority is local-only and is recomputed after parsing.
 */
typedef struct {
    redp2p_candidate_type_t type;
    char addr[REDP2P_ADDR_MAX + 1];
    unsigned short port;
    unsigned int priority;
} redp2p_candidate_t;

/**
 * Index publisher record.
 * Summary: Records live or die by TTL from last_seen, not connection lifetime.
 */
typedef struct {
    char id[REDP2P_ID_MAX + 1];
    char key[REDP2P_KEY_STR_SZ];
    time_t last_seen;
    int proto;
    unsigned short udp_port;
    redp2p_candidate_t candidates[REDP2P_PEER_CANDIDATES_MAX];
    int n_candidates;
} redp2p_peer_t;

/**
 * Publisher listing callback.
 * @param id Publisher identifier registered in the index.
 * @param userdata Caller-owned pointer passed through unchanged.
 * @return None.
 */
typedef void (*redp2p_publisher_cb)(
const char *id,
void *userdata
);

/**
 * Returns initialized caller-owned runtime options.
 * @return Options value with documented defaults.
 */
redp2p_options_t redp2p_options_default(void);

/**
 * Loads publisher or consumer REDP2P environment settings into options.
 * @param opts Caller-owned options initialized by redp2p_options_default.
 * @return None.
 */
void redp2p_options_load_env(redp2p_options_t *opts);

/**
 * Releases allocations owned by one options value.
 * @param opts Caller-owned options value.
 * @return None.
 */
void redp2p_options_free(redp2p_options_t *opts);

/**
 * Allocates one independent REDP2P context.
 * @param out Receives the caller-owned context.
 * @return REDP2P_OK on success or REDP2P_ERROR on allocation failure.
 */
int redp2p_open(redp2p_t **out);

/**
 * Closes descriptors, wipes session state, and releases one context.
 * @param ctx Context returned by redp2p_open.
 * @return REDP2P_OK on success or REDP2P_ERROR for NULL.
 */
int redp2p_close(redp2p_t *ctx);

/**
 * Request clean termination for the current blocking operation on one context.
 * @param ctx Context to stop.
 * @return REDP2P_OK on success or REDP2P_EINVAL for NULL.
 */
int redp2p_stop(redp2p_t *ctx);

/**
 * Checks whether one context was requested to stop.
 * Summary: Thread-safe and async-signal-safe query of the stop flag.
 * @param ctx Context to query.
 * @return Nonzero if a stop was requested, zero otherwise.
 */
int redp2p_stop_requested(redp2p_t *ctx);

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t redp2p_version(void);

/**
 * Returns a stable static description for one REDP2P status category.
 * @param code REDP2P status code.
 * @return Static string requiring no release.
 */
const char *redp2p_strerror(int code);

/**
 * Returns the last per-context detail error message.
 * @param ctx Context to query.
 * @return Context-owned string valid until the next update or context close.
 */
const char *redp2p_get_error(redp2p_t *ctx);

/**
 * Validates one ASCII service identifier.
 * @param id Identifier to validate.
 * @return 1 when valid, 0 otherwise.
 */
int redp2p_is_valid_id(const char *id);

/**
 * Validates one terminal-safe password token.
 * @param pass Token to validate.
 * @return 1 when valid, 0 otherwise.
 */
int redp2p_is_valid_pass_token(const char *pass);

/**
 * INDEX SERVER
 * Binds a TCP socket and enters a blocking loop handling
 * REGISTER / DEREGISTER / LIST / LOOKUP / PUNCH_REQ2.
 * Never returns on success.
 * @return Negative error code on setup failure.
 */
int redp2p_serve_index(
redp2p_t *ctx,
const char *host,
unsigned short port
);

/**
 * CLIENT: Publish a local service through the rendezvous index.
 * Connects to the index over TCP, REGISTERs, and waits for PUNCH_CALL2
 * requests over the same TCP connection. Creates one backend session
 * per connecting client.
 * @return REDP2P_OK on clean exit, or a negative error code.
 */
int redp2p_wait(
redp2p_t *ctx,
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
 * @return REDP2P_OK on clean exit, or a negative error code.
 */
int redp2p_connect(
redp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port
);

/**
 * CLIENT: Deregister from an index server over TCP.
 * Used by `redp2p del` and internally on shutdown.
 * @return REDP2P_OK on success, or a negative error code.
 */
int redp2p_deregister(
redp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *id
);

/**
 * CLIENT: List publishers registered in an index server over TCP.
 * Calls cb once for each active publisher id returned by the index.
 * @return REDP2P_OK on success, or a negative error code.
 */
int redp2p_list_publishers(
redp2p_t *ctx,
const char *index_host,
unsigned short index_port,
redp2p_publisher_cb cb,
void *userdata
);

/**
 * Sets the number of index publisher seats.
 * @param ctx Open context.
 * @param seats Total publisher seats; VIP reservations count toward the total.
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_seats(redp2p_t *ctx, size_t seats);

/**
 * Sets registration proof difficulty.
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_pow(redp2p_t *ctx, int bits);

/**
 * Sets the local nonzero service port.
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_port(redp2p_t *ctx, unsigned short port);

/**
 * Selects TCP or UDP edge transport.
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_protocol(redp2p_t *ctx, int proto);

/**
 * Sets publisher registration protection.
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_pass(redp2p_t *ctx, const char *pass);

/**
 * Sets reserved publisher IDs and registration passwords.
 * @return REDP2P_OK or a negative error category.
 */
int redp2p_set_vip(
redp2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
);

/**
 * Sets the bounded direct-punch port sweep range.
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_sweep(
redp2p_t *ctx,
int sweep
);

/**
 * Sets or disables the optional STUN discovery URL.
 * @return REDP2P_OK or a negative error category.
 */
int redp2p_set_stun_url(
redp2p_t *ctx,
const char *url
);

/**
 * Sets the base directory for publisher deregistration key files.
 * Summary: Overrides the default $HOME/.local/share/redp2p/keys path.
 * When empty, resets to the default path derived from $HOME.
 * @param ctx Open context.
 * @param dir Base directory path (non-NULL).
 * @return REDP2P_OK or REDP2P_EINVAL.
 */
int redp2p_set_keys_dir(
redp2p_t *ctx,
const char *dir
);

/**
 * Executes a CLI subcommand from a JSON payload and returns the result as a
 * JSON string. Synchronous one-shot commands (del, list) run directly.
 * Long-lived commands (open/status/stop/close) manage a background thread
 * per handle so pub, con, and idx run without blocking the caller.
 * @param payload_json JSON payload with "cmd" and "args".
 * @param out_err Receives a malloc'd error message on failure, or NULL on
 *     success.
 * @return malloc'd JSON result string, or NULL on failure.
 */
char *kc_redp2p_run(const char *payload_json, char **out_err);

#ifdef __cplusplus
}
#endif

#endif
