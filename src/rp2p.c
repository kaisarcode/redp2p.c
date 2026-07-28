/**
 * rp2p.c - RedP2P.
 * Summary: RP2P tunnel CLI - idx, set, del, con.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "librp2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#ifdef _WIN32
#  include <process.h>
#  include <windows.h>
#else
#  include <unistd.h>
#include <sys/stat.h>
#endif

/**
 * Parses one bounded ASCII decimal integer.
 * @param text Input decimal text.
 * @param min  Inclusive lower bound.
 * @param max  Inclusive upper bound.
 * @param out  Output parsed value.
 * @return 0 on success, 1 on invalid input.
 */
static int parse_decimal(const char *text, long min, long max, long *out) {
    unsigned long value;
    unsigned long limit;
    size_t i;

    if (!text || !text[0] || !out || min < 0 || max < min) return 1;
    value = 0;
    limit = (unsigned long)max;
    for (i = 0; text[i] != '\0'; i++) {
        unsigned long digit;

        if (text[i] < '0' || text[i] > '9') return 1;
        digit = (unsigned long)(text[i] - '0');
        if (digit > limit) return 1;
        if (value > (limit - digit) / 10) return 1;
        value = value * 10 + digit;
    }
    if (value < (unsigned long)min) return 1;
    *out = (long)value;
    return 0;
}

/**
 * Parses host and optional port from a string.
 * Summary: Supports host, host:port, IPv4:port, [IPv6], and [IPv6]:port.
 * @param text     Input address string.
 * @param host     Output host buffer.
 * @param host_sz  Output host buffer capacity.
 * @param port     Output port.
 * @return 0 on success, 1 on failure.
 */
static int parse_addr(const char *text, char *host, size_t host_sz,
    unsigned short *port)
{
    const char *colon;
    const char *end_bracket;
    long val;
    size_t n;

    if (!text || !text[0] || !host || host_sz == 0 || !port) return 1;
    *port = RP2P_PORT_DEFAULT;
    if (text[0] == '[') {
        end_bracket = strchr(text, ']');
        if (!end_bracket) return 1;
        n = (size_t)(end_bracket - text - 1);
        if (n == 0 || n >= host_sz) return 1;
        memcpy(host, text + 1, n);
        host[n] = '\0';
        if (end_bracket[1] == '\0') return 0;
        if (end_bracket[1] != ':' || end_bracket[2] == '\0') return 1;
        if (parse_decimal(end_bracket + 2, 1, 65535, &val) != 0) return 1;
        *port = (unsigned short)val;
        return 0;
    }
    colon = strrchr(text, ':');
    if (colon && strchr(text, ':') != colon) {
        n = strlen(text);
        if (n == 0 || n >= host_sz) return 1;
        memcpy(host, text, n + 1);
        return 0;
    }
    if (!colon) {
        n = strlen(text);
        if (n == 0 || n >= host_sz) return 1;
        memcpy(host, text, n + 1);
        return 0;
    }
    if (colon == text || colon[1] == '\0') return 1;
    n = (size_t)(colon - text);
    if (n == 0 || n >= host_sz) return 1;
    memcpy(host, text, n);
    host[n] = '\0';
    if (parse_decimal(colon + 1, 1, 65535, &val) != 0) return 1;
    *port = (unsigned short)val;
    return 0;
}

/**
 * Parses hostname@index:port spec string.
 * Summary: Splits on '@', parses the index part as addr:port.
 * @param spec     Input spec string (hostname@addr:port).
 * @param hostname Output hostname buffer.
 * @param hn_sz    Output hostname buffer capacity.
 * @param idx_addr Output index address buffer.
 * @param ia_sz    Output index address buffer capacity.
 * @param idx_port Output index port.
 * @return 0 on success, 1 on failure.
 */
static int parse_hostspec(const char *spec, char *hostname, size_t hn_sz,
    char *idx_addr, size_t ia_sz, unsigned short *idx_port)
{
    const char *at;
    size_t n;

    if (!spec || !spec[0]) return 1;
    at = strrchr(spec, '@');
    if (!at || at == spec) return 1;

    n = (size_t)(at - spec);
    if (n == 0 || n >= hn_sz) return 1;
    memcpy(hostname, spec, n);
    hostname[n] = '\0';

    *idx_port = RP2P_PORT_DEFAULT;
    return parse_addr(at + 1, idx_addr, ia_sz, idx_port);
}

/**
 * Parses one strict TCP or UDP port from CLI text.
 * Summary: Rejects NULL, empty, signs, trailing garbage, overflow, and 0.
 * @param text Input text to parse.
 * @param out  Output parsed port.
 * @return 0 on success, 1 on failure.
 */
static int parse_port(const char *text, unsigned short *out) {
    long val;

    if (!out || parse_decimal(text, 1, 65535, &val) != 0) return 1;
    *out = (unsigned short)val;
    return 0;
}

/**
 * Parses one strict signed integer with explicit bounds from CLI text.
 * Summary: Rejects NULL, empty, signs, trailing garbage, and overflow.
 * @param text Input text to parse.
 * @param min  Inclusive lower bound.
 * @param max  Inclusive upper bound.
 * @param out  Output parsed value.
 * @return 0 on success, 1 on failure.
 */
static int parse_int(const char *text, long min, long max, long *out) {
    return parse_decimal(text, min, max, out);
}

/**
 * Loads only index-owned environment configuration.
 * @param opts Index options to populate.
 * @param seats_set Set when RP2P_SEATS contains a valid value.
 * @return 0 on success, 1 on allocation failure.
 */
static int load_index_options(rp2p_options_t *opts, int *seats_set) {
    const char *value;
    long number;
    size_t len;

    value = getenv("RP2P_SEATS");
    if (parse_decimal(value, 0, INT_MAX, &number) == 0) {
        opts->seats = (int)number;
        *seats_set = 1;
    }
    value = getenv("RP2P_POW");
    if (parse_decimal(value, 0, 32, &number) == 0)
        opts->pow = (int)number;
    value = getenv("RP2P_PASS");
    if (value) {
        strncpy(opts->pass, value, RP2P_PASS_MAX);
        opts->pass[RP2P_PASS_MAX] = '\0';
    }
    value = getenv("RP2P_VIP");
    if (!value) return 0;
    len = strlen(value);
    opts->vip = (char *)malloc(len + 1);
    if (!opts->vip) return 1;
    memcpy(opts->vip, value, len + 1);
    return 0;
}

/**
 * Prints usage information.
 * Summary: Shows available commands and options.
 * @param name Program executable name.
 * @return None.
 */
static void print_help(const char *name) {
    printf("Usage: %s <command> [options]\n", name);
    printf("\n");
    printf("Commands:\n");
    printf("  idx <port> [--max <N>] [--pow <N>] Start index server on TCP control port\n");
    printf("  set <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  set <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  del <host>@<index[:port]> Deregister from index\n");
    printf("  con <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  con <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]\n");
    printf("\n");
    printf("Environment:\n");
    printf("  RP2P_POW                PoW bits for index registration (0..32)\n");
    printf("  RP2P_PASS               Optional shared password for REGISTER/set protection\n");
    printf("  RP2P_VIP                Reserved seat passwords as '<id> <pass> ...'\n");
    printf("  RP2P_SWEEP              UDP port sweep range used during punch fallback\n");
    printf("  RP2P_STUN               Optional STUN URL (stun:host:port)\n");
    printf("  IDs may use only A-Z a-z 0-9\n");
    printf("  Passwords may use A-Z a-z 0-9 . _ - + = , : @ %% /\n");
}

/**
 * Program entry point.
 * Summary: Dispatches subcommands (idx, set, del, con).
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char **argv) {
    rp2p_t *ctx;
    int ret;

    if (argc < 2) { print_help(argv[0]); return 1; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { print_help(argv[0]); return 0; }
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("rp2p build %llu\n",
            (unsigned long long)rp2p_version());
        return 0;
    }

    if (strcmp(argv[1], "idx") == 0) {
        rp2p_options_t opts;
        unsigned short port;
        char vip_err[256];
        int seats;
        int seats_set;
        int pow_bits;
        int exit_code;

        opts = rp2p_options_default();
        seats_set = 0;
        if (load_index_options(&opts, &seats_set) != 0) {
            fprintf(stderr, "rp2p: failed to load index options\n");
            return 1;
        }
        seats = opts.seats;
        pow_bits = opts.pow;

        if (argc < 3) {
            fprintf(stderr, "rp2p: usage: %s idx <port>\n", argv[0]);
            rp2p_options_free(&opts);
            return 1;
        }
        if (parse_port(argv[2], &port) != 0) {
            fprintf(stderr, "rp2p: invalid port '%s'\n", argv[2]);
            rp2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--max") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --max requires an argument\n"); rp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, INT_MAX, &v) != 0) {
                    fprintf(stderr, "rp2p: invalid --max '%s'\n", argv[i]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                seats = (int)v;
                seats_set = 1;
            } else if (strcmp(argv[i], "--pow") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --pow requires an argument\n"); rp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, 32, &v) != 0) {
                    fprintf(stderr, "rp2p: invalid --pow '%s'\n", argv[i]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                pow_bits = (int)v;
            } else { fprintf(stderr, "rp2p: unknown option '%s'\n", argv[i]); rp2p_options_free(&opts); return 1; }
        }

        if (rp2p_open(&ctx) != RP2P_OK) {
            fprintf(stderr, "rp2p: failed to create context\n");
            rp2p_options_free(&opts);
            return 1;
        }
        if (rp2p_set_pass(ctx, opts.pass) != RP2P_OK) {
            fprintf(stderr, "rp2p: invalid RP2P_PASS characters\n");
            rp2p_close(ctx);
            rp2p_options_free(&opts);
            return 1;
        }
        if (seats_set && rp2p_set_seats(ctx, seats) != RP2P_OK) {
            fprintf(stderr, "rp2p: invalid publisher capacity: %s\n",
                rp2p_get_error(ctx));
            rp2p_close(ctx);
            rp2p_options_free(&opts);
            return 1;
        }
        rp2p_set_pow(ctx, pow_bits);
        vip_err[0] = '\0';
        if (rp2p_set_vip(ctx, opts.vip, vip_err, sizeof(vip_err)) != RP2P_OK) {
            fprintf(stderr, "rp2p: %s\n", vip_err[0] ? vip_err : "invalid RP2P_VIP");
            rp2p_close(ctx);
            rp2p_options_free(&opts);
            return 1;
        }

        ret = rp2p_serve_index(ctx, NULL, port);
        fprintf(stderr, "rp2p: index exited: %s\n", rp2p_strerror(ret));
        exit_code = ret == RP2P_OK ? 0 : 1;
        rp2p_close(ctx);
        rp2p_options_free(&opts);
        return exit_code;

    } else if (strcmp(argv[1], "set") == 0) {
        rp2p_options_t opts;
        char host[RP2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;
        unsigned short service_port = 0;
        int proto = 0;

        opts = rp2p_options_default();
        rp2p_options_load_env(&opts);

        if (argc < 3) { fprintf(stderr, "rp2p: usage: %s set <host>@<index[:port]>\n", argv[0]); rp2p_options_free(&opts); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "rp2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); rp2p_options_free(&opts); return 1;
        }
        if (!rp2p_is_valid_id(host)) {
            fprintf(stderr, "rp2p: invalid host id '%s'\n", host);
            rp2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--tcp") == 0) {
                if (proto != 0) { fprintf(stderr, "rp2p: choose only one of --tcp or --udp\n"); rp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --tcp requires a port\n"); rp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &service_port) != 0) {
                    fprintf(stderr, "rp2p: invalid --tcp port '%s'\n", argv[i + 1]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = RP2P_PROTO_TCP;
            } else if (strcmp(argv[i], "--udp") == 0) {
                if (proto != 0) { fprintf(stderr, "rp2p: choose only one of --tcp or --udp\n"); rp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --udp requires a port\n"); rp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &service_port) != 0) {
                    fprintf(stderr, "rp2p: invalid --udp port '%s'\n", argv[i + 1]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = RP2P_PROTO_UDP;
            } else if (strcmp(argv[i], "--sweep") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --sweep requires a number\n"); rp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, 1024, &v) != 0) {
                    fprintf(stderr, "rp2p: invalid --sweep '%s'\n", argv[i]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                opts.sweep = (int)v;
            } else if (strcmp(argv[i], "--stun") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --stun requires a URL\n"); rp2p_options_free(&opts); return 1; }
                strncpy(opts.stun_url, argv[++i], sizeof(opts.stun_url) - 1);
                opts.stun_url[sizeof(opts.stun_url) - 1] = '\0';
            } else { fprintf(stderr, "rp2p: unknown option '%s'\n", argv[i]); rp2p_options_free(&opts); return 1; }
        }

        if (proto == 0 || service_port == 0) { fprintf(stderr, "rp2p: set requires --tcp <port> or --udp <port>\n"); rp2p_options_free(&opts); return 1; }

        if (rp2p_open(&ctx) != RP2P_OK) { fprintf(stderr, "rp2p: failed to create context\n"); rp2p_options_free(&opts); return 1; }
        if (rp2p_set_pass(ctx, opts.pass) != RP2P_OK) {
            fprintf(stderr, "rp2p: invalid RP2P_PASS characters\n");
            rp2p_close(ctx);
            rp2p_options_free(&opts);
            return 1;
        }
        rp2p_set_protocol(ctx, proto);
        rp2p_set_port(ctx, service_port);
        rp2p_set_sweep(ctx, opts.sweep);
        rp2p_set_stun_url(ctx, opts.stun_url[0] ? opts.stun_url : NULL);

        fprintf(stderr, "rp2p: waiting for connections...\n");

        ret = rp2p_wait(ctx, idx_host, idx_port, host, 0);
        if (ret != RP2P_OK)
            fprintf(stderr, "rp2p: set exited: %s\n", rp2p_strerror(ret));

        rp2p_close(ctx);
        rp2p_options_free(&opts);
        return ret == RP2P_OK ? 0 : 1;

    } else if (strcmp(argv[1], "del") == 0) {
        char host[RP2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;

        if (argc < 3) { fprintf(stderr, "rp2p: usage: %s del <host>@<index[:port]>\n", argv[0]); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "rp2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); return 1;
        }
        if (!rp2p_is_valid_id(host)) {
            fprintf(stderr, "rp2p: invalid host id '%s'\n", host);
            return 1;
        }

        if (rp2p_open(&ctx) != RP2P_OK) { fprintf(stderr, "rp2p: failed to create context\n"); return 1; }
        ret = rp2p_deregister(ctx, idx_host, idx_port, host);
        if (ret != RP2P_OK) {
            fprintf(stderr, "rp2p: deregister failed: %s\n", rp2p_strerror(ret));
            rp2p_close(ctx);
            return 1;
        }
        rp2p_close(ctx);
        return 0;

    } else if (strcmp(argv[1], "con") == 0) {
        rp2p_options_t opts;
        char host[RP2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;
        unsigned short listen_port = 0;
        char self_id[32];
        int proto = 0;

        opts = rp2p_options_default();
        rp2p_options_load_env(&opts);

        if (argc < 3) { fprintf(stderr, "rp2p: usage: %s con <host>@<index[:port]>\n", argv[0]); rp2p_options_free(&opts); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "rp2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); rp2p_options_free(&opts); return 1;
        }
        if (!rp2p_is_valid_id(host)) {
            fprintf(stderr, "rp2p: invalid host id '%s'\n", host);
            rp2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--tcp") == 0) {
                if (proto != 0) { fprintf(stderr, "rp2p: choose only one of --tcp or --udp\n"); rp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --tcp requires a port\n"); rp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &listen_port) != 0) {
                    fprintf(stderr, "rp2p: invalid --tcp port '%s'\n", argv[i + 1]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = RP2P_PROTO_TCP;
            } else if (strcmp(argv[i], "--udp") == 0) {
                if (proto != 0) { fprintf(stderr, "rp2p: choose only one of --tcp or --udp\n"); rp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --udp requires a port\n"); rp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &listen_port) != 0) {
                    fprintf(stderr, "rp2p: invalid --udp port '%s'\n", argv[i + 1]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = RP2P_PROTO_UDP;
            } else if (strcmp(argv[i], "--sweep") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --sweep requires a number\n"); rp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, 1024, &v) != 0) {
                    fprintf(stderr, "rp2p: invalid --sweep '%s'\n", argv[i]);
                    rp2p_options_free(&opts);
                    return 1;
                }
                opts.sweep = (int)v;
            } else if (strcmp(argv[i], "--stun") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "rp2p: --stun requires a URL\n"); rp2p_options_free(&opts); return 1; }
                strncpy(opts.stun_url, argv[++i], sizeof(opts.stun_url) - 1);
                opts.stun_url[sizeof(opts.stun_url) - 1] = '\0';
            } else { fprintf(stderr, "rp2p: unknown option '%s'\n", argv[i]); rp2p_options_free(&opts); return 1; }
        }

        if (proto == 0 || listen_port == 0) { fprintf(stderr, "rp2p: con requires --tcp <port> or --udp <port>\n"); rp2p_options_free(&opts); return 1; }

        snprintf(self_id, sizeof(self_id), "c%d", (int)getpid());

        if (rp2p_open(&ctx) != RP2P_OK) { fprintf(stderr, "rp2p: failed to create context\n"); rp2p_options_free(&opts); return 1; }
        rp2p_set_protocol(ctx, proto);
        rp2p_set_port(ctx, listen_port);
        rp2p_set_sweep(ctx, opts.sweep);
        rp2p_set_stun_url(ctx, opts.stun_url[0] ? opts.stun_url : NULL);

        ret = rp2p_connect(ctx, idx_host, idx_port, self_id, host, 0);
        if (ret != RP2P_OK)
            fprintf(stderr, "rp2p: connect failed: %s\n", rp2p_strerror(ret));

        rp2p_close(ctx);
        rp2p_options_free(&opts);
        return ret == RP2P_OK ? 0 : 1;

    } else {
        fprintf(stderr, "rp2p: unknown command '%s'\n", argv[1]);
        fprintf(stderr, "rp2p: try '%s --help'\n", argv[0]);
        return 1;
    }
}
