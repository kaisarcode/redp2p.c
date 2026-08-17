/**
 * redp2p.c - REDP2P.
 * Summary: REDP2P tunnel CLI - idx, pub, con.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "libredp2p.h"
#include "parson.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#ifdef _WIN32
#include <direct.h>
#endif

static volatile sig_atomic_t g_stop_requested = 0;

/**
 * Signal handler for SIGINT/SIGTERM.
 * Sets the stop flag so the runner loop requests shutdown of the active
 * operation.
 * @param sig Signal number (unused).
 * @return None.
 */
static void sigint_handler(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

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
 * Parses one ASCII decimal size value.
 * @param text Input decimal text.
 * @param out Output parsed value.
 * @return 0 on success, 1 on invalid input or overflow.
 */
static int parse_size(const char *text, size_t *out) {
    size_t value;
    size_t i;

    if (!text || !text[0] || !out) return 1;
    value = 0;
    for (i = 0; text[i] != '\0'; i++) {
        size_t digit;

        if (text[i] < '0' || text[i] > '9') return 1;
        digit = (size_t)(text[i] - '0');
        if (value > (SIZE_MAX - digit) / 10) return 1;
        value = value * 10 + digit;
    }
    *out = value;
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
    *port = REDP2P_PORT_DEFAULT;
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

    *idx_port = REDP2P_PORT_DEFAULT;
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
 * @param seats_set Set when REDP2P_SEATS contains a valid value.
 * @return 0 on success, 1 on allocation failure.
 */
static int load_index_options(redp2p_options_t *opts, int *seats_set) {
    const char *value;
    long number;
    size_t seats;
    size_t len;

    value = getenv("REDP2P_SEATS");
    if (value) {
        if (parse_size(value, &seats) != 0 ||
            seats > SIZE_MAX / sizeof(redp2p_peer_t))
            return 1;
        opts->seats = seats;
        *seats_set = 1;
    }
    value = getenv("REDP2P_POW");
    if (parse_decimal(value, 0, 32, &number) == 0)
        opts->pow = (int)number;
    value = getenv("REDP2P_PASS");
    if (value) {
        strncpy(opts->pass, value, REDP2P_PASS_MAX);
        opts->pass[REDP2P_PASS_MAX] = '\0';
    }
    value = getenv("REDP2P_VIP");
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
    printf("  idx <port> [--seats <N>] [--pow <N>] Start index server\n");
    printf("  idx <port> -l, --list                  List local index publishers\n");
    printf("  idx <port> -p, --prune                 Prune expired index records\n");
    printf("  idx <port> -d, --down                   Stop a background index\n");
    printf("  pub <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  pub <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  pub <host>@<index[:port]> -d, --down    Stop a background publisher\n");
    printf("  con <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  con <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  con <host>@<index[:port]> -d, --down    Stop a background consumer\n");
    printf("\n");
    printf("Environment:\n");
    printf("  REDP2P_STATE_DIR          State directory base (default: $HOME/.local/share/redp2p)\n");
    printf("  REDP2P_SEATS              Publisher seats; VIPs count; unset means no limit\n");
    printf("  REDP2P_POW                PoW bits for index registration (0..32)\n");
    printf("  REDP2P_PASS               Optional shared password for REGISTER/pub protection\n");
    printf("  REDP2P_VIP                Reserved seat passwords as '<id> <pass> ...'\n");
    printf("  REDP2P_SWEEP              UDP port sweep range used during punch fallback\n");
    printf("  REDP2P_STUN               Optional STUN URL (stun:host:port)\n");
    printf("  REDP2P_PRUNE_INTERVAL_S   Index prune interval seconds (1..3600, default 60)\n");
    printf("  REDP2P_ETIMEOUT_SEC       Index eviction TTL seconds (1..86400, default 120)\n");
    printf("  REDP2P_HEARTBEAT_S        Publisher heartbeat interval seconds (1..3600, default 15)\n");
    printf("  REDP2P_PUNCH_POLL_MS      Publisher punch poll interval ms (10..60000, default 500)\n");
    printf("  IDs may use only A-Z a-z 0-9\n");
    printf("  Passwords may use A-Z a-z 0-9 . _ - + = , : @ %% /\n");
}

/**
 * Prints the publisher ids from a runner list result, one per line.
 * @param result_json Runner list result JSON string.
 * @return 0 on success, 1 on malformed result or write failure.
 */
static int kc_redp2p_print_publishers(const char *result_json) {
    JSON_Value *root;
    JSON_Object *o;
    JSON_Object *res;
    JSON_Array *publishers;
    size_t count;
    size_t i;
    int failed;

    root = json_parse_string(result_json);
    if (root == NULL || json_value_get_type(root) != JSONObject) {
        json_value_free(root);
        return 1;
    }
    o = json_value_get_object(root);
    res = json_object_get_object(o, "result");
    if (res == NULL) {
        json_value_free(root);
        return 1;
    }
    publishers = json_object_get_array(res, "publishers");
    if (publishers == NULL) {
        json_value_free(root);
        return 1;
    }
    failed = 0;
    count = json_array_get_count(publishers);
    for (i = 0; i < count; i++) {
        const char *id;

        id = json_array_get_string(publishers, i);
        if (id == NULL || fprintf(stdout, "%s\n", id) < 0) failed = 1;
    }
    json_value_free(root);
    return failed;
}

/**
 * Sleeps for a bounded delay across platforms.
 * @param ms Delay in milliseconds.
 * @return None.
 */
static void cli_sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/**
 * Builds a runner request root with a command and empty args object.
 * @param cmd Command name.
 * @param args_out Receives the args object.
 * @return malloc'd JSON root, or NULL on allocation failure.
 */
static JSON_Value *cli_runner_root(const char *cmd, JSON_Value **args_out) {
    JSON_Value *root;
    JSON_Value *args;

    root = json_value_init_object();
    args = json_value_init_object();
    if (root == NULL || args == NULL) {
        json_value_free(root);
        json_value_free(args);
        return NULL;
    }
    json_object_set_string(json_value_get_object(root), "cmd", cmd);
    json_object_set_value(json_value_get_object(root), "args", args);
    if (args_out != NULL) *args_out = args;
    return root;
}

/**
 * Serializes and dispatches one runner request, releasing the request root.
 * @param root Request JSON root (consumed).
 * @param out_err Receives a malloc'd error message on failure, or NULL on
 *     success.
 * @return malloc'd result JSON string, or NULL on failure.
 */
static char *cli_runner_call(JSON_Value *root, char **out_err) {
    char *payload;
    char *result;

    payload = json_serialize_to_string(root);
    json_value_free(root);
    if (payload == NULL) return NULL;
    result = kc_redp2p_run(payload, out_err);
    free(payload);
    return result;
}

/**
 * Opens a long-lived runner operation and returns its handle.
 * @param root Request JSON root with args (consumed).
 * @param handle_out Receives the runner handle.
 * @param out_err Receives a malloc'd error message on failure.
 * @return 0 on success, 1 on failure.
 */
static int cli_runner_open(JSON_Value *root, int *handle_out, char **out_err) {
    char *result;
    JSON_Value *parsed;
    JSON_Value *v;
    double handle;

    result = cli_runner_call(root, out_err);
    if (result == NULL) return 1;
    parsed = json_parse_string(result);
    free(result);
    if (parsed == NULL || json_value_get_type(parsed) != JSONObject) {
        json_value_free(parsed);
        return 1;
    }
    v = json_object_get_value(json_value_get_object(parsed), "handle");
    if (v == NULL || json_value_get_type(v) != JSONNumber) {
        json_value_free(parsed);
        return 1;
    }
    handle = json_value_get_number(v);
    json_value_free(parsed);
    *handle_out = (int)handle;
    return 0;
}

/**
 * Requests stop for one runner handle.
 * @param handle Runner handle.
 * @return None.
 */
static void cli_runner_stop(int handle) {
    JSON_Value *root;
    JSON_Value *args;
    char *err = NULL;
    char *result;

    root = cli_runner_root("stop", &args);
    if (root == NULL) return;
    json_object_set_number(json_value_get_object(args), "handle", (double)handle);
    result = cli_runner_call(root, &err);
    free(result);
    free(err);
}

/**
 * Closes one runner handle.
 * @param handle Runner handle.
 * @return None.
 */
static void cli_runner_close(int handle) {
    JSON_Value *root;
    JSON_Value *args;
    char *err = NULL;
    char *result;

    root = cli_runner_root("close", &args);
    if (root == NULL) return;
    json_object_set_number(json_value_get_object(args), "handle", (double)handle);
    result = cli_runner_call(root, &err);
    free(result);
    free(err);
}

/**
 * Runs one long-lived runner operation until it finishes or a signal arrives.
 * @param handle Runner handle.
 * @param exit_result_out Receives the operation result code.
 * @param out_err Receives a malloc'd error message on failure.
 * @return 0 on clean finish, 1 on error, 2 when interrupted by signal.
 */
static int cli_runner_wait(int handle, int *exit_result_out, char **out_err) {
    for (;;) {
        JSON_Value *root;
        JSON_Value *args;
        char *result;
        JSON_Value *parsed;
        JSON_Object *res;
        const char *state;

        if (g_stop_requested) {
            cli_runner_stop(handle);
            cli_runner_close(handle);
            return 2;
        }
        root = cli_runner_root("status", &args);
        if (root == NULL) return 1;
        json_object_set_number(json_value_get_object(args), "handle", (double)handle);
        result = cli_runner_call(root, out_err);
        if (result == NULL) return 1;
        parsed = json_parse_string(result);
        free(result);
        if (parsed == NULL || json_value_get_type(parsed) != JSONObject) {
            json_value_free(parsed);
            return 1;
        }
        res = json_object_get_object(json_value_get_object(parsed), "result");
        if (res == NULL) {
            json_value_free(parsed);
            return 1;
        }
        state = json_object_get_string(res, "state");
        if (state != NULL && strcmp(state, "finished") == 0) {
            *exit_result_out = (int)json_object_get_number(res, "result");
            json_value_free(parsed);
            return 0;
        }
        json_value_free(parsed);
        cli_sleep_ms(200);
    }
}

/**
 * Sanitizes an address string for use as a PID filename.
 * Replaces '.', ':', '@' with '_'. Writes into caller-owned buffer.
 * @param addr Input address string.
 * @param out  Output buffer.
 * @param out_sz Output buffer capacity.
 * @return 0 on success, 1 if output too small.
 */
static int cli_sanitize_addr(const char *addr, char *out, size_t out_sz) {
    size_t i;
    size_t n;

    if (!addr || !out || out_sz == 0) return 1;
    n = strlen(addr);
    if (n >= out_sz) return 1;
    for (i = 0; i < n; i++) {
        char c = addr[i];
        if (c == '.' || c == ':' || c == '@')
            out[i] = '_';
        else
            out[i] = c;
    }
    out[n] = '\0';
    return 0;
}

/**
 * Resolves the state directory path.
 * Priority: cli_flag > REDP2P_STATE_DIR env > $HOME/.local/share/redp2p
 * @param cli_flag CLI --state-dir value, or NULL.
 * @param buf Output buffer.
 * @param buf_sz Output buffer capacity.
 * @return 0 on success, 1 on failure.
 */
static int cli_state_dir(const char *cli_flag, char *buf, size_t buf_sz) {
    const char *base;

    if (cli_flag && cli_flag[0] != '\0') {
        snprintf(buf, buf_sz, "%s", cli_flag);
        return 0;
    }
    base = getenv("REDP2P_STATE_DIR");
    if (base && base[0] != '\0') {
        snprintf(buf, buf_sz, "%s", base);
        return 0;
    }
    base = getenv("HOME");
#ifdef _WIN32
    if (!base || !base[0]) base = getenv("USERPROFILE");
#endif
    if (!base || !base[0]) return 1;
    snprintf(buf, buf_sz, "%s/.local/share/redp2p", base);
    return 0;
}

/**
 * Computes the PID file path for a background process.
 * @param state_dir State directory base.
 * @param cmd Command name (idx, pub, con).
 * @param addr Address string (port for idx, host@index:port for pub/con).
 * @param buf Output buffer.
 * @param buf_sz Output buffer capacity.
 * @return 0 on success, 1 on failure.
 */
static int cli_pid_path(const char *state_dir, const char *cmd,
    const char *addr, char *buf, size_t buf_sz)
{
    char safe[256];

    if (strcmp(cmd, "idx") == 0) {
        snprintf(buf, buf_sz, "%s/pids/%s_%s.pid", state_dir, cmd, addr);
    } else {
        if (cli_sanitize_addr(addr, safe, sizeof(safe)) != 0) return 1;
        snprintf(buf, buf_sz, "%s/pids/%s_%s.pid", state_dir, cmd, safe);
    }
    return 0;
}

/**
 * Creates parent directories for a file path.
 * @param path Full file path.
 * @return 0 on success, -1 on failure.
 */
static int cli_mkdir_p(const char *path) {
    char tmp[1024];
    char *p;
    size_t n;

    n = strlen(path);
    if (n >= sizeof(tmp)) return -1;
    memcpy(tmp, path, n + 1);
    for (p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
#ifdef _WIN32
        _mkdir(tmp);
#else
        mkdir(tmp, 0755);
#endif
        *p = '/';
    }
#ifdef _WIN32
    _mkdir(tmp);
#else
    mkdir(tmp, 0755);
#endif
    return 0;
}

/**
 * Writes the current process PID to a file.
 * @param pid_path Full path to PID file.
 * @return 0 on success, 1 on failure.
 */
static int cli_pid_write(const char *pid_path) {
    FILE *f;

    cli_mkdir_p(pid_path);
    f = fopen(pid_path, "w");
    if (f == NULL) return 1;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    return 0;
}

/**
 * Removes a PID file.
 * @param pid_path Full path to PID file.
 * @return None.
 */
static void cli_pid_remove(const char *pid_path) {
    if (pid_path && pid_path[0] != '\0')
        remove(pid_path);
}

/**
 * Stops a background process by PID file.
 * @param pid_path Full path to PID file.
 * @return 0 on success, 1 on error.
 */
static int cli_pid_stop(const char *pid_path) {
    FILE *f;
    long pid;

    f = fopen(pid_path, "r");
    if (f == NULL) {
        fprintf(stderr, "redp2p: no background instance found\n");
        return 1;
    }
    if (fscanf(f, "%ld", &pid) != 1 || pid <= 0) {
        fclose(f);
        remove(pid_path);
        fprintf(stderr, "redp2p: invalid PID file\n");
        return 1;
    }
    fclose(f);

#ifdef _WIN32
    {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
        if (h == NULL) {
            remove(pid_path);
            fprintf(stderr, "redp2p: process not running\n");
            return 1;
        }
        TerminateProcess(h, 1);
        CloseHandle(h);
    }
#else
    {
        int killed;
        if (kill((pid_t)pid, 0) != 0) {
            remove(pid_path);
            fprintf(stderr, "redp2p: process not running\n");
            return 1;
        }
        killed = kill((pid_t)pid, SIGTERM);
        if (killed != 0) {
            fprintf(stderr, "redp2p: failed to signal process\n");
            return 1;
        }
    }
#endif
    remove(pid_path);
    fprintf(stderr, "redp2p: stopped\n");
    return 0;
}

/**
 * Program entry point.
 * Summary: Dispatches subcommands (idx, pub, con).
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char **argv) {
    const char *state_dir_flag = NULL;

    if (argc < 2) { print_help(argv[0]); return 1; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { print_help(argv[0]); return 0; }
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("redp2p build %llu\n",
            (unsigned long long)redp2p_version());
        return 0;
    }

    if (strcmp(argv[1], "idx") == 0) {
        redp2p_options_t opts;
        unsigned short port = 0;
        size_t seats;
        int seats_set;
        int seats_option_set;
        int pow_bits;
        int pow_option_set;
        int list_mode;
        int prune_mode;
        int down_mode;

        list_mode = 0;
        prune_mode = 0;
        down_mode = 0;
        seats_set = 0;
        seats_option_set = 0;
        pow_option_set = 0;
        seats = 0;
        pow_bits = 0;

        opts = redp2p_options_default();
        seats = opts.seats;
        pow_bits = opts.pow;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--list") == 0 || strcmp(argv[i], "-l") == 0) {
                list_mode = 1;
            } else if (strcmp(argv[i], "--prune") == 0 || strcmp(argv[i], "-p") == 0) {
                prune_mode = 1;
            } else if (strcmp(argv[i], "--down") == 0 || strcmp(argv[i], "-d") == 0) {
                down_mode = 1;
            } else if (strcmp(argv[i], "--seats") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --seats requires an argument\n"); redp2p_options_free(&opts); return 1; }
                if (parse_size(argv[++i], &seats) != 0) {
                    fprintf(stderr, "redp2p: invalid --seats '%s'\n", argv[i]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                seats_set = 1;
                seats_option_set = 1;
            } else if (strcmp(argv[i], "--pow") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --pow requires an argument\n"); redp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, 32, &v) != 0) {
                    fprintf(stderr, "redp2p: invalid --pow '%s'\n", argv[i]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                pow_bits = (int)v;
                pow_option_set = 1;
            } else if (port == 0 && parse_port(argv[i], &port) == 0) {
            } else {
                fprintf(stderr, "redp2p: unknown option '%s'\n", argv[i]);
                redp2p_options_free(&opts);
                return 1;
            }
        }

        if (port == 0) {
            fprintf(stderr, "redp2p: usage: %s idx <port> [--list|-l] [--prune|-p] [--seats N] [--pow N]\n", argv[0]);
            redp2p_options_free(&opts);
            return 1;
        }

        if (load_index_options(&opts, &seats_set) != 0) {
            fprintf(stderr, "redp2p: failed to load index options\n");
            redp2p_options_free(&opts);
            return 1;
        }

        if (list_mode && (seats_option_set || pow_option_set)) {
            fprintf(stderr,
                "redp2p: --list cannot be combined with --seats or --pow\n");
            redp2p_options_free(&opts);
            return 1;
        }
        if (prune_mode && (list_mode || seats_option_set || pow_option_set)) {
            fprintf(stderr,
                "redp2p: --prune cannot be combined with --list, --seats, or --pow\n");
            redp2p_options_free(&opts);
            return 1;
        }
        if (down_mode && (list_mode || prune_mode || seats_option_set || pow_option_set)) {
            fprintf(stderr,
                "redp2p: --down cannot be combined with --list, --prune, --seats, or --pow\n");
            redp2p_options_free(&opts);
            return 1;
        }

        if (down_mode) {
            char sdir[1024];
            char pidfile[1280];
            int rc;

            if (port == 0) {
                fprintf(stderr, "redp2p: usage: %s idx <port> --down\n", argv[0]);
                redp2p_options_free(&opts);
                return 1;
            }
            redp2p_options_free(&opts);
            if (cli_state_dir(state_dir_flag, sdir, sizeof(sdir)) != 0) {
                fprintf(stderr, "redp2p: cannot resolve state directory\n");
                return 1;
            }
            {
                char port_str[8];
                snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
                if (cli_pid_path(sdir, "idx", port_str, pidfile, sizeof(pidfile)) != 0) {
                    fprintf(stderr, "redp2p: path too long\n");
                    return 1;
                }
            }
            rc = cli_pid_stop(pidfile);
            return rc;
        }

        if (list_mode) {
            char *payload;
            char *result;
            char *run_err = NULL;
            JSON_Value *root;
            JSON_Value *args_value;
            int list_rc;

            root = json_value_init_object();
            args_value = json_value_init_object();
            if (root == NULL || args_value == NULL) {
                json_value_free(root);
                json_value_free(args_value);
                fprintf(stderr, "redp2p: allocation failed\n");
                redp2p_options_free(&opts);
                return 1;
            }
            json_object_set_string(json_value_get_object(root), "cmd", "list");
            json_object_set_string(json_value_get_object(args_value), "host", "127.0.0.1");
            json_object_set_number(json_value_get_object(args_value), "port", (double)port);
            json_object_set_value(json_value_get_object(root), "args", args_value);
            payload = json_serialize_to_string(root);
            json_value_free(root);
            if (payload == NULL) {
                fprintf(stderr, "redp2p: allocation failed\n");
                redp2p_options_free(&opts);
                return 1;
            }

            result = kc_redp2p_run(payload, &run_err);
            free(payload);
            redp2p_options_free(&opts);
            if (result == NULL) {
                fprintf(stderr, "redp2p: list failed: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                return 1;
            }
            list_rc = kc_redp2p_print_publishers(result);
            free(result);
            if (list_rc != 0 || fflush(stdout) != 0) {
                fprintf(stderr, "redp2p: failed to write publisher list\n");
                return 1;
            }
            return 0;
        }
        if (prune_mode) {
            fprintf(stderr, "redp2p: index pruning runs automatically every 60 seconds\n");
            redp2p_options_free(&opts);
            return 0;
        }
        {
            JSON_Value *root;
            JSON_Value *args;
            char *run_err = NULL;
            int handle;
            int exit_result;
            int wait_rc;
            char sdir[1024];
            char pidfile[1280];

            sdir[0] = '\0';
            pidfile[0] = '\0';
            if (port != 0 && cli_state_dir(state_dir_flag, sdir, sizeof(sdir)) == 0) {
                char port_str[8];
                snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
                cli_pid_path(sdir, "idx", port_str, pidfile, sizeof(pidfile));
            }

            root = cli_runner_root("open", &args);
            if (root == NULL) {
                fprintf(stderr, "redp2p: allocation failed\n");
                redp2p_options_free(&opts);
                return 1;
            }
            json_object_set_string(json_value_get_object(args), "op", "idx");
            json_object_set_number(json_value_get_object(args), "port", (double)port);
            if (seats_set) json_object_set_number(json_value_get_object(args), "seats", (double)seats);
            if (pow_option_set) json_object_set_number(json_value_get_object(args), "pow", (double)pow_bits);
            if (opts.pass[0] != '\0')
                json_object_set_string(json_value_get_object(args), "pass", opts.pass);
            if (opts.vip != NULL)
                json_object_set_string(json_value_get_object(args), "vip", opts.vip);
            if (sdir[0] != '\0')
                json_object_set_string(json_value_get_object(args), "state_dir", sdir);
            redp2p_options_free(&opts);
            if (cli_runner_open(root, &handle, &run_err) != 0) {
                fprintf(stderr, "redp2p: failed to create context: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                return 1;
            }
            if (pidfile[0] != '\0') cli_pid_write(pidfile);
            signal(SIGINT, sigint_handler);
            signal(SIGTERM, sigint_handler);
            wait_rc = cli_runner_wait(handle, &exit_result, &run_err);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            cli_pid_remove(pidfile);
            if (wait_rc == 1) {
                fprintf(stderr, "redp2p: index exited: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                cli_runner_close(handle);
                return 1;
            }
            cli_runner_close(handle);
            fprintf(stderr, "redp2p: index exited: %s\n",
                redp2p_strerror(exit_result));
            return exit_result == REDP2P_OK ? 0 : 1;
        }

    } else if (strcmp(argv[1], "pub") == 0) {
        redp2p_options_t opts;
        char host[REDP2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;
        unsigned short service_port = 0;
        int proto = 0;
        int down_mode = 0;

        opts = redp2p_options_default();
        redp2p_options_load_env(&opts);

        if (argc < 3) { fprintf(stderr, "redp2p: usage: %s pub <host>@<index[:port]>\n", argv[0]); redp2p_options_free(&opts); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "redp2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); redp2p_options_free(&opts); return 1;
        }
        if (!redp2p_is_valid_id(host)) {
            fprintf(stderr, "redp2p: invalid host id '%s'\n", host);
            redp2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--down") == 0 || strcmp(argv[i], "-d") == 0) {
                down_mode = 1;
            } else if (strcmp(argv[i], "--tcp") == 0) {
                if (proto != 0) { fprintf(stderr, "redp2p: choose only one of --tcp or --udp\n"); redp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --tcp requires a port\n"); redp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &service_port) != 0) {
                    fprintf(stderr, "redp2p: invalid --tcp port '%s'\n", argv[i + 1]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = REDP2P_PROTO_TCP;
            } else if (strcmp(argv[i], "--udp") == 0) {
                if (proto != 0) { fprintf(stderr, "redp2p: choose only one of --tcp or --udp\n"); redp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --udp requires a port\n"); redp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &service_port) != 0) {
                    fprintf(stderr, "redp2p: invalid --udp port '%s'\n", argv[i + 1]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = REDP2P_PROTO_UDP;
            } else if (strcmp(argv[i], "--sweep") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --sweep requires a number\n"); redp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, 1024, &v) != 0) {
                    fprintf(stderr, "redp2p: invalid --sweep '%s'\n", argv[i]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                opts.sweep = (int)v;
            } else if (strcmp(argv[i], "--stun") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --stun requires a URL\n"); redp2p_options_free(&opts); return 1; }
                strncpy(opts.stun_url, argv[++i], sizeof(opts.stun_url) - 1);
                opts.stun_url[sizeof(opts.stun_url) - 1] = '\0';
            } else { fprintf(stderr, "redp2p: unknown option '%s'\n", argv[i]); redp2p_options_free(&opts); return 1; }
        }

        if (down_mode && (proto != 0 || service_port != 0 || opts.sweep != 0 || opts.stun_url[0] != '\0')) {
            fprintf(stderr, "redp2p: --down cannot be combined with --tcp, --udp, --sweep, or --stun\n");
            redp2p_options_free(&opts);
            return 1;
        }

        if (down_mode) {
            char sdir[1024];
            char pidfile[1280];
            int rc;

            redp2p_options_free(&opts);
            if (cli_state_dir(state_dir_flag, sdir, sizeof(sdir)) != 0) {
                fprintf(stderr, "redp2p: cannot resolve state directory\n");
                return 1;
            }
            if (cli_pid_path(sdir, "pub", argv[2], pidfile, sizeof(pidfile)) != 0) {
                fprintf(stderr, "redp2p: path too long\n");
                return 1;
            }
            rc = cli_pid_stop(pidfile);
            return rc;
        }

        if (proto == 0 || service_port == 0) { fprintf(stderr, "redp2p: pub requires --tcp <port> or --udp <port>\n"); redp2p_options_free(&opts); return 1; }

        {
            JSON_Value *root;
            JSON_Value *args;
            char *run_err = NULL;
            int handle;
            int exit_result;
            int wait_rc;
            char sdir[1024];
            char pidfile[1280];

            sdir[0] = '\0';
            pidfile[0] = '\0';
            if (cli_state_dir(state_dir_flag, sdir, sizeof(sdir)) == 0)
                cli_pid_path(sdir, "pub", argv[2], pidfile, sizeof(pidfile));

            root = cli_runner_root("open", &args);
            if (root == NULL) {
                fprintf(stderr, "redp2p: allocation failed\n");
                redp2p_options_free(&opts);
                return 1;
            }
            json_object_set_string(json_value_get_object(args), "op", "pub");
            json_object_set_string(json_value_get_object(args), "addr", argv[2]);
            if (proto == REDP2P_PROTO_TCP) {
                json_object_set_number(json_value_get_object(args), "tcp", (double)service_port);
            } else {
                json_object_set_number(json_value_get_object(args), "udp", (double)service_port);
            }
            json_object_set_number(json_value_get_object(args), "sweep", (double)opts.sweep);
            if (opts.stun_url[0] != '\0')
                json_object_set_string(json_value_get_object(args), "stun", opts.stun_url);
            if (opts.pass[0] != '\0')
                json_object_set_string(json_value_get_object(args), "pass", opts.pass);
            if (sdir[0] != '\0')
                json_object_set_string(json_value_get_object(args), "state_dir", sdir);
            redp2p_options_free(&opts);
            if (cli_runner_open(root, &handle, &run_err) != 0) {
                fprintf(stderr, "redp2p: failed to create context: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                return 1;
            }
            if (pidfile[0] != '\0') cli_pid_write(pidfile);
            fprintf(stderr, "redp2p: waiting for connections...\n");
            signal(SIGINT, sigint_handler);
            signal(SIGTERM, sigint_handler);
            wait_rc = cli_runner_wait(handle, &exit_result, &run_err);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            cli_pid_remove(pidfile);
            if (wait_rc == 1) {
                fprintf(stderr, "redp2p: pub exited: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                cli_runner_close(handle);
                return 1;
            }
            cli_runner_close(handle);
            if (exit_result != REDP2P_OK)
                fprintf(stderr, "redp2p: pub exited: %s\n",
                    redp2p_strerror(exit_result));
            return exit_result == REDP2P_OK ? 0 : 1;
        }

    } else if (strcmp(argv[1], "con") == 0) {
        redp2p_options_t opts;
        char host[REDP2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;
        unsigned short listen_port = 0;
        int proto = 0;
        int down_mode = 0;

        opts = redp2p_options_default();
        redp2p_options_load_env(&opts);

        if (argc < 3) { fprintf(stderr, "redp2p: usage: %s con <host>@<index[:port]>\n", argv[0]); redp2p_options_free(&opts); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "redp2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); redp2p_options_free(&opts); return 1;
        }
        if (!redp2p_is_valid_id(host)) {
            fprintf(stderr, "redp2p: invalid host id '%s'\n", host);
            redp2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--down") == 0 || strcmp(argv[i], "-d") == 0) {
                down_mode = 1;
            } else if (strcmp(argv[i], "--tcp") == 0) {
                if (proto != 0) { fprintf(stderr, "redp2p: choose only one of --tcp or --udp\n"); redp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --tcp requires a port\n"); redp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &listen_port) != 0) {
                    fprintf(stderr, "redp2p: invalid --tcp port '%s'\n", argv[i + 1]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = REDP2P_PROTO_TCP;
            } else if (strcmp(argv[i], "--udp") == 0) {
                if (proto != 0) { fprintf(stderr, "redp2p: choose only one of --tcp or --udp\n"); redp2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --udp requires a port\n"); redp2p_options_free(&opts); return 1; }
                if (parse_port(argv[i + 1], &listen_port) != 0) {
                    fprintf(stderr, "redp2p: invalid --udp port '%s'\n", argv[i + 1]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                i++;
                proto = REDP2P_PROTO_UDP;
            } else if (strcmp(argv[i], "--sweep") == 0) {
                long v;
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --sweep requires a number\n"); redp2p_options_free(&opts); return 1; }
                if (parse_int(argv[++i], 0, 1024, &v) != 0) {
                    fprintf(stderr, "redp2p: invalid --sweep '%s'\n", argv[i]);
                    redp2p_options_free(&opts);
                    return 1;
                }
                opts.sweep = (int)v;
            } else if (strcmp(argv[i], "--stun") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "redp2p: --stun requires a URL\n"); redp2p_options_free(&opts); return 1; }
                strncpy(opts.stun_url, argv[++i], sizeof(opts.stun_url) - 1);
                opts.stun_url[sizeof(opts.stun_url) - 1] = '\0';
            } else { fprintf(stderr, "redp2p: unknown option '%s'\n", argv[i]); redp2p_options_free(&opts); return 1; }
        }

        if (down_mode && (proto != 0 || listen_port != 0 || opts.sweep != 0 || opts.stun_url[0] != '\0')) {
            fprintf(stderr, "redp2p: --down cannot be combined with --tcp, --udp, --sweep, or --stun\n");
            redp2p_options_free(&opts);
            return 1;
        }

        if (down_mode) {
            char sdir[1024];
            char pidfile[1280];
            int rc;

            redp2p_options_free(&opts);
            if (cli_state_dir(state_dir_flag, sdir, sizeof(sdir)) != 0) {
                fprintf(stderr, "redp2p: cannot resolve state directory\n");
                return 1;
            }
            if (cli_pid_path(sdir, "con", argv[2], pidfile, sizeof(pidfile)) != 0) {
                fprintf(stderr, "redp2p: path too long\n");
                return 1;
            }
            rc = cli_pid_stop(pidfile);
            return rc;
        }

        if (proto == 0 || listen_port == 0) { fprintf(stderr, "redp2p: con requires --tcp <port> or --udp <port>\n"); redp2p_options_free(&opts); return 1; }

        {
            JSON_Value *root;
            JSON_Value *args;
            char *run_err = NULL;
            int handle;
            int exit_result;
            int wait_rc;
            char sdir[1024];
            char pidfile[1280];

            sdir[0] = '\0';
            pidfile[0] = '\0';
            if (cli_state_dir(state_dir_flag, sdir, sizeof(sdir)) == 0)
                cli_pid_path(sdir, "con", argv[2], pidfile, sizeof(pidfile));

            root = cli_runner_root("open", &args);
            if (root == NULL) {
                fprintf(stderr, "redp2p: allocation failed\n");
                redp2p_options_free(&opts);
                return 1;
            }
            json_object_set_string(json_value_get_object(args), "op", "con");
            json_object_set_string(json_value_get_object(args), "addr", argv[2]);
            if (proto == REDP2P_PROTO_TCP) {
                json_object_set_number(json_value_get_object(args), "tcp", (double)listen_port);
            } else {
                json_object_set_number(json_value_get_object(args), "udp", (double)listen_port);
            }
            json_object_set_number(json_value_get_object(args), "sweep", (double)opts.sweep);
            if (opts.stun_url[0] != '\0')
                json_object_set_string(json_value_get_object(args), "stun", opts.stun_url);
            if (sdir[0] != '\0')
                json_object_set_string(json_value_get_object(args), "state_dir", sdir);
            redp2p_options_free(&opts);
            if (cli_runner_open(root, &handle, &run_err) != 0) {
                fprintf(stderr, "redp2p: connect failed: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                return 1;
            }
            if (pidfile[0] != '\0') cli_pid_write(pidfile);
            signal(SIGINT, sigint_handler);
            signal(SIGTERM, sigint_handler);
            wait_rc = cli_runner_wait(handle, &exit_result, &run_err);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            cli_pid_remove(pidfile);
            if (wait_rc == 1) {
                fprintf(stderr, "redp2p: connect failed: %s\n",
                    run_err != NULL ? run_err : "unknown error");
                free(run_err);
                cli_runner_close(handle);
                return 1;
            }
            cli_runner_close(handle);
            if (exit_result != REDP2P_OK)
                fprintf(stderr, "redp2p: connect failed: %s\n",
                    redp2p_strerror(exit_result));
            return exit_result == REDP2P_OK ? 0 : 1;
        }

    } else {
        fprintf(stderr, "redp2p: unknown command '%s'\n", argv[1]);
        fprintf(stderr, "redp2p: try '%s --help'\n", argv[0]);
        return 1;
    }
}
