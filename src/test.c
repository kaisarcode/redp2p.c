/**
 * redp2p.c - libredp2p public API contract tests.
 * Summary: Validates each exported function through one dedicated test case.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "libredp2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>

#ifdef _WIN32
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#define TEST_HOST "127.0.0.1"
#define TEST_TCP_CLIENTS 4
#define TEST_TCP_LARGE_SIZE (80U * 1024U + 333U)
#define TEST_HTTP_LINE_MAX 256
#define TEST_HTTP_HEADERS_MAX 32

#ifndef REDP2P_TEST_CLI
#define REDP2P_TEST_CLI ""
#endif

#ifdef _WIN32
typedef HANDLE test_thread_t;
typedef SOCKET test_socket_t;
typedef int test_socklen_t;
#define TEST_SOCKET_INVALID INVALID_SOCKET
#else
typedef pthread_t test_thread_t;
typedef int test_socket_t;
typedef socklen_t test_socklen_t;
#define TEST_SOCKET_INVALID -1
#endif

typedef struct {
    redp2p_t *ctx;
    unsigned short port;
    int result;
    test_thread_t thread;
} test_index_t;

typedef struct {
    redp2p_t *ctx;
    const char *host;
    unsigned short index_port;
    const char *id;
    unsigned short bind_port;
    int protocol;
    const char *pass;
    _Atomic int result;
    test_thread_t thread;
} test_publisher_t;

typedef struct {
    redp2p_t *ctx;
    const char *host;
    unsigned short index_port;
    const char *self_id;
    const char *target_id;
    unsigned short bind_port;
    int protocol;
    _Atomic int result;
    test_thread_t thread;
} test_consumer_t;

typedef struct {
    test_socket_t fd;
    unsigned short port;
    _Atomic int stop;
    test_thread_t thread;
} test_udp_echo_t;

typedef struct {
    test_socket_t fd;
    test_socket_t clients[TEST_TCP_CLIENTS];
    unsigned short port;
    _Atomic int stop;
    test_thread_t thread;
} test_tcp_echo_t;

typedef struct {
    test_socket_t fd;
    unsigned short port;
    test_thread_t thread;
} test_control_stub_t;

typedef struct {
    char ids[8][REDP2P_ID_MAX + 1];
    size_t count;
} test_publishers_t;

static char test_home_path[512];
static char test_port_reservation[512];
static const char *test_case_name;

static int test_socket_close(test_socket_t fd);
static int test_http_request(unsigned short port, const char *body,
    size_t body_len, int expected_status, const char *expected_fragment);
static int test_http_raw_status(unsigned short port, const char *request,
    size_t request_len);
static int test_http_incomplete_closed(unsigned short port,
    const char *request, size_t request_len);

/**
 * Reports which socket protocols one test case uses at a port offset.
 * @param offset Port offset from the allocated base.
 * @param tcp Set to 1 when the TCP port is required.
 * @param udp Set to 1 when the UDP port is required.
 * @return None.
 */
static void test_port_requirement(unsigned int offset, int *tcp, int *udp) {
    unsigned int anchor;

    *tcp = 0;
    *udp = 0;
    if (strcmp(test_case_name, "redp2p_serve_index") == 0) {
        *tcp = offset >= 1U && offset <= 4U;
    } else if (strcmp(test_case_name, "redp2p_wait") == 0) {
        *tcp = offset == 20U || offset == 22U;
    } else if (strcmp(test_case_name, "redp2p_connect") == 0) {
        *tcp = offset >= 40U && offset <= 45U;
        if (offset == 47U) *tcp = 1;
    } else if (strcmp(test_case_name, "redp2p_udp_tunnel") == 0) {
        anchor = 300U;
        *tcp = offset == anchor;
        *udp = offset == anchor + 1U || offset == anchor + 2U;
    } else if (strcmp(test_case_name, "redp2p_tcp_stream") == 0)
    {
        anchor = 400U;
        *tcp = offset >= anchor && offset <= anchor + 2U;
    } else if (strcmp(test_case_name, "redp2p_deregister") == 0) {
        *tcp = offset >= 60U && offset <= 62U;
    } else if (strcmp(test_case_name, "redp2p_list_publishers") == 0) {
        *tcp = offset >= 80U && offset <= 84U;
    } else if (strcmp(test_case_name, "redp2p_heartbeat") == 0) {
        *tcp = offset >= 100U && offset <= 102U;
    }
}

/**
 * Reports whether one required loopback port can be bound.
 * @param base First port in the candidate block.
 * @param offset Port offset from the candidate base.
 * @param type Socket type.
 * @return 1 when the required port can be bound, 0 otherwise.
 */
static int test_port_available(unsigned short base, unsigned int offset,
    int type)
{
    struct sockaddr_in addr;
    test_socket_t fd;
    int result;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)(base + offset));
    fd = socket(AF_INET, type, 0);
    if (fd == TEST_SOCKET_INVALID) return 0;
    result = bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0;
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return result;
}

/**
 * Reports whether every port required by the active case is available.
 * @param base Candidate port base.
 * @return 1 when all required ports are available, 0 otherwise.
 */
static int test_port_base_available(unsigned short base) {
    unsigned int offset;

    for (offset = 0; offset <= 412U; offset++) {
        int tcp;
        int udp;

        test_port_requirement(offset, &tcp, &udp);
        if (tcp && !test_port_available(base, offset, SOCK_STREAM)) return 0;
        if (udp && !test_port_available(base, offset, SOCK_DGRAM)) return 0;
    }
    return 1;
}

/**
 * Reserves one candidate port block against other test processes.
 * @param base Candidate port base.
 * @return 1 when reserved, 0 when already reserved or unavailable.
 */
static int test_port_base_reserve(unsigned short base) {
    int length;

#ifdef _WIN32
    char root[384];
    DWORD root_len;

    root_len = GetTempPathA(sizeof(root), root);
    if (root_len == 0 || root_len >= sizeof(root)) return 0;
    length = snprintf(test_port_reservation, sizeof(test_port_reservation),
        "%sredp2p-test-ports-%u.lock", root, (unsigned)base);
    if (length < 0 || (size_t)length >= sizeof(test_port_reservation)) return 0;
    if (!CreateDirectoryA(test_port_reservation, NULL)) {
        test_port_reservation[0] = '\0';
        return 0;
    }
#else
    const char *tmp;

    tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) tmp = "/tmp";
    length = snprintf(test_port_reservation, sizeof(test_port_reservation),
        "%s/redp2p-test-ports-%u.lock", tmp, (unsigned)base);
    if (length < 0 || (size_t)length >= sizeof(test_port_reservation)) return 0;
    if (mkdir(test_port_reservation, 0700) != 0) {
        test_port_reservation[0] = '\0';
        return 0;
    }
#endif
    return 1;
}

/**
 * Releases the current cross-process port block reservation.
 * @return None.
 */
static void test_port_base_release(void) {
    if (!test_port_reservation[0]) return;
#ifdef _WIN32
    RemoveDirectoryA(test_port_reservation);
#else
    rmdir(test_port_reservation);
#endif
    test_port_reservation[0] = '\0';
}

/**
 * Returns a checked loopback port base for the active test case.
 * @return Port base, or 0 when no candidate is available.
 */
static unsigned short test_port_base(void) {
    static unsigned short selected;
    struct sockaddr_in addr;
    test_socklen_t addr_len;
    unsigned int attempt;

    if (selected != 0) return selected;
    for (attempt = 0; attempt < 64U; attempt++) {
        test_socket_t seed_fd;
        unsigned short seed;
        unsigned short candidate;

        seed_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (seed_fd == TEST_SOCKET_INVALID) break;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (bind(seed_fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
            test_socket_close(seed_fd);
            break;
        }
        addr_len = sizeof(addr);
        if (getsockname(seed_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
            test_socket_close(seed_fd);
            break;
        }
        seed = ntohs(addr.sin_port);
        test_socket_close(seed_fd);
        candidate = (unsigned short)(10000U + seed % 50000U);
        if (candidate > 65000U) candidate = (unsigned short)(candidate - 1000U);
        if (!test_port_base_reserve(candidate)) continue;
        if (test_port_base_available(candidate)) {
            selected = candidate;
            return selected;
        }
        test_port_base_release();
    }
    fprintf(stderr, "no available loopback ports for %s\n", test_case_name);
    return 0;
}

/**
 * Sleeps for a bounded number of milliseconds.
 * @param ms Milliseconds to sleep.
 * @return None.
 */
static void test_sleep_ms(unsigned int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
#endif
}

/**
 * Sets or clears a process environment variable.
 * @param name Environment variable name.
 * @param value Environment variable value or NULL.
 * @return 0 on success, 1 on failure.
 */
static int test_setenv(const char *name, const char *value) {
#ifdef _WIN32
    return _putenv_s(name, value != NULL ? value : "") == 0 ? 0 : 1;
#else
    if (value == NULL) return unsetenv(name) == 0 ? 0 : 1;
    return setenv(name, value, 1) == 0 ? 0 : 1;
#endif
}

/**
 * Removes one test directory tree.
 * @param path Directory path.
 * @return 0 on success, 1 on failure.
 */
static int test_remove_tree(const char *path) {
#ifdef _WIN32
    WIN32_FIND_DATAA entry;
    char child[512];
    char pattern[512];
    HANDLE search;
    int rc;

    if (snprintf(pattern, sizeof(pattern), "%s\\*", path) < 0 ||
        strlen(pattern) >= sizeof(pattern))
        return 1;
    search = FindFirstFileA(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE)
        return RemoveDirectoryA(path) ? 0 : 1;
    rc = 0;
    do {
        if (strcmp(entry.cFileName, ".") == 0 ||
            strcmp(entry.cFileName, "..") == 0)
            continue;
        if (snprintf(child, sizeof(child), "%s\\%s", path,
            entry.cFileName) < 0 || strlen(child) >= sizeof(child))
        {
            rc = 1;
            continue;
        }
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (test_remove_tree(child) != 0) rc = 1;
        } else if (!DeleteFileA(child)) {
            rc = 1;
        }
    } while (FindNextFileA(search, &entry));
    FindClose(search);
    if (!RemoveDirectoryA(path)) rc = 1;
    return rc;
#else
    struct dirent *entry;
    struct stat st;
    char child[512];
    DIR *dir;
    int rc;

    dir = opendir(path);
    if (!dir) return rmdir(path) == 0 ? 0 : 1;
    rc = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path,
            entry->d_name) < 0 || strlen(child) >= sizeof(child))
        {
            rc = 1;
            continue;
        }
        if (lstat(child, &st) != 0) {
            rc = 1;
        } else if (S_ISDIR(st.st_mode)) {
            if (test_remove_tree(child) != 0) rc = 1;
        } else if (unlink(child) != 0) {
            rc = 1;
        }
    }
    closedir(dir);
    if (rmdir(path) != 0) rc = 1;
    return rc;
#endif
}

/**
 * Configures a temporary process-local HOME directory for key files.
 * @return 0 on success, 1 on failure.
 */
static int test_home(void) {
#ifdef _WIN32
    char base[MAX_PATH];
    char path[MAX_PATH];
    DWORD base_len;

    base_len = GetTempPathA(sizeof(base), base);
    if (base_len == 0 || base_len >= sizeof(base)) return 1;
    if (GetTempFileNameA(base, "rpt", 0, path) == 0) return 1;
    if (!DeleteFileA(path) || !CreateDirectoryA(path, NULL)) return 1;
    if (strlen(path) >= sizeof(test_home_path)) {
        RemoveDirectoryA(path);
        return 1;
    }
    strcpy(test_home_path, path);
#else
    const char *base;

    base = getenv("TMPDIR");
    if (!base || !base[0]) base = "/tmp";
    if (snprintf(test_home_path, sizeof(test_home_path),
        "%s/redp2p-test-XXXXXX", base) < 0 ||
        strlen(test_home_path) >= sizeof(test_home_path))
        return 1;
    if (!mkdtemp(test_home_path)) return 1;
#endif
    if (test_setenv("HOME", test_home_path) != 0) {
        test_remove_tree(test_home_path);
        test_home_path[0] = '\0';
        return 1;
    }
    return 0;
}

/**
 * Removes the temporary process-local HOME directory.
 * @return 0 on success, 1 on failure.
 */
static int test_home_cleanup(void) {
    int rc;

    if (!test_home_path[0]) return 0;
    rc = test_remove_tree(test_home_path);
    test_home_path[0] = '\0';
    return rc;
}

/**
 * Builds the test HOME registration key directory path.
 * @param path Output path.
 * @param cap Output capacity.
 * @return 0 on success, 1 on overflow.
 */
static int test_key_dir(char *path, size_t cap) {
    int n;

    n = snprintf(path, cap, "%s/.local/share/redp2p/keys", test_home_path);
    return n < 0 || (size_t)n >= cap ? 1 : 0;
}

/**
 * Lists regular registration key filenames in the test HOME.
 * @param names Output filename array.
 * @param capacity Maximum filename count.
 * @param count Output filename count.
 * @return 0 on success, 1 on failure or overflow.
 */
static int test_key_list(char names[][128], int capacity, int *count) {
    char dir[640];

    if (test_key_dir(dir, sizeof(dir)) != 0 || !count) return 1;
    *count = 0;
#ifdef _WIN32
    {
        WIN32_FIND_DATAA entry;
        char pattern[672];
        HANDLE search;

        if (snprintf(pattern, sizeof(pattern), "%s/*", dir) < 0 ||
            strlen(pattern) >= sizeof(pattern))
            return 1;
        search = FindFirstFileA(pattern, &entry);
        if (search == INVALID_HANDLE_VALUE)
            return GetLastError() == ERROR_PATH_NOT_FOUND ? 0 : 1;
        do {
            if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (*count >= capacity || strlen(entry.cFileName) >= 128) {
                FindClose(search);
                return 1;
            }
            strcpy(names[*count], entry.cFileName);
            (*count)++;
        } while (FindNextFileA(search, &entry));
        FindClose(search);
    }
#else
    {
        struct dirent *entry;
        DIR *directory;

        directory = opendir(dir);
        if (!directory) return errno == ENOENT ? 0 : 1;
        while ((entry = readdir(directory)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            if (*count >= capacity || strlen(entry->d_name) >= 128) {
                closedir(directory);
                return 1;
            }
            strcpy(names[*count], entry->d_name);
            (*count)++;
        }
        closedir(directory);
    }
#endif
    return 0;
}

/**
 * Builds one path below the registration key directory.
 * @param name Filename.
 * @param path Output path.
 * @param cap Output capacity.
 * @return 0 on success, 1 on overflow.
 */
static int test_key_path(const char *name, char *path, size_t cap) {
    char dir[640];
    int n;

    if (test_key_dir(dir, sizeof(dir)) != 0) return 1;
    n = snprintf(path, cap, "%s/%s", dir, name);
    return n < 0 || (size_t)n >= cap ? 1 : 0;
}

/**
 * Reads one complete small test file.
 * @param path File path.
 * @param data Output bytes.
 * @param cap Output capacity.
 * @param len Output byte count.
 * @return 0 on success, 1 on failure or overflow.
 */
static int test_file_read(const char *path, char *data, size_t cap,
    size_t *len)
{
    FILE *file;
    size_t total;
    int byte;

    file = fopen(path, "rb");
    if (!file) return 1;
    total = fread(data, 1, cap, file);
    byte = fgetc(file);
    if (ferror(file) || byte != EOF || fclose(file) != 0) return 1;
    if (len) *len = total;
    return 0;
}

/**
 * Replaces one small test file with exact bytes.
 * @param path File path.
 * @param data Input bytes.
 * @param len Input byte count.
 * @return 0 on success, 1 on failure.
 */
static int test_file_write(const char *path, const char *data, size_t len) {
    FILE *file;
    size_t written;

    file = fopen(path, "wb");
    if (!file) return 1;
    written = fwrite(data, 1, len, file);
    if (written != len || fflush(file) != 0 || fclose(file) != 0) return 1;
    return 0;
}

/**
 * Reports whether one filesystem path exists.
 * @param path Path to inspect.
 * @return 1 when present, 0 otherwise.
 */
static int test_path_exists(const char *path) {
#ifdef _WIN32
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
    struct stat status;

    return lstat(path, &status) == 0;
#endif
}

/**
 * Starts platform socket state.
 * @return 0 on success, 1 on failure.
 */
static int test_socket_start(void) {
#ifdef _WIN32
    WSADATA data;

    return WSAStartup(MAKEWORD(2, 2), &data) == 0 ? 0 : 1;
#else
    signal(SIGPIPE, SIG_IGN);
    return 0;
#endif
}

/**
 * Stops platform socket state.
 * @return 0 on success.
 */
static int test_socket_stop(void) {
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

/**
 * Closes a socket.
 * @param fd Socket descriptor.
 * @return 0 on success, non-zero on failure.
 */
static int test_socket_close(test_socket_t fd) {
#ifdef _WIN32
    return closesocket(fd);
#else
    return close(fd);
#endif
}

/**
 * Shuts down both directions of one socket.
 * @param fd Socket descriptor.
 * @return 0 on success, non-zero on failure.
 */
static int test_socket_shutdown(test_socket_t fd) {
#ifdef _WIN32
    return shutdown(fd, SD_BOTH);
#else
    return shutdown(fd, SHUT_RDWR);
#endif
}

/**
 * Sets receive timeout on one socket.
 * @param fd Socket descriptor.
 * @param ms Timeout in milliseconds.
 * @return 0 on success.
 */
static int test_socket_timeout(test_socket_t fd, unsigned int ms) {
#ifdef _WIN32
    DWORD tv;

    tv = (DWORD)ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;

    tv.tv_sec = (time_t)(ms / 1000U);
    tv.tv_usec = (suseconds_t)(ms % 1000U) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif
    return 0;
}

/**
 * Reports whether the latest socket operation was interrupted.
 * @return 1 when interrupted, 0 otherwise.
 */
static int test_socket_interrupted(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

/**
 * Sends an exact byte sequence before the socket timeout expires.
 * @param fd Socket descriptor.
 * @param data Bytes to send.
 * @param len Byte count.
 * @return 0 on success, 1 on failure.
 */
static int test_socket_send_all(test_socket_t fd, const unsigned char *data,
size_t len)
{
    size_t sent;

    sent = 0;
    while (sent < len) {
        int n;

        n = (int)send(fd, (const char *)data + sent, (int)(len - sent), 0);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && test_socket_interrupted()) continue;
        return 1;
    }
    return 0;
}

/**
 * Receives an exact byte sequence before the socket timeout expires.
 * @param fd Socket descriptor.
 * @param data Destination buffer.
 * @param len Byte count.
 * @return 0 on success, 1 on failure.
 */
static int test_socket_receive_exact(test_socket_t fd, unsigned char *data,
size_t len)
{
    size_t received;

    received = 0;
    while (received < len) {
        int n;

        n = (int)recv(fd, (char *)data + received, (int)(len - received), 0);
        if (n > 0) {
            received += (size_t)n;
            continue;
        }
        if (n < 0 && test_socket_interrupted()) continue;
        return 1;
    }
    return 0;
}

/**
 * Tests whether a loopback TCP port accepts connections.
 * @param port TCP port.
 * @return 1 when open, 0 when closed.
 */
static int test_port_open(unsigned short port) {
    test_socket_t fd;
    struct sockaddr_in addr;
    int rc;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == TEST_SOCKET_INVALID) return 0;
    test_socket_timeout(fd, 250U);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rc = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    test_socket_close(fd);
    return rc == 0 ? 1 : 0;
}

/**
 * Waits for a TCP port to reach an expected state.
 * @param port TCP port.
 * @param open Expected state.
 * @return 1 when observed, 0 on timeout.
 */
static int test_wait_port(unsigned short port, int open) {
    int i;

    for (i = 0; i < 100; i++) {
        if (test_port_open(port) == open) return 1;
        test_sleep_ms(20U);
    }
    return 0;
}

/**
 * Waits until one publisher is registered or has returned.
 * @param publisher Publisher state.
 * @return 0 when startup reaches an observable state, 1 on timeout.
 */
static int test_wait_publisher_ready(test_publisher_t *publisher) {
    char body[REDP2P_ID_MAX + 64];
    char expected[64];
    int body_len;
    int expected_len;
    int observed;
    unsigned int elapsed;

    body_len = snprintf(body, sizeof(body), "{\"op\":\"lookup\",\"id\":\"%s\"}",
        publisher->id);
    expected_len = snprintf(expected, sizeof(expected), "\"udp_port\":%u",
        (unsigned)publisher->bind_port);
    if (body_len < 0 || (size_t)body_len >= sizeof(body) ||
        expected_len < 0 || (size_t)expected_len >= sizeof(expected))
        return 1;
    observed = 0;
    for (elapsed = 0; elapsed < 2000U; elapsed += 20U) {
        if (atomic_load(&publisher->result) != 999) return 0;
        if (test_http_request(publisher->index_port, body, (size_t)body_len,
            200, expected) == 0) {
            observed++;
            if (observed == 2) return 0;
        } else {
            observed = 0;
        }
        test_sleep_ms(20U);
    }
    fprintf(stderr, "publisher %s startup timed out: result=%d error=%s\n",
        publisher->id, atomic_load(&publisher->result),
        redp2p_get_error(publisher->ctx));
    return 1;
}

/**
 * Waits until one TCP consumer listens or has returned.
 * @param consumer Consumer state.
 * @return 0 when listening, 1 on timeout or terminal failure.
 */
static int test_wait_consumer_ready(test_consumer_t *consumer) {
    unsigned int elapsed;

    for (elapsed = 0; elapsed < 2000U; elapsed += 20U) {
        if (test_port_open(consumer->bind_port)) return 0;
        if (atomic_load(&consumer->result) != 999) break;
        test_sleep_ms(20U);
    }
    fprintf(stderr, "consumer %s startup failed: result=%d error=%s\n",
        consumer->self_id, atomic_load(&consumer->result),
        redp2p_get_error(consumer->ctx));
    return 1;
}

/**
 * Checks one integer value.
 * @param name Check name.
 * @param expected Expected value.
 * @param actual Actual value.
 * @return 0 on success, 1 on failure.
 */
static int expect_int(const char *name, int expected, int actual) {
    if (expected != actual) {
        printf("[FAIL] %s: expected %d, got %d\n", name, expected, actual);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

/**
 * Checks one size value.
 * @param name Check name.
 * @param expected Expected value.
 * @param actual Actual value.
 * @return 0 on success, 1 on failure.
 */
static int expect_size(const char *name, size_t expected, size_t actual) {
    if (expected != actual) {
        printf("[FAIL] %s: expected %zu, got %zu\n", name, expected, actual);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

/**
 * Checks one true condition.
 * @param name Check name.
 * @param condition Condition value.
 * @return 0 on success, 1 on failure.
 */
static int expect_true(const char *name, int condition) {
    if (!condition) {
        printf("[FAIL] %s\n", name);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

/**
 * Checks one string value.
 * @param name Check name.
 * @param expected Expected string.
 * @param actual Actual string.
 * @return 0 on success, 1 on failure.
 */
static int expect_string(const char *name, const char *expected, const char *actual) {
    if (actual == NULL || strcmp(expected, actual) != 0) {
        printf("[FAIL] %s: expected '%s', got '%s'\n", name, expected,
            actual != NULL ? actual : "NULL");
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

#ifndef _WIN32
/**
 * Runs the REDP2P CLI and captures stdout.
 * @param argv Command argument vector.
 * @param output Destination output buffer.
 * @param output_cap Output buffer capacity.
 * @param output_size Destination captured byte count.
 * @param exit_code Destination process exit code.
 * @return 0 on success, 1 on failure.
 */
static int test_cli_capture(char *const argv[], char *output,
    size_t output_cap, size_t *output_size, int *exit_code)
{
    int output_pipe[2];
    pid_t pid;
    size_t used;
    int status;

    if (!argv || !argv[0] || !output || output_cap == 0 || !output_size ||
        !exit_code)
        return 1;
    if (pipe(output_pipe) != 0) return 1;
    pid = fork();
    if (pid < 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return 1;
    }
    if (pid == 0) {
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0) _exit(127);
        close(output_pipe[0]);
        close(output_pipe[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(output_pipe[1]);
    used = 0;
    while (used + 1 < output_cap) {
        ssize_t count;

        count = read(output_pipe[0], output + used, output_cap - used - 1);
        if (count < 0) {
            if (errno == EINTR) continue;
            close(output_pipe[0]);
            waitpid(pid, NULL, 0);
            return 1;
        }
        if (count == 0) break;
        used += (size_t)count;
    }
    close(output_pipe[0]);
    output[used] = '\0';
    *output_size = used;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) return 1;
    *exit_code = WEXITSTATUS(status);
    return 0;
}

/**
 * Runs one idx list CLI assertion.
 * @param name Assertion name.
 * @param port Local index port.
 * @param list_option List option spelling.
 * @param server_option Optional conflicting server option.
 * @param server_value Optional conflicting server option value.
 * @param expected_exit Expected process exit code.
 * @param expected_output Expected stdout text.
 * @return 0 on success, 1 on failure.
 */
static int test_cli_list(const char *name, unsigned short port,
    const char *list_option, const char *server_option,
    const char *server_value, int expected_exit, const char *expected_output)
{
    char output[256];
    char port_text[6];
    char *arguments[] = {
        (char *)REDP2P_TEST_CLI,
        (char *)"idx",
        port_text,
        (char *)list_option,
        (char *)server_option,
        (char *)server_value,
        NULL,
    };
    size_t output_size;
    int exit_code;
    int rc;

    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);
    output[0] = '\0';
    exit_code = -1;
    if (test_cli_capture(arguments, output, sizeof(output), &output_size,
        &exit_code) != 0)
    {
        printf("[FAIL] %s: failed to capture CLI\n", name);
        return 1;
    }
    rc = expect_int(name, expected_exit, exit_code);
    rc += expect_string(name, expected_output, output);
    return rc == 0 ? 0 : 1;
}
#endif

/**
 * Runs one loopback UDP echo backend until stopped.
 * @param arg Echo backend state.
 * @return None.
 */
static void test_udp_echo_run(void *arg) {
    test_udp_echo_t *echo;
    unsigned char buf[2048];

    echo = (test_udp_echo_t *)arg;
    while (!atomic_load(&echo->stop)) {
        struct sockaddr_storage from;
        test_socklen_t from_len;
        int n;

        from_len = sizeof(from);
        n = (int)recvfrom(echo->fd, (char *)buf, sizeof(buf), 0,
            (struct sockaddr *)&from, &from_len);
        if (n < 0) continue;
        sendto(echo->fd, (const char *)buf, (size_t)n, 0,
            (const struct sockaddr *)&from, from_len);
    }
}

/**
 * Runs one loopback TCP echo backend until stopped.
 * @param arg Echo backend state.
 * @return None.
 */
static void test_tcp_echo_run(void *arg) {
    test_tcp_echo_t *echo;
    unsigned int i;

    echo = (test_tcp_echo_t *)arg;
    while (!atomic_load(&echo->stop)) {
        fd_set readable;
        struct timeval timeout;
        int max_fd;
        int selected;

        FD_ZERO(&readable);
        FD_SET(echo->fd, &readable);
#ifdef _WIN32
        max_fd = 0;
#else
        max_fd = (int)echo->fd;
#endif
        for (i = 0; i < TEST_TCP_CLIENTS; i++) {
            if (echo->clients[i] == TEST_SOCKET_INVALID) continue;
            FD_SET(echo->clients[i], &readable);
#ifndef _WIN32
            if (echo->clients[i] > max_fd) max_fd = echo->clients[i];
#endif
        }
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        selected = select(max_fd + 1, &readable, NULL, NULL, &timeout);
        if (selected <= 0) continue;
        if (FD_ISSET(echo->fd, &readable)) {
            test_socket_t client;

            client = accept(echo->fd, NULL, NULL);
            if (client != TEST_SOCKET_INVALID) {
                for (i = 0; i < TEST_TCP_CLIENTS; i++) {
                    if (echo->clients[i] == TEST_SOCKET_INVALID) break;
                }
                if (i == TEST_TCP_CLIENTS) {
                    test_socket_close(client);
                } else {
                    test_socket_timeout(client, 3000U);
                    echo->clients[i] = client;
                }
            }
        }
        for (i = 0; i < TEST_TCP_CLIENTS; i++) {
            unsigned char buf[1024];
            int n;

            if (echo->clients[i] == TEST_SOCKET_INVALID ||
                !FD_ISSET(echo->clients[i], &readable))
                continue;
            n = (int)recv(echo->clients[i], (char *)buf, sizeof(buf), 0);
            if (n > 0 && test_socket_send_all(echo->clients[i], buf,
                (size_t)n) == 0)
                continue;
            test_socket_close(echo->clients[i]);
            echo->clients[i] = TEST_SOCKET_INVALID;
        }
    }
    for (i = 0; i < TEST_TCP_CLIENTS; i++) {
        if (echo->clients[i] == TEST_SOCKET_INVALID) continue;
        test_socket_close(echo->clients[i]);
        echo->clients[i] = TEST_SOCKET_INVALID;
    }
}

/**
 * Reads one bounded HTTP request head up to the blank line.
 * @param client   Client socket.
 * @param head     Output head buffer.
 * @param cap      Head buffer capacity.
 * @param head_len Output head byte count.
 * @return 0 on success, 1 on failure.
 */
static int test_stub_read_head(test_socket_t client, char *head, int cap,
    int *head_len)
{
    int len;
    int n;

    len = 0;
    while (len < cap - 1) {
        char byte;

        n = (int)recv(client, &byte, 1, 0);
        if (n <= 0) return 1;
        head[len++] = byte;
        if (len >= 4 &&
            head[len - 4] == '\r' && head[len - 3] == '\n' &&
            head[len - 2] == '\r' && head[len - 1] == '\n')
            break;
    }
    head[len] = '\0';
    *head_len = len;
    return 0;
}

/**
 * Reads one Content-Length value from an HTTP request head.
 * @param head     Request head text.
 * @param head_len Request head byte count.
 * @return Content-Length value, or 0 when absent or invalid.
 */
static long test_stub_content_length(const char *head, int head_len) {
    static const char marker[] = "Content-Length:";
    long i;

    for (i = 0; i + (long)sizeof(marker) - 1 <= head_len; i++) {
        long j;
        int matched;

        matched = 1;
        for (j = 0; marker[j] != '\0'; j++) {
            if (head[i + j] != marker[j]) {
                matched = 0;
                break;
            }
        }
        if (matched) {
            long pos;
            long value;

            pos = i + (long)sizeof(marker) - 1;
            while (pos < head_len && head[pos] == ' ') pos++;
            value = 0;
            while (pos < head_len && head[pos] >= '0' && head[pos] <= '9') {
                value = value * 10 + (head[pos] - '0');
                pos++;
            }
            return value;
        }
    }
    return 0;
}

/**
 * Discards one HTTP request body of known length.
 * @param client Client socket.
 * @param len    Remaining body bytes.
 * @return 0 on success, 1 on failure.
 */
static int test_stub_drain_body(test_socket_t client, long len) {
    char buf[256];

    while (len > 0) {
        int want;
        int n;

        want = (int)(len < (long)sizeof(buf) ? len : (long)sizeof(buf));
        n = (int)recv(client, buf, (int)want, 0);
        if (n <= 0) return 1;
        len -= n;
    }
    return 0;
}

/**
 * Serves one closed-before-response and one non-HTTP index response.
 * @param arg Control stub state.
 * @return None.
 */
static void test_control_stub_run(void *arg) {
    static const unsigned char bad_status_line[] =
        "NOT-HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    test_control_stub_t *stub;
    int request;

    stub = (test_control_stub_t *)arg;
    for (request = 0; request < 2; request++) {
        test_socket_t client;
        char head[4096];
        int head_len;

        client = accept(stub->fd, NULL, NULL);
        if (client == TEST_SOCKET_INVALID) return;
        test_socket_timeout(client, 2000U);
        if (test_stub_read_head(client, head, sizeof(head), &head_len) != 0 ||
            test_stub_drain_body(client,
                test_stub_content_length(head, head_len)) != 0)
        {
            test_socket_close(client);
            return;
        }
        if (request == 1)
            test_socket_send_all(client, bad_status_line,
                sizeof(bad_status_line) - 1);
        test_socket_close(client);
    }
}

#ifdef _WIN32
/**
 * Runs an index server thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_index_main(void *arg) {
    test_index_t *index;

    index = (test_index_t *)arg;
    index->result = redp2p_serve_index(index->ctx, NULL, index->port);
    return 0;
}

/**
 * Runs a publisher thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_publisher_main(void *arg) {
    test_publisher_t *publisher;

    publisher = (test_publisher_t *)arg;
    redp2p_set_protocol(publisher->ctx, publisher->protocol);
    redp2p_set_port(publisher->ctx, publisher->bind_port);
    if (publisher->pass != NULL) redp2p_set_pass(publisher->ctx, publisher->pass);
    atomic_store(&publisher->result,
        redp2p_wait(publisher->ctx, publisher->host, publisher->index_port,
            publisher->id, publisher->bind_port));
    return 0;
}

/**
 * Runs a consumer thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_consumer_main(void *arg) {
    test_consumer_t *consumer;

    consumer = (test_consumer_t *)arg;
    redp2p_set_protocol(consumer->ctx, consumer->protocol);
    redp2p_set_port(consumer->ctx, consumer->bind_port);
    atomic_store(&consumer->result,
        redp2p_connect(consumer->ctx, consumer->host, consumer->index_port,
            consumer->self_id, consumer->target_id, consumer->bind_port));
    return 0;
}

/**
 * Runs a UDP echo backend thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_udp_echo_main(void *arg) {
    test_udp_echo_run(arg);
    return 0;
}

/**
 * Runs a TCP echo backend thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_tcp_echo_main(void *arg) {
    test_tcp_echo_run(arg);
    return 0;
}

/**
 * Runs an incomplete-response control stub thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_control_stub_main(void *arg) {
    test_control_stub_run(arg);
    return 0;
}
#else
/**
 * Runs an index server thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static void *test_index_main(void *arg) {
    test_index_t *index;

    index = (test_index_t *)arg;
    index->result = redp2p_serve_index(index->ctx, NULL, index->port);
    return NULL;
}

/**
 * Runs a publisher thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static void *test_publisher_main(void *arg) {
    test_publisher_t *publisher;

    publisher = (test_publisher_t *)arg;
    redp2p_set_protocol(publisher->ctx, publisher->protocol);
    redp2p_set_port(publisher->ctx, publisher->bind_port);
    if (publisher->pass != NULL) redp2p_set_pass(publisher->ctx, publisher->pass);
    atomic_store(&publisher->result,
        redp2p_wait(publisher->ctx, publisher->host, publisher->index_port,
            publisher->id, publisher->bind_port));
    return NULL;
}

/**
 * Runs a consumer thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_consumer_main(void *arg) {
    test_consumer_t *consumer;

    consumer = (test_consumer_t *)arg;
    redp2p_set_protocol(consumer->ctx, consumer->protocol);
    redp2p_set_port(consumer->ctx, consumer->bind_port);
    atomic_store(&consumer->result,
        redp2p_connect(consumer->ctx, consumer->host, consumer->index_port,
            consumer->self_id, consumer->target_id, consumer->bind_port));
    return NULL;
}

/**
 * Runs a UDP echo backend thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_udp_echo_main(void *arg) {
    test_udp_echo_run(arg);
    return NULL;
}

/**
 * Runs a TCP echo backend thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_tcp_echo_main(void *arg) {
    test_tcp_echo_run(arg);
    return NULL;
}

/**
 * Runs an incomplete-response control stub thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_control_stub_main(void *arg) {
    test_control_stub_run(arg);
    return NULL;
}
#endif

/**
 * Starts one thread.
 * @param thread Output thread handle.
 * @param fn Thread entry point.
 * @param arg Thread argument.
 * @return 0 on success, 1 on failure.
 */
static int test_thread_start(test_thread_t *thread,
#ifdef _WIN32
DWORD (WINAPI *fn)(void *),
#else
void *(*fn)(void *),
#endif
void *arg)
{
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, fn, arg, 0, NULL);
    return *thread != NULL ? 0 : 1;
#else
    return pthread_create(thread, NULL, fn, arg) == 0 ? 0 : 1;
#endif
}

/**
 * Joins one thread.
 * @param thread Thread handle.
 * @return 0 on success, 1 on failure.
 */
static int test_thread_join(test_thread_t thread) {
#ifdef _WIN32
    if (WaitForSingleObject(thread, 15000U) != WAIT_OBJECT_0) return 1;
    CloseHandle(thread);
    return 0;
#else
    return pthread_join(thread, NULL) == 0 ? 0 : 1;
#endif
}

/**
 * Starts an index server on a port.
 * @param index Index state.
 * @param port TCP port.
 * @return 0 on success, 1 on failure.
 */
static int test_index_start(test_index_t *index, unsigned short port) {
    memset(index, 0, sizeof(*index));
    index->port = port;
    index->result = 999;
    if (redp2p_open(&index->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&index->thread, test_index_main, index) != 0) return 1;
    return test_wait_port(port, 1) ? 0 : 1;
}

/**
 * Starts one configured index server on a port.
 * @param index Index state.
 * @param port TCP port.
 * @param seats Publisher capacity.
 * @param vip Optional VIP seat map.
 * @param pass Optional global registration password.
 * @return 0 on success, 1 on failure.
 */
static int test_index_start_configured(test_index_t *index,
    unsigned short port, size_t seats, const char *vip, const char *pass)
{
    char err[128];

    memset(index, 0, sizeof(*index));
    index->port = port;
    index->result = 999;
    if (redp2p_open(&index->ctx) != REDP2P_OK) return 1;
    if (redp2p_set_seats(index->ctx, seats) != REDP2P_OK) return 1;
    if (vip != NULL && redp2p_set_vip(index->ctx, vip, err,
        sizeof(err)) != REDP2P_OK)
        return 1;
    if (pass != NULL && redp2p_set_pass(index->ctx, pass) != REDP2P_OK) return 1;
    if (test_thread_start(&index->thread, test_index_main, index) != 0) return 1;
    return test_wait_port(port, 1) ? 0 : 1;
}

/**
 * Stops an index server.
 * @param index Index state.
 * @return 0 on success.
 */
static int test_index_stop(test_index_t *index) {
    if (index->ctx != NULL) redp2p_stop(index->ctx);
    test_port_open(index->port);
    test_thread_join(index->thread);
    if (index->ctx != NULL) redp2p_close(index->ctx);
    index->ctx = NULL;
    return 0;
}

/**
 * Starts a publisher context.
 * @param publisher Publisher state.
 * @param id Publisher id.
 * @param index_port Index control port.
 * @param bind_port Backend port value.
 * @return 0 on success, 1 on failure.
 */
static int test_publisher_start(test_publisher_t *publisher, const char *id,
unsigned short index_port, unsigned short bind_port)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = REDP2P_PROTO_TCP;
    atomic_init(&publisher->result, 999);
    if (redp2p_open(&publisher->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0) return 1;
    return test_wait_publisher_ready(publisher);
}

/**
 * Starts one password-configured TCP publisher context.
 * @param publisher Publisher state.
 * @param id Publisher id.
 * @param index_port Index control port.
 * @param bind_port Backend port value.
 * @param pass Registration password.
 * @return 0 on success, 1 on failure.
 */
static int test_publisher_start_pass(test_publisher_t *publisher,
    const char *id, unsigned short index_port, unsigned short bind_port,
    const char *pass)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = REDP2P_PROTO_TCP;
    publisher->pass = pass;
    atomic_init(&publisher->result, 999);
    if (redp2p_open(&publisher->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0)
        return 1;
    return test_wait_publisher_ready(publisher);
}

/**
 * Stops a publisher context.
 * @param publisher Publisher state.
 * @return 0 on success.
 */
static int test_publisher_stop(test_publisher_t *publisher) {
    if (publisher->ctx != NULL) redp2p_stop(publisher->ctx);
    test_thread_join(publisher->thread);
    if (publisher->ctx != NULL) redp2p_close(publisher->ctx);
    publisher->ctx = NULL;
    return 0;
}

/**
 * Joins one publisher that must have exited without a local stop request.
 * @param publisher Publisher state.
 * @return 0 on success, 1 on failure.
 */
static int test_publisher_finish(test_publisher_t *publisher) {
    int result;

    result = test_thread_join(publisher->thread);
    if (publisher->ctx != NULL) redp2p_close(publisher->ctx);
    publisher->ctx = NULL;
    return result;
}

/**
 * Waits for one publisher operation to return.
 * @param publisher Publisher state.
 * @param timeout_ms Maximum wait in milliseconds.
 * @return 1 when returned, 0 on timeout.
 */
static int test_publisher_wait_result(test_publisher_t *publisher,
    unsigned int timeout_ms)
{
    unsigned int elapsed;

    for (elapsed = 0; elapsed < timeout_ms; elapsed += 50U) {
        if (atomic_load(&publisher->result) != 999) return 1;
        test_sleep_ms(50U);
    }
    return atomic_load(&publisher->result) != 999;
}

/**
 * Starts a UDP publisher.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_publisher_start(test_publisher_t *publisher,
    const char *id, unsigned short index_port, unsigned short bind_port)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = REDP2P_PROTO_UDP;
    atomic_init(&publisher->result, 999);
    if (redp2p_open(&publisher->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0)
        return 1;
    return test_wait_publisher_ready(publisher);
}

/**
 * Starts a UDP consumer.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_consumer_start(test_consumer_t *consumer,
    const char *self_id, const char *target_id, unsigned short index_port,
    unsigned short bind_port)
{
    memset(consumer, 0, sizeof(*consumer));
    consumer->host = TEST_HOST;
    consumer->index_port = index_port;
    consumer->self_id = self_id;
    consumer->target_id = target_id;
    consumer->bind_port = bind_port;
    consumer->protocol = REDP2P_PROTO_UDP;
    atomic_init(&consumer->result, 999);
    if (redp2p_open(&consumer->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&consumer->thread, test_consumer_main,
        consumer) != 0)
        return 1;
    return 0;
}

/**
 * Stops one consumer context.
 * @return 0 on success.
 */
static int test_consumer_stop(test_consumer_t *consumer) {
    struct sockaddr_in addr;
    test_socket_t fd;

    if (consumer->ctx != NULL) redp2p_stop(consumer->ctx);
    fd = socket(AF_INET, consumer->protocol == REDP2P_PROTO_TCP ?
        SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd != TEST_SOCKET_INVALID) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(consumer->bind_port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (consumer->protocol == REDP2P_PROTO_TCP)
            connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
        else
            sendto(fd, "", 0, 0, (const struct sockaddr *)&addr,
                sizeof(addr));
        test_socket_close(fd);
    }
    test_thread_join(consumer->thread);
    if (consumer->ctx != NULL) redp2p_close(consumer->ctx);
    consumer->ctx = NULL;
    return 0;
}

/**
 * Starts one loopback UDP echo backend.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_echo_start(test_udp_echo_t *echo, unsigned short port) {
    struct sockaddr_in addr;

    memset(echo, 0, sizeof(*echo));
    atomic_init(&echo->stop, 0);
    echo->port = port;
    echo->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (echo->fd == TEST_SOCKET_INVALID) return 1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(echo->fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        test_socket_close(echo->fd);
        return 1;
    }
    test_socket_timeout(echo->fd, 100U);
    return test_thread_start(&echo->thread, test_udp_echo_main, echo);
}

/**
 * Stops one loopback UDP echo backend.
 * @return 0 on success.
 */
static int test_udp_echo_stop(test_udp_echo_t *echo) {
    struct sockaddr_in addr;
    test_socket_t fd;

    atomic_store(&echo->stop, 1);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd != TEST_SOCKET_INVALID) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(echo->port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sendto(fd, "", 0, 0, (const struct sockaddr *)&addr, sizeof(addr));
        test_socket_close(fd);
    }
    test_thread_join(echo->thread);
    test_socket_close(echo->fd);
    echo->fd = TEST_SOCKET_INVALID;
    return 0;
}

/**
 * Starts one loopback TCP echo backend.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_echo_start(test_tcp_echo_t *echo, unsigned short port) {
    struct sockaddr_in addr;
    unsigned int i;
    int reuse;

    memset(echo, 0, sizeof(*echo));
    atomic_init(&echo->stop, 0);
    echo->port = port;
    for (i = 0; i < TEST_TCP_CLIENTS; i++)
        echo->clients[i] = TEST_SOCKET_INVALID;
    echo->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (echo->fd == TEST_SOCKET_INVALID) return 1;
    reuse = 1;
    setsockopt(echo->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
        sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(echo->fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(echo->fd, 8) != 0)
    {
        test_socket_close(echo->fd);
        return 1;
    }
    test_socket_timeout(echo->fd, 100U);
    return test_thread_start(&echo->thread, test_tcp_echo_main, echo);
}

/**
 * Stops one loopback TCP echo backend.
 * @return 0 on success.
 */
static int test_tcp_echo_stop(test_tcp_echo_t *echo) {
    atomic_store(&echo->stop, 1);
    test_socket_shutdown(echo->fd);
    test_thread_join(echo->thread);
    test_socket_close(echo->fd);
    echo->fd = TEST_SOCKET_INVALID;
    return 0;
}

/**
 * Starts one bounded incomplete-response control stub.
 * @param stub Control stub state.
 * @param port TCP control port.
 * @return 0 on success, 1 on failure.
 */
static int test_control_stub_start(test_control_stub_t *stub,
    unsigned short port)
{
    struct sockaddr_in addr;
    int reuse;

    memset(stub, 0, sizeof(*stub));
    stub->port = port;
    stub->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (stub->fd == TEST_SOCKET_INVALID) return 1;
    reuse = 1;
    setsockopt(stub->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
        sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(stub->fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(stub->fd, 1) != 0)
    {
        test_socket_close(stub->fd);
        stub->fd = TEST_SOCKET_INVALID;
        return 1;
    }
    return test_thread_start(&stub->thread, test_control_stub_main, stub);
}

/**
 * Stops one completed incomplete-response control stub.
 * @param stub Control stub state.
 * @return 0 on success, 1 on failure.
 */
static int test_control_stub_stop(test_control_stub_t *stub) {
    int result;

    result = test_thread_join(stub->thread);
    if (stub->fd != TEST_SOCKET_INVALID) test_socket_close(stub->fd);
    stub->fd = TEST_SOCKET_INVALID;
    return result;
}

/**
 * Starts one TCP publisher context.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_publisher_start(test_publisher_t *publisher,
    const char *id, unsigned short index_port, unsigned short bind_port)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = REDP2P_PROTO_TCP;
    atomic_init(&publisher->result, 999);
    if (redp2p_open(&publisher->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0)
        return 1;
    return test_wait_publisher_ready(publisher);
}

/**
 * Starts one TCP consumer context.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_consumer_start(test_consumer_t *consumer,
    const char *self_id, const char *target_id, unsigned short index_port,
    unsigned short bind_port)
{
    memset(consumer, 0, sizeof(*consumer));
    consumer->host = TEST_HOST;
    consumer->index_port = index_port;
    consumer->self_id = self_id;
    consumer->target_id = target_id;
    consumer->bind_port = bind_port;
    consumer->protocol = REDP2P_PROTO_TCP;
    atomic_init(&consumer->result, 999);
    if (redp2p_open(&consumer->ctx) != REDP2P_OK) return 1;
    if (test_thread_start(&consumer->thread, test_consumer_main,
        consumer) != 0)
        return 1;
    return test_wait_consumer_ready(consumer);
}

/**
 * Opens one bounded loopback TCP connection.
 * @param port TCP port.
 * @return Connected socket, or TEST_SOCKET_INVALID on failure.
 */
static test_socket_t test_tcp_connect(unsigned short port) {
    test_socket_t fd;
    struct sockaddr_in addr;
    unsigned int attempt;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fd = TEST_SOCKET_INVALID;
    for (attempt = 0; attempt < 20U; attempt++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == TEST_SOCKET_INVALID) return TEST_SOCKET_INVALID;
        test_socket_timeout(fd, 10000U);
        if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0)
            break;
        test_socket_close(fd);
        fd = TEST_SOCKET_INVALID;
        test_sleep_ms(100U);
    }
    return fd;
}

/**
 * Fills one buffer with deterministic non-repeating test bytes.
 * @param data Destination buffer.
 * @param len Byte count.
 * @param seed Pattern seed.
 * @return None.
 */
static void test_tcp_pattern(unsigned char *data, size_t len,
unsigned int seed)
{
    size_t i;

    for (i = 0; i < len; i++)
        data[i] = (unsigned char)((i * 131U + i / 251U + seed) & 0xffU);
}

/**
 * Sends and verifies one exact exchange on an open TCP session.
 * @param fd Connected socket.
 * @param data Bytes to exchange.
 * @param len Byte count.
 * @return Received byte count, or -1 on failure.
 */
static int test_tcp_exchange(test_socket_t fd, const unsigned char *data,
size_t len)
{
    unsigned char *received;
    int result;

    received = (unsigned char *)malloc(len == 0 ? 1 : len);
    if (received == NULL) return -1;
    result = -1;
    if (test_socket_send_all(fd, data, len) == 0 &&
        test_socket_receive_exact(fd, received, len) == 0 &&
        memcmp(received, data, len) == 0)
        result = (int)len;
    free(received);
    return result;
}

/**
 * Sends bytes through one local TCP adapter and waits for their exact echo.
 * @param port TCP port.
 * @param data Bytes to exchange.
 * @param len Byte count.
 * @return Received byte count, or -1 on failure.
 */
static int test_tcp_roundtrip(unsigned short port, const unsigned char *data,
size_t len)
{
    test_socket_t fd;
    int result;

    fd = test_tcp_connect(port);
    if (fd == TEST_SOCKET_INVALID) return -1;
    result = test_tcp_exchange(fd, data, len);
    test_socket_close(fd);
    return result;
}

/**
 * Half-closes the sending direction of one TCP socket.
 * @param fd Connected socket.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_shutdown_send(test_socket_t fd) {
#ifdef _WIN32
    return shutdown(fd, SD_SEND) == 0 ? 0 : 1;
#else
    return shutdown(fd, SHUT_WR) == 0 ? 0 : 1;
#endif
}

/**
 * Drains bounded in-flight bytes and waits for peer closure.
 * @param fd Connected socket.
 * @param limit Maximum bytes accepted before closure.
 * @return 0 when closure is observed, 1 otherwise.
 */
static int test_tcp_wait_closed(test_socket_t fd, size_t limit) {
    unsigned char received[1024];
    size_t total;

    total = 0;
    while (total <= limit) {
        int n;

        n = (int)recv(fd, (char *)received, sizeof(received), 0);
        if (n == 0) return 0;
        if (n < 0 && test_socket_interrupted()) continue;
        if (n < 0) return 1;
        total += (size_t)n;
    }
    return 1;
}

/**
 * Issues one HTTP/1.1 JSON request to an index and checks status plus one
 * response-body fragment.
 * @param port Index port.
 * @param body JSON request body.
 * @param body_len Request body byte count.
 * @param expected_status Expected HTTP status code.
 * @param expected_fragment Text fragment required inside the response, or
 *                          NULL when the response body is not inspected.
 * @return 0 on success, 1 on failure.
 */
static int test_http_request(unsigned short port, const char *body,
    size_t body_len, int expected_status, const char *expected_fragment)
{
    test_socket_t fd;
    char head[512];
    char response[8192];
    const char *cursor;
    size_t total;
    int status;
    int digits;
    int n;

    fd = test_tcp_connect(port);
    if (fd == TEST_SOCKET_INVALID) return 1;
    test_socket_timeout(fd, 2000U);
    n = snprintf(head, sizeof(head),
        "POST /redp2p/ HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "\r\n", TEST_HOST, (unsigned)body_len);
    if (n < 0 || (size_t)n >= sizeof(head) ||
        test_socket_send_all(fd, (const unsigned char *)head, (size_t)n) != 0 ||
        test_socket_send_all(fd, (const unsigned char *)body, body_len) != 0)
    {
        test_socket_close(fd);
        return 1;
    }
    total = 0;
    response[0] = '\0';
    while (total < sizeof(response) - 1) {
        int m;

        m = (int)recv(fd, response + total, sizeof(response) - 1 - total, 0);
        if (m <= 0) break;
        total += (size_t)m;
    }
    response[total] = '\0';
    test_socket_close(fd);
    if (total == 0 || strncmp(response, "HTTP/", 5) != 0) return 1;
    cursor = strchr(response, ' ');
    status = -1;
    if (cursor) {
        while (*cursor == ' ') cursor++;
        status = 0;
        for (digits = 0; digits < 3 && cursor[digits] >= '0' &&
            cursor[digits] <= '9'; digits++)
            status = status * 10 + (cursor[digits] - '0');
        if (digits != 3) status = -1;
    }
    if (status != expected_status) return 1;
    if (expected_fragment != NULL &&
        strstr(response, expected_fragment) == NULL)
        return 1;
    return 0;
}

/**
 * Sends one raw HTTP request and returns its response status code.
 * @param port Index port.
 * @param request Raw request bytes.
 * @param request_len Request byte count.
 * @return HTTP status code, or -1 on failure.
 */
static int test_http_raw_status(unsigned short port, const char *request,
    size_t request_len)
{
    test_socket_t fd;
    const char *cursor;
    char response[8192];
    size_t total;
    int status;
    int digits;

    fd = test_tcp_connect(port);
    if (fd == TEST_SOCKET_INVALID) return -1;
    test_socket_timeout(fd, 2000U);
    if (test_socket_send_all(fd, (const unsigned char *)request,
        request_len) != 0) {
        test_socket_close(fd);
        return -1;
    }
    total = 0;
    response[0] = '\0';
    while (total < sizeof(response) - 1) {
        int m;

        m = (int)recv(fd, response + total, sizeof(response) - 1 - total, 0);
        if (m <= 0) break;
        total += (size_t)m;
    }
    response[total] = '\0';
    test_socket_close(fd);
    if (total == 0 || strncmp(response, "HTTP/", 5) != 0) return -1;
    cursor = strchr(response, ' ');
    status = -1;
    if (cursor) {
        while (*cursor == ' ') cursor++;
        status = 0;
        for (digits = 0; digits < 3 && cursor[digits] >= '0' &&
            cursor[digits] <= '9'; digits++)
            status = status * 10 + (cursor[digits] - '0');
        if (digits != 3) status = -1;
    }
    return status;
}

/**
 * Sends an incomplete HTTP request and verifies server-side closure.
 * @param port Index port.
 * @param request Raw request bytes.
 * @param request_len Request byte count.
 * @return 0 on observed closure, 1 otherwise.
 */
static int test_http_incomplete_closed(unsigned short port,
    const char *request, size_t request_len)
{
    test_socket_t fd;
    int result;

    fd = test_tcp_connect(port);
    if (fd == TEST_SOCKET_INVALID) return 1;
    test_socket_timeout(fd, 2000U);
    test_socket_send_all(fd, (const unsigned char *)request, request_len);
    test_tcp_shutdown_send(fd);
    result = test_tcp_wait_closed(fd, 4096U);
    test_socket_close(fd);
    return result;
}

/**
 * Sends one UDP datagram and waits for its echo.
 * @return Received length, or -1 on timeout or mismatch.
 */
static int test_udp_roundtrip(unsigned short port, const unsigned char *data,
    size_t len, unsigned int timeout_ms)
{
    test_socket_t fd;
    struct sockaddr_in addr;
    unsigned char received[REDP2P_UDP_PAYLOAD_MAX + 1];
    unsigned int attempts;
    unsigned int i;
    int n;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == TEST_SOCKET_INVALID) return -1;
    test_socket_timeout(fd, 500U);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    attempts = timeout_ms / 500U;
    if (attempts == 0) attempts = 1;
    n = -1;
    for (i = 0; i < attempts; i++) {
        if (sendto(fd, (const char *)data, len, 0,
            (const struct sockaddr *)&addr, sizeof(addr)) < 0)
            continue;
        n = (int)recvfrom(fd, (char *)received, sizeof(received), 0,
            NULL, NULL);
        if (n >= 0) break;
    }
    test_socket_close(fd);
    if (n < 0 || (size_t)n != len) {
        fprintf(stderr, "udp roundtrip length: sent=%lu received=%d\n",
            (unsigned long)len, n);
        return -1;
    }
    if (len > 0 && memcmp(received, data, len) != 0) {
        fprintf(stderr, "udp roundtrip payload mismatch\n");
        return -1;
    }
    return n;
}

/**
 * Sends one UDP datagram without waiting for a response.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_send_only(unsigned short port, const unsigned char *data,
    size_t len)
{
    test_socket_t fd;
    struct sockaddr_in addr;
    int result;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == TEST_SOCKET_INVALID) return 1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    result = sendto(fd, (const char *)data, len, 0,
        (const struct sockaddr *)&addr, sizeof(addr)) < 0;
    test_socket_close(fd);
    return result;
}

/**
 * Records one publisher id.
 * @param id Publisher id.
 * @param userdata Publisher collection.
 * @return None.
 */
static void test_on_publisher(const char *id, void *userdata) {
    test_publishers_t *publishers;

    publishers = (test_publishers_t *)userdata;
    if (publishers->count >= 8) return;
    strncpy(publishers->ids[publishers->count], id, REDP2P_ID_MAX);
    publishers->ids[publishers->count][REDP2P_ID_MAX] = '\0';
    publishers->count++;
}

/**
 * Returns whether one publisher id was recorded.
 * @param publishers Publisher collection.
 * @param id Publisher id.
 * @return 1 when present, 0 otherwise.
 */
static int test_has_publisher(test_publishers_t *publishers, const char *id) {
    size_t i;

    for (i = 0; i < publishers->count; i++) {
        if (strcmp(publishers->ids[i], id) == 0) return 1;
    }
    return 0;
}

/**
 * Tests redp2p_options_default.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_options_default(void) {
    redp2p_options_t opts;
    int rc;

    rc = 0;
    opts = redp2p_options_default();
    rc += expect_size("default seats are unrestricted", 0, opts.seats);
    rc += expect_int("default pow", 0, opts.pow);
    rc += expect_int("default sweep", 20, opts.sweep);
    rc += expect_true("default vip is NULL", opts.vip == NULL);
    rc += expect_true("default pass is empty", opts.pass[0] == '\0');
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_options_load_env.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_options_load_env(void) {
    redp2p_options_t opts;
    int rc;

    rc = 0;
    opts = redp2p_options_default();
    test_setenv("REDP2P_SEATS", "7");
    test_setenv("REDP2P_POW", "3");
    test_setenv("REDP2P_PASS", "secret");
    test_setenv("REDP2P_VIP", "vip vip-pass");
    test_setenv("REDP2P_SWEEP", "9");
    test_setenv("REDP2P_STUN", "stun:example.com:3478");
    redp2p_options_load_env(&opts);
    rc += expect_size("env seats", 7, opts.seats);
    rc += expect_int("env pow", 3, opts.pow);
    rc += expect_string("env pass", "secret", opts.pass);
    rc += expect_string("env vip", "vip vip-pass", opts.vip);
    rc += expect_int("env sweep", 9, opts.sweep);
    rc += expect_string("env stun", "stun:example.com:3478", opts.stun_url);
    redp2p_options_load_env(NULL);
    redp2p_options_free(&opts);
    test_setenv("REDP2P_SEATS", NULL);
    test_setenv("REDP2P_POW", NULL);
    test_setenv("REDP2P_PASS", NULL);
    test_setenv("REDP2P_VIP", NULL);
    test_setenv("REDP2P_SWEEP", NULL);
    test_setenv("REDP2P_STUN", NULL);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_options_load_env strict rejection.
 * Summary: Invalid numeric environment values are ignored and keep defaults.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_options_load_env_invalid(void) {
    static const char *invalid[] = {
        "+1", "-1", " 1", "1 ", "1x", ""
    };
    char allocation_overflow[64];
    char numeric_overflow[64];
    redp2p_options_t opts;
    int rc;
    size_t i;
    size_t max_peer_count;

    rc = 0;
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        opts = redp2p_options_default();
        test_setenv("REDP2P_SEATS", invalid[i]);
        test_setenv("REDP2P_POW", invalid[i]);
        test_setenv("REDP2P_SWEEP", invalid[i]);
        redp2p_options_load_env(&opts);
        rc += expect_size("invalid seats kept default", 0,
            opts.seats);
        rc += expect_int("invalid pow kept default", 0, opts.pow);
        rc += expect_int("invalid sweep kept default", 20, opts.sweep);
        redp2p_options_free(&opts);
    }
    max_peer_count = SIZE_MAX / sizeof(redp2p_peer_t);
    snprintf(allocation_overflow, sizeof(allocation_overflow), "%zu",
        max_peer_count + 1);
    snprintf(numeric_overflow, sizeof(numeric_overflow), "%zu0", SIZE_MAX);
    opts = redp2p_options_default();
    test_setenv("REDP2P_SEATS", allocation_overflow);
    redp2p_options_load_env(&opts);
    rc += expect_size("allocation-overflow seats kept default", 0,
        opts.seats);
    redp2p_options_free(&opts);
    opts = redp2p_options_default();
    test_setenv("REDP2P_SEATS", numeric_overflow);
    redp2p_options_load_env(&opts);
    rc += expect_size("numeric-overflow seats kept default", 0, opts.seats);
    redp2p_options_free(&opts);
    opts = redp2p_options_default();
    test_setenv("REDP2P_SEATS", "0");
    test_setenv("REDP2P_POW", "0");
    test_setenv("REDP2P_SWEEP", "0");
    redp2p_options_load_env(&opts);
    rc += expect_size("zero seats accepted", 0, opts.seats);
    rc += expect_int("zero pow accepted", 0, opts.pow);
    rc += expect_int("zero sweep accepted", 0, opts.sweep);
    redp2p_options_free(&opts);
    test_setenv("REDP2P_SEATS", NULL);
    test_setenv("REDP2P_POW", NULL);
    test_setenv("REDP2P_SWEEP", NULL);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_options_free.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_options_free(void) {
    redp2p_options_t opts;
    int rc;

    rc = 0;
    opts = redp2p_options_default();
    test_setenv("REDP2P_VIP", "one pass");
    redp2p_options_load_env(&opts);
    rc += expect_true("vip allocated", opts.vip != NULL);
    redp2p_options_free(&opts);
    rc += expect_true("vip cleared", opts.vip == NULL);
    redp2p_options_free(&opts);
    redp2p_options_free(NULL);
    test_setenv("REDP2P_VIP", NULL);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_open.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_open(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    ctx = NULL;
    rc += expect_int("open NULL", REDP2P_ERROR, redp2p_open(NULL));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_true("context is set", ctx != NULL);
    if (ctx != NULL) redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_close.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_close(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("close NULL", REDP2P_ERROR, redp2p_close(NULL));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("close context", REDP2P_OK, redp2p_close(ctx));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_stop.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_stop(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("stop NULL", REDP2P_EINVAL, redp2p_stop(NULL));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_true("stop initially clear", !redp2p_stop_requested(ctx));
    rc += expect_int("stop context", REDP2P_OK, redp2p_stop(ctx));
    rc += expect_true("stop requested", redp2p_stop_requested(ctx));
    rc += expect_int("stop context twice", REDP2P_OK, redp2p_stop(ctx));
    rc += expect_true("stop remains requested", redp2p_stop_requested(ctx));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_version.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_version(void) {
    return expect_true("version is available", redp2p_version() != 0U);
}

/**
 * Tests redp2p_strerror.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_strerror(void) {
    int rc;

    rc = 0;
    rc += expect_string("OK text", "OK", redp2p_strerror(REDP2P_OK));
    rc += expect_string("ERROR text", "general error", redp2p_strerror(REDP2P_ERROR));
    rc += expect_string("ENET text", "network error", redp2p_strerror(REDP2P_ENET));
    rc += expect_string("ENOENT text", "peer not found", redp2p_strerror(REDP2P_ENOENT));
    rc += expect_string("ETIMEOUT text", "timeout", redp2p_strerror(REDP2P_ETIMEOUT));
    rc += expect_string("EFULL text", "peer table full", redp2p_strerror(REDP2P_EFULL));
    rc += expect_string("EINVAL text", "invalid argument",
        redp2p_strerror(REDP2P_EINVAL));
    rc += expect_string("EPROTO text", "protocol error",
        redp2p_strerror(REDP2P_EPROTO));
    rc += expect_string("EAUTH text", "authentication failed",
        redp2p_strerror(REDP2P_EAUTH));
    rc += expect_string("EVERSION text", "unsupported protocol version",
        redp2p_strerror(REDP2P_EVERSION));
    rc += expect_string("EPUNCH text", "direct connectivity failed",
        redp2p_strerror(REDP2P_EPUNCH));
    rc += expect_string("unknown text", "unknown error", redp2p_strerror(999));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_is_valid_id.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_is_valid_id(void) {
    int rc;

    rc = 0;
    rc += expect_int("alphanumeric id", 1, redp2p_is_valid_id("abcXYZ123"));
    rc += expect_int("single id", 1, redp2p_is_valid_id("a"));
    rc += expect_int("NULL id", 0, redp2p_is_valid_id(NULL));
    rc += expect_int("empty id", 0, redp2p_is_valid_id(""));
    rc += expect_int("punctuation id", 0, redp2p_is_valid_id("bad:id"));
    rc += expect_int("space id", 0, redp2p_is_valid_id("bad id"));
    rc += expect_int("long id", 0, redp2p_is_valid_id(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_is_valid_pass_token.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_is_valid_pass_token(void) {
    int rc;

    rc = 0;
    rc += expect_int("safe pass", 1, redp2p_is_valid_pass_token("a._-+=,:@%/"));
    rc += expect_int("single pass", 1, redp2p_is_valid_pass_token("x"));
    rc += expect_int("NULL pass", 0, redp2p_is_valid_pass_token(NULL));
    rc += expect_int("empty pass", 0, redp2p_is_valid_pass_token(""));
    rc += expect_int("space pass", 0, redp2p_is_valid_pass_token("bad pass"));
    rc += expect_int("unsafe pass", 0, redp2p_is_valid_pass_token("bad`pass"));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_serve_index.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_serve_index(void) {
    test_index_t index;
    test_publisher_t first;
    test_publisher_t second;
    test_publisher_t third;
    redp2p_t *stopped;
    char too_many[4096];
    char overlong_line[TEST_HTTP_LINE_MAX * TEST_HTTP_HEADERS_MAX + 64];
    char incomplete_body[64];
    unsigned short port;
    size_t used;
    int i;
    int rc;

    rc = 0;
    port = (unsigned short)(test_port_base() + 1U);
    rc += expect_int("serve NULL", REDP2P_EINVAL,
        redp2p_serve_index(NULL, TEST_HOST, port));
    rc += expect_int("open stopped index context", REDP2P_OK,
        redp2p_open(&stopped));
    rc += expect_int("stop index before entry", REDP2P_OK,
        redp2p_stop(stopped));
    rc += expect_int("serve honors prior stop", REDP2P_OK,
        redp2p_serve_index(stopped, TEST_HOST, port));
    rc += expect_true("prior-stopped index did not listen",
        !test_port_open(port));
    memset(&index, 0, sizeof(index));
    index.ctx = stopped;
    index.port = port;
    index.result = 999;
    if (test_thread_start(&index.thread, test_index_main, &index) != 0)
        return 1;
    if (!test_wait_port(port, 1)) return 1;
    rc += expect_true("index accepts TCP", test_port_open(port));
    rc += expect_int("reject malformed JSON", 0,
        test_http_request(port, "{\"op\":\"register\",id:1}",
            strlen("{\"op\":\"register\",id:1}"), 400,
            "\"error\":\"bad_request\""));
    rc += expect_int("reject non-object JSON", 0,
        test_http_request(port, "[1,2]", 5, 400,
            "\"error\":\"bad_request\""));
    rc += expect_int("reject duplicate JSON fields", 0,
        test_http_request(port, "{\"op\":\"list\",\"op\":\"list\"}",
            strlen("{\"op\":\"list\",\"op\":\"list\"}"), 400,
            "\"error\":\"bad_request\""));
    rc += expect_int("reject missing op", 0,
        test_http_request(port, "{\"id\":\"x\"}",
            strlen("{\"id\":\"x\"}"), 400, "\"error\":\"bad_request\""));
    rc += expect_int("reject unknown op", 0,
        test_http_request(port, "{\"op\":\"frobnicate\"}",
            strlen("{\"op\":\"frobnicate\"}"), 400,
            "\"error\":\"bad_request\""));
    rc += expect_int("reject invalid register id", 0,
        test_http_request(port, "{\"op\":\"register\",\"id\":\"bad:id\"}",
            strlen("{\"op\":\"register\",\"id\":\"bad:id\"}"), 400,
            "\"error\":\"invalid_id\""));
    rc += expect_int("reject lookup missing id", 0,
        test_http_request(port, "{\"op\":\"lookup\"}",
            strlen("{\"op\":\"lookup\"}"), 400, "\"error\":\"bad_request\""));
    rc += expect_int("reject punch_req missing session", 0,
        test_http_request(port,
            "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\"}",
            strlen("{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\"}"),
            400, "\"error\":\"bad_request\""));
    rc += expect_int("reject punch_req invalid session", 0,
        test_http_request(port,
            "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"bad token\"}",
            strlen("{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"bad token\"}"),
            400, "\"error\":\"bad_request\""));
    rc += expect_int("reject candidate type", 0,
        test_http_request(port,
            "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[{\"type\":\"bogus\",\"addr\":\"127.0.0.1\",\"port\":9}]}",
            strlen("{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[{\"type\":\"bogus\",\"addr\":\"127.0.0.1\",\"port\":9}]}"),
            400, "\"error\":\"bad_request\""));
    rc += expect_int("reject candidate address", 0,
        test_http_request(port,
            "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[{\"type\":\"host\",\"addr\":\"not-an-address\",\"port\":9}]}",
            strlen("{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[{\"type\":\"host\",\"addr\":\"not-an-address\",\"port\":9}]}"),
            400, "\"error\":\"bad_request\""));
    rc += expect_int("reject candidate port", 0,
        test_http_request(port,
            "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[{\"type\":\"host\",\"addr\":\"127.0.0.1\",\"port\":0}]}",
            strlen("{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[{\"type\":\"host\",\"addr\":\"127.0.0.1\",\"port\":0}]}"),
            400, "\"error\":\"bad_request\""));
    rc += expect_int("reject candidate non-object", 0,
        test_http_request(port,
            "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[1]}",
            strlen("{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess1\",\"candidates\":[1]}"),
            400, "\"error\":\"bad_request\""));
    used = (size_t)snprintf(too_many, sizeof(too_many),
        "{\"op\":\"punch_req\",\"self_id\":\"client\",\"target_id\":\"missing\",\"session\":\"sess2\",\"candidates\":[");
    for (i = 0; i < REDP2P_PEER_CANDIDATES_MAX + 1 &&
        used < sizeof(too_many); i++)
    {
        int written;

        written = snprintf(too_many + used, sizeof(too_many) - used,
            "%s{\"type\":\"host\",\"addr\":\"127.0.0.1\",\"port\":%d}",
            i == 0 ? "" : ",", i + 1);
        if (written < 0 || (size_t)written >= sizeof(too_many) - used) {
            used = sizeof(too_many);
            break;
        }
        used += (size_t)written;
    }
    if (used < sizeof(too_many)) {
        int written = snprintf(too_many + used, sizeof(too_many) - used,
            "]}");
        if (written < 0 || (size_t)written >= sizeof(too_many) - used)
            used = sizeof(too_many);
        else
            used += (size_t)written;
    }
    rc += expect_true("build excessive candidate block",
        used < sizeof(too_many));
    if (used < sizeof(too_many))
        rc += expect_int("reject excessive candidate count", 0,
            test_http_request(port, too_many, used, 400,
                "\"error\":\"bad_request\""));
    used = (size_t)snprintf(overlong_line, sizeof(overlong_line),
        "POST /redp2p/ HTTP/1.1\r\nX-Filler: ");
    for (i = (int)used; (size_t)i < sizeof(overlong_line); i++)
        overlong_line[i] = 'a';
    rc += expect_int("reject overlong request headers", 431,
        test_http_raw_status(port, overlong_line, sizeof(overlong_line)));
    used = (size_t)snprintf(incomplete_body, sizeof(incomplete_body),
        "POST /redp2p/ HTTP/1.1\r\nContent-Length: 5\r\n\r\nab");
    rc += expect_int("close incomplete request body", 0,
        test_http_incomplete_closed(port, incomplete_body, used));
    rc += expect_int("index usable after malformed requests", 0,
        test_http_request(port, "{\"op\":\"list\"}",
            strlen("{\"op\":\"list\"}"), 200, "\"ok\":true"));
    test_index_stop(&index);
    rc += expect_int("stopped index result", REDP2P_OK, index.result);
    rc += expect_true("index port closed", test_wait_port(port, 0));

    port = (unsigned short)(test_port_base() + 2U);
    rc += expect_int("start capacity-limited index", 0,
        test_index_start_configured(&index, port, 2, NULL, NULL));
    rc += expect_int("start first capacity publisher", 0,
        test_publisher_start(&first, "capone", port,
            (unsigned short)(port + 20U)));
    rc += expect_true("first capacity publisher active",
        atomic_load(&first.result) == 999);
    rc += expect_int("start second capacity publisher", 0,
        test_publisher_start(&second, "captwo", port,
            (unsigned short)(port + 21U)));
    rc += expect_true("second capacity publisher active",
        atomic_load(&second.result) == 999);
    rc += expect_int("start over-capacity publisher", 0,
        test_publisher_start(&third, "capthree", port,
            (unsigned short)(port + 22U)));
    rc += expect_true("capacity reached is reported",
        test_publisher_wait_result(&third, 2000U));
    rc += expect_int("capacity rejection category", REDP2P_EFULL,
        atomic_load(&third.result));
    rc += expect_true("capacity rejection detail",
        strstr(redp2p_get_error(third.ctx), "full") != NULL);
    test_publisher_finish(&third);
    test_publisher_stop(&first);
    rc += expect_int("lookup removed disconnected publisher", 0,
        test_http_request(port, "{\"op\":\"lookup\",\"id\":\"capone\"}",
            strlen("{\"op\":\"lookup\",\"id\":\"capone\"}"), 404,
            "\"error\":\"not_found\""));
    rc += expect_int("start publisher after capacity release", 0,
        test_publisher_start(&third, "capthree", port,
            (unsigned short)(port + 22U)));
    rc += expect_true("released capacity is reusable",
        atomic_load(&third.result) == 999);
    test_publisher_stop(&third);
    test_publisher_stop(&second);
    test_index_stop(&index);

    port = (unsigned short)(test_port_base() + 3U);
    rc += expect_int("start reserved-seat index", 0,
        test_index_start_configured(&index, port, 2, "vip vippass",
            "globalpass"));
    rc += expect_int("start VIP publisher", 0,
        test_publisher_start_pass(&first, "vip", port,
            (unsigned short)(port + 20U), "vippass"));
    rc += expect_int("start available non-VIP publisher", 0,
        test_publisher_start_pass(&second, "regular", port,
            (unsigned short)(port + 21U), "globalpass"));
    rc += expect_true("VIP reserved seat active",
        atomic_load(&first.result) == 999);
    rc += expect_true("non-VIP capacity active",
        atomic_load(&second.result) == 999);
    rc += expect_int("start excess non-VIP publisher", 0,
        test_publisher_start_pass(&third, "excess", port,
            (unsigned short)(port + 22U), "globalpass"));
    rc += expect_true("VIP reservation limits non-VIP seats",
        test_publisher_wait_result(&third, 2000U));
    rc += expect_int("reserved capacity rejection category", REDP2P_EFULL,
        atomic_load(&third.result));
    test_publisher_finish(&third);
    rc += expect_int("start wrong-password VIP publisher", 0,
        test_publisher_start_pass(&third, "vip", port,
            (unsigned short)(port + 22U), "wrongpass"));
    rc += expect_true("wrong-password VIP publisher returns",
        test_publisher_wait_result(&third, 2000U));
    rc += expect_int("registration mismatch category", REDP2P_EAUTH,
        atomic_load(&third.result));
    rc += expect_true("registration mismatch detail",
        strstr(redp2p_get_error(third.ctx), "auth_failed") != NULL);
    test_publisher_finish(&third);
    test_publisher_stop(&second);
    test_publisher_stop(&first);
    test_index_stop(&index);

    port = (unsigned short)(test_port_base() + 4U);
    rc += expect_int("start zero-seat index", 0,
        test_index_start_configured(&index, port, 0, NULL, NULL));
    rc += expect_int("start publisher against zero-seat index", 0,
        test_publisher_start(&first, "noseat", port,
            (unsigned short)(port + 20U)));
    rc += expect_true("zero seats rejects publisher",
        test_publisher_wait_result(&first, 2000U));
    rc += expect_int("zero-seat rejection category", REDP2P_EFULL,
        atomic_load(&first.result));
    test_publisher_finish(&first);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_wait.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_wait(void) {
    test_index_t index;
    test_publisher_t publisher;
    redp2p_t *ctx;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 20U);
    rc += expect_int("wait NULL", REDP2P_EINVAL,
        redp2p_wait(NULL, TEST_HOST, base, "pub", (unsigned short)(base + 1U)));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("stop wait before entry", REDP2P_OK, redp2p_stop(ctx));
    rc += expect_int("wait honors prior stop", REDP2P_OK,
        redp2p_wait(ctx, TEST_HOST, base, "pub",
            (unsigned short)(base + 1U)));
    rc += expect_true("wait stop consumed", !redp2p_stop_requested(ctx));
    rc += expect_int("wait without index", REDP2P_ENET,
        redp2p_wait(ctx, TEST_HOST, base, "pub", (unsigned short)(base + 1U)));
    redp2p_close(ctx);
    if (test_index_start(&index, (unsigned short)(base + 2U)) != 0) return 1;
    if (test_publisher_start(&publisher, "waitpub", (unsigned short)(base + 2U),
        (unsigned short)(base + 3U)) != 0) return 1;
    rc += expect_true("publisher remains running",
        atomic_load(&publisher.result) == 999);
    test_index_stop(&index);
    rc += expect_true("publisher exits after index stop",
        test_publisher_wait_result(&publisher, 3000U));
    rc += expect_int("index loss publisher category", REDP2P_ENET,
        atomic_load(&publisher.result));
    rc += expect_true("index loss publisher detail",
        strstr(redp2p_get_error(publisher.ctx), "index connect") != NULL);
    test_publisher_finish(&publisher);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_connect.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_connect(void) {
    test_control_stub_t stub;
    test_index_t index;
    test_publisher_t publisher;
    test_tcp_echo_t occupied;
    redp2p_t *ctx;
    unsigned short base;
    int stub_started;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 40U);
    rc += expect_int("connect NULL", REDP2P_EINVAL,
        redp2p_connect(NULL, TEST_HOST, base, "client", "missing",
            (unsigned short)(base + 1U)));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    redp2p_set_port(ctx, (unsigned short)(base + 1U));
    rc += expect_int("stop connect before entry", REDP2P_OK, redp2p_stop(ctx));
    rc += expect_int("connect honors prior stop", REDP2P_OK,
        redp2p_connect(ctx, TEST_HOST, base, "client", "missing",
            (unsigned short)(base + 1U)));
    rc += expect_true("connect stop consumed", !redp2p_stop_requested(ctx));
    redp2p_set_port(ctx, (unsigned short)(base + 1U));
    rc += expect_int("connect without index", REDP2P_ENET,
        redp2p_connect(ctx, TEST_HOST, base, "client", "missing",
            (unsigned short)(base + 1U)));
    redp2p_close(ctx);
    if (test_index_start(&index, (unsigned short)(base + 2U)) != 0) return 1;
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    redp2p_set_port(ctx, (unsigned short)(base + 3U));
    rc += expect_int("connect missing target", REDP2P_ENOENT,
        redp2p_connect(ctx, TEST_HOST, (unsigned short)(base + 2U), "client",
            "missing", (unsigned short)(base + 3U)));
    redp2p_close(ctx);
    rc += expect_int("start occupied-listener publisher", 0,
        test_publisher_start(&publisher, "occupied",
            (unsigned short)(base + 2U), (unsigned short)(base + 6U)));
    rc += expect_int("occupy consumer listener", 0,
        test_tcp_echo_start(&occupied, (unsigned short)(base + 7U)));
    rc += expect_int("open occupied-listener context", REDP2P_OK,
        redp2p_open(&ctx));
    redp2p_set_port(ctx, (unsigned short)(base + 7U));
    rc += expect_int("occupied consumer listener category", REDP2P_ENET,
        redp2p_connect(ctx, TEST_HOST, (unsigned short)(base + 2U), "client",
            "occupied", (unsigned short)(base + 7U)));
    redp2p_close(ctx);
    test_tcp_echo_stop(&occupied);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    stub_started = test_control_stub_start(&stub,
        (unsigned short)(base + 4U));
    rc += expect_int("start incomplete index response", 0, stub_started);
    if (stub_started == 0) {
        rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
        redp2p_set_port(ctx, (unsigned short)(base + 5U));
        rc += expect_int("reject closed index response", REDP2P_ENET,
            redp2p_connect(ctx, TEST_HOST, (unsigned short)(base + 4U),
                "client", "missing", (unsigned short)(base + 5U)));
        rc += expect_int("reject malformed index status line", REDP2P_EPROTO,
            redp2p_connect(ctx, TEST_HOST, (unsigned short)(base + 4U),
                "client", "missing", (unsigned short)(base + 5U)));
        rc += expect_true("malformed status line detail",
            strstr(redp2p_get_error(ctx), "index status line") != NULL);
        redp2p_close(ctx);
        rc += expect_int("stop incomplete index response", 0,
            test_control_stub_stop(&stub));
    }
    return rc == 0 ? 0 : 1;
}

/**
 * Runs one public-API UDP payload regression scenario.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_tunnel_case(void)
{
    test_index_t index;
    test_publisher_t publisher;
    test_consumer_t consumer;
    test_udp_echo_t echo;
    unsigned char payload[REDP2P_UDP_PAYLOAD_MAX + 1];
    unsigned short base;
    unsigned int elapsed;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 300U);
    memset(payload, 0x5a, sizeof(payload));
    rc += expect_int("start UDP echo", 0,
        test_udp_echo_start(&echo, (unsigned short)(base + 1U)));
    rc += expect_int("start UDP index", 0, test_index_start(&index, base));
    rc += expect_int("start UDP publisher", 0,
        test_udp_publisher_start(&publisher, "udppub", base,
            (unsigned short)(base + 1U)));
    rc += expect_int("start UDP consumer", 0,
        test_udp_consumer_start(&consumer, "udpclient", "udppub", base,
            (unsigned short)(base + 2U)));
    if (rc == 0) {
        int small_result = test_udp_roundtrip(
            (unsigned short)(base + 2U), payload, 3, 3000U);
        rc += expect_int("UDP small datagram", 3, small_result);
        if (small_result < 0)
            fprintf(stderr,
                "consumer result: %d error: %s\npublisher result: %d error: %s\n",
                atomic_load(&consumer.result), redp2p_get_error(consumer.ctx),
                atomic_load(&publisher.result),
                redp2p_get_error(publisher.ctx));
        rc += expect_int("UDP empty datagram", 0,
            test_udp_roundtrip((unsigned short)(base + 2U), payload, 0, 3000U));
        rc += expect_int("UDP maximum datagram", REDP2P_UDP_PAYLOAD_MAX,
            test_udp_roundtrip((unsigned short)(base + 2U), payload,
                REDP2P_UDP_PAYLOAD_MAX, 3000U));
        rc += expect_int("send UDP oversized datagram", 0,
            test_udp_send_only((unsigned short)(base + 2U), payload,
                REDP2P_UDP_PAYLOAD_MAX + 1));
        for (elapsed = 0; elapsed < 2000U; elapsed += 50U) {
            if (strstr(redp2p_get_error(consumer.ctx),
                "exceeds maximum") != NULL)
                break;
            test_sleep_ms(50U);
        }
        rc += expect_true("UDP oversized datagram rejected",
            redp2p_get_error(consumer.ctx)[0] != '\0');
        rc += expect_true("UDP oversized detail",
            strstr(redp2p_get_error(consumer.ctx), "exceeds maximum") != NULL);
    }
    test_consumer_stop(&consumer);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    test_udp_echo_stop(&echo);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests plaintext UDP datagrams and MTU enforcement.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_udp_tunnel(void) {
    return test_udp_tunnel_case();
}

/**
 * Exercises bounded TCP stream lifecycle and payload behavior.
 * @param port Local TCP adapter port.
 * @param echo Running TCP backend stopped by the final close scenario.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_stream_coverage(unsigned short port, test_tcp_echo_t *echo) {
    unsigned char first[1537];
    unsigned char second[3073];
    unsigned char concurrent_first[4096];
    unsigned char concurrent_first_received[4096];
    unsigned char concurrent_second[6145];
    unsigned char concurrent_second_received[6145];
    unsigned char half_payload[4097];
    unsigned char half_received[4097];
    unsigned char ready[1];
    unsigned char *large;
    test_socket_t fd;
    test_socket_t first_fd;
    test_socket_t second_fd;
    char *drop_previous;
    char *reorder_previous;
    const char *env;
    int drop_saved;
    int fault_env_ready;
    int reorder_saved;
    int result;
    int rc;

    rc = 0;
    drop_previous = NULL;
    reorder_previous = NULL;
    env = getenv("REDP2P_DEBUG_STREAM_DROP_EVERY");
    if (env != NULL) {
        drop_previous = (char *)malloc(strlen(env) + 1U);
        if (drop_previous != NULL) memcpy(drop_previous, env, strlen(env) + 1U);
    }
    drop_saved = env == NULL || drop_previous != NULL;
    env = getenv("REDP2P_DEBUG_STREAM_REORDER_EVERY");
    if (env != NULL) {
        reorder_previous = (char *)malloc(strlen(env) + 1U);
        if (reorder_previous != NULL)
            memcpy(reorder_previous, env, strlen(env) + 1U);
    }
    reorder_saved = env == NULL || reorder_previous != NULL;
    fault_env_ready = drop_saved && reorder_saved;
    rc += expect_true("save TCP fault environment", fault_env_ready);
    if (fault_env_ready) {
        fault_env_ready = test_setenv("REDP2P_DEBUG_STREAM_DROP_EVERY", "7") == 0 &&
            test_setenv("REDP2P_DEBUG_STREAM_REORDER_EVERY", "11") == 0;
        rc += expect_true("enable TCP drop and reorder faults", fault_env_ready);
    }
    large = (unsigned char *)malloc(TEST_TCP_LARGE_SIZE);
    rc += expect_true("allocate TCP patterned payload", large != NULL);
    if (large != NULL) {
        test_tcp_pattern(large, TEST_TCP_LARGE_SIZE, 7U);
        if (fault_env_ready)
            rc += expect_int(
                "TCP KCP datagram drop/reorder recovery",
                (int)TEST_TCP_LARGE_SIZE,
                test_tcp_roundtrip(port, large, TEST_TCP_LARGE_SIZE));
    }
    rc += expect_int("restore TCP drop fault environment", 0,
        drop_saved ? test_setenv("REDP2P_DEBUG_STREAM_DROP_EVERY",
            drop_previous) : 0);
    rc += expect_int("restore TCP reorder fault environment", 0,
        reorder_saved ? test_setenv("REDP2P_DEBUG_STREAM_REORDER_EVERY",
            reorder_previous) : 0);
    free(drop_previous);
    free(reorder_previous);

    test_tcp_pattern(first, sizeof(first), 11U);
    test_tcp_pattern(second, sizeof(second), 23U);
    fd = test_tcp_connect(port);
    rc += expect_true("open TCP bidirectional session",
        fd != TEST_SOCKET_INVALID);
    if (fd != TEST_SOCKET_INVALID) {
        rc += expect_int("TCP first same-session direction",
            (int)sizeof(first), test_tcp_exchange(fd, first, sizeof(first)));
        rc += expect_int("TCP second same-session direction",
            (int)sizeof(second), test_tcp_exchange(fd, second, sizeof(second)));
        test_socket_close(fd);
    }

    test_tcp_pattern(half_payload, sizeof(half_payload), 31U);
    memset(half_received, 0, sizeof(half_received));
    fd = test_tcp_connect(port);
    rc += expect_true("open TCP half-close session",
        fd != TEST_SOCKET_INVALID);
    if (fd != TEST_SOCKET_INVALID) {
        result = test_socket_send_all(fd, half_payload,
            sizeof(half_payload));
        if (result == 0) result = test_tcp_shutdown_send(fd);
        if (result == 0)
            result = test_socket_receive_exact(fd, half_received,
                sizeof(half_received));
        if (result == 0 && memcmp(half_payload, half_received,
            sizeof(half_payload)) != 0)
            result = 1;
        rc += expect_int("TCP half-close preserves pending response", 0,
            result);
        rc += expect_int("TCP half-close reaches peer EOF", 0,
            test_tcp_wait_closed(fd, 0));
        test_socket_close(fd);
    }

    test_tcp_pattern(concurrent_first, sizeof(concurrent_first), 43U);
    test_tcp_pattern(concurrent_second, sizeof(concurrent_second), 59U);
    first_fd = test_tcp_connect(port);
    second_fd = test_tcp_connect(port);
    rc += expect_true("open bounded concurrent TCP sessions",
        first_fd != TEST_SOCKET_INVALID && second_fd != TEST_SOCKET_INVALID);
    if (first_fd != TEST_SOCKET_INVALID &&
        second_fd != TEST_SOCKET_INVALID)
    {
        result = test_socket_send_all(first_fd, concurrent_first,
            sizeof(concurrent_first));
        if (result == 0)
            result = test_socket_send_all(second_fd, concurrent_second,
                sizeof(concurrent_second));
        if (result == 0)
            result = test_socket_receive_exact(first_fd,
                concurrent_first_received,
                sizeof(concurrent_first));
        if (result == 0 && memcmp(concurrent_first, concurrent_first_received,
            sizeof(concurrent_first)) != 0)
            result = 1;
        if (result == 0)
            result = test_socket_receive_exact(second_fd,
                concurrent_second_received,
                sizeof(concurrent_second));
        if (result == 0 && memcmp(concurrent_second,
            concurrent_second_received,
            sizeof(concurrent_second)) != 0)
            result = 1;
        rc += expect_int("TCP concurrent session isolation", 0, result);
    }
    if (first_fd != TEST_SOCKET_INVALID) test_socket_close(first_fd);
    if (second_fd != TEST_SOCKET_INVALID) test_socket_close(second_fd);

    if (large != NULL) {
        fd = test_tcp_connect(port);
        rc += expect_true("open TCP client-close session",
            fd != TEST_SOCKET_INVALID);
        if (fd != TEST_SOCKET_INVALID) {
            rc += expect_int("send TCP client-close payload", 0,
                test_socket_send_all(fd, large, TEST_TCP_LARGE_SIZE / 2U));
            test_socket_close(fd);
        }
        rc += expect_int("TCP session after client close", (int)sizeof(first),
            test_tcp_roundtrip(port, first, sizeof(first)));
    }

    ready[0] = 0xa5U;
    fd = test_tcp_connect(port);
    rc += expect_true("open TCP backend-close session",
        fd != TEST_SOCKET_INVALID);
    if (fd != TEST_SOCKET_INVALID) {
        rc += expect_int("establish TCP backend-close session", 1,
            test_tcp_exchange(fd, ready, sizeof(ready)));
        if (large != NULL)
            rc += expect_int("send TCP backend-close payload", 0,
                test_socket_send_all(fd, large, TEST_TCP_LARGE_SIZE / 2U));
    }
    test_tcp_echo_stop(echo);
    if (fd != TEST_SOCKET_INVALID) {
        rc += expect_int("TCP backend close reaches client", 0,
            test_tcp_wait_closed(fd, TEST_TCP_LARGE_SIZE / 2U));
        test_socket_close(fd);
    }
    free(large);
    return rc == 0 ? 0 : 1;
}

/**
 * Runs the public-API TCP stream regression scenario.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_tunnel_case(void)
{
    test_index_t index;
    test_publisher_t publisher;
    test_consumer_t consumer;
    test_tcp_echo_t echo;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 400U);
    rc += expect_int("start TCP echo", 0,
        test_tcp_echo_start(&echo, (unsigned short)(base + 1U)));
    rc += expect_int("start TCP index", 0, test_index_start(&index, base));
    rc += expect_int("start TCP publisher", 0,
        test_tcp_publisher_start(&publisher, "tcppub", base,
            (unsigned short)(base + 1U)));
    rc += expect_int("start TCP consumer", 0,
        test_tcp_consumer_start(&consumer, "tcpclient", "tcppub", base,
            (unsigned short)(base + 2U)));
    if (rc == 0) {
        rc += test_tcp_stream_coverage((unsigned short)(base + 2U), &echo);
    } else {
        test_tcp_echo_stop(&echo);
    }
    test_consumer_stop(&consumer);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests TCP stream through the public API.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_tcp_stream(void) {
    return test_tcp_tunnel_case();
}

/**
 * Tests redp2p_deregister.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_deregister(void) {
    test_index_t first_index;
    test_index_t second_index;
    test_publisher_t first_publisher;
    test_publisher_t second_publisher;
    test_publisher_t publisher;
    test_publishers_t publishers;
    redp2p_t *client;
    char names[8][128];
    char paths[8][768];
    char key_data[64];
    char legacy_path[768];
    char blocked_home[640];
    char long_home[900];
    size_t key_len;
    unsigned short base;
    int first_index_started;
    int second_index_started;
    int first_publisher_started;
    int second_publisher_started;
    int publisher_started;
    int count;
    int rc;
#ifndef _WIN32
    mode_t old_umask;
    struct stat status;
#endif

    rc = 0;
    client = NULL;
    first_index_started = 0;
    second_index_started = 0;
    first_publisher_started = 0;
    second_publisher_started = 0;
    publisher_started = 0;
    memset(&first_index, 0, sizeof(first_index));
    memset(&second_index, 0, sizeof(second_index));
    memset(&first_publisher, 0, sizeof(first_publisher));
    memset(&second_publisher, 0, sizeof(second_publisher));
    memset(&publisher, 0, sizeof(publisher));
#ifndef _WIN32
    old_umask = umask(000);
#endif
    base = (unsigned short)(test_port_base() + 60U);
    rc += expect_int("open client", REDP2P_OK, redp2p_open(&client));
    if (!client) goto cleanup;
    rc += expect_int("deregister NULL context", REDP2P_EINVAL,
        redp2p_deregister(NULL, TEST_HOST, base, "absent"));
    rc += expect_int("deregister NULL host", REDP2P_EINVAL,
        redp2p_deregister(client, NULL, base, "absent"));
    rc += expect_true("NULL host detail", redp2p_get_error(client)[0] != '\0');
    rc += expect_int("deregister empty host", REDP2P_EINVAL,
        redp2p_deregister(client, "", base, "absent"));
    rc += expect_int("deregister zero port", REDP2P_EINVAL,
        redp2p_deregister(client, TEST_HOST, 0, "absent"));
    rc += expect_int("deregister invalid id", REDP2P_EINVAL,
        redp2p_deregister(client, TEST_HOST, base, "../unsafe"));
    rc += expect_int("deregister missing key", REDP2P_ENOENT,
        redp2p_deregister(client, TEST_HOST, base, "absent"));

    if (test_index_start(&first_index, (unsigned short)(base + 1U)) != 0)
        goto cleanup;
    first_index_started = 1;
    if (test_index_start(&second_index, (unsigned short)(base + 2U)) != 0)
        goto cleanup;
    second_index_started = 1;
    if (test_publisher_start(&first_publisher, "shared",
        (unsigned short)(base + 1U), (unsigned short)(base + 3U)) != 0)
        goto cleanup;
    first_publisher_started = 1;
    if (test_publisher_start(&second_publisher, "shared",
        (unsigned short)(base + 2U), (unsigned short)(base + 4U)) != 0)
        goto cleanup;
    second_publisher_started = 1;

    rc += expect_int("list two scoped keys", 0,
        test_key_list(names, 8, &count));
    rc += expect_int("same id has two scoped keys", 2, count);
    for (int i = 0; i < count; i++) {
        int valid_name;

        valid_name = strlen(names[i]) == 64;
        for (size_t j = 0; valid_name && j < strlen(names[i]); j++) {
            char byte;

            byte = names[i][j];
            valid_name = (byte >= '0' && byte <= '9') ||
                (byte >= 'a' && byte <= 'f');
        }
        rc += expect_true("scoped filename is bounded hex", valid_name);
        if (test_key_path(names[i], paths[i], sizeof(paths[i])) != 0) {
            rc++;
            continue;
        }
        rc += expect_int("read scoped key", 0,
            test_file_read(paths[i], key_data, sizeof(key_data), &key_len));
        rc += expect_int("scoped key content length", 17, (int)key_len);
        rc += expect_true("scoped key line ending",
            key_len == 17 && key_data[16] == '\n');
#ifndef _WIN32
        rc += expect_int("scoped key stat", 0, stat(paths[i], &status));
        rc += expect_int("scoped key permissions", 0600,
            (int)(status.st_mode & 0777));
#endif
    }

    rc += expect_int("deregister first scoped publisher", REDP2P_OK,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 1U),
            "shared"));
    rc += expect_string("successful deregistration clears detail", "",
        redp2p_get_error(client));
    rc += expect_int("list remaining scoped key", 0,
        test_key_list(names, 8, &count));
    rc += expect_int("successful deregistration deletes one key", 1, count);
    if (count != 1 || test_key_path(names[0], paths[0], sizeof(paths[0])) != 0 ||
        test_file_read(paths[0], key_data, sizeof(key_data), &key_len) != 0)
    {
        rc++;
        goto cleanup;
    }
    test_publisher_stop(&first_publisher);
    first_publisher_started = 0;

    rc += expect_int("write malformed key", 0,
        test_file_write(paths[0], "0123456789abcdeg", 16));
    rc += expect_int("reject malformed key", REDP2P_EPROTO,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 2U),
            "shared"));
    rc += expect_true("malformed key preserved", test_path_exists(paths[0]));
    rc += expect_int("write truncated key", 0,
        test_file_write(paths[0], "01234567", 8));
    rc += expect_int("reject truncated key", REDP2P_EPROTO,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 2U),
            "shared"));
    rc += expect_true("truncated key preserved", test_path_exists(paths[0]));
    rc += expect_int("write extra key", 0,
        test_file_write(paths[0], "0123456789abcdefx", 17));
    rc += expect_int("reject extra key", REDP2P_EPROTO,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 2U),
            "shared"));
    rc += expect_true("extra key preserved", test_path_exists(paths[0]));
    rc += expect_int("restore valid key", 0,
        test_file_write(paths[0], key_data, key_len));

    test_index_stop(&second_index);
    second_index_started = 0;
    rc += expect_int("failed deregistration category", REDP2P_ENET,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 2U),
            "shared"));
    rc += expect_true("failed deregistration preserves key",
        test_path_exists(paths[0]));
    test_publisher_stop(&second_publisher);
    second_publisher_started = 0;
    remove(paths[0]);
#ifndef _WIN32
    rc += expect_int("create key path directory", 0, mkdir(paths[0], 0700));
    rc += expect_int("reject key path directory", REDP2P_ERROR,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 2U),
            "shared"));
    rc += expect_int("remove key path directory", 0, rmdir(paths[0]));
#endif

    if (test_publisher_start(&publisher, "shutdown",
        (unsigned short)(base + 1U), (unsigned short)(base + 5U)) != 0)
        goto cleanup;
    publisher_started = 1;
    rc += expect_int("shutdown key created", 0,
        test_key_list(names, 8, &count));
    rc += expect_int("shutdown key count", 1, count);
    test_publisher_stop(&publisher);
    publisher_started = 0;
    rc += expect_int("shutdown key list", 0,
        test_key_list(names, 8, &count));
    rc += expect_int("successful shutdown deletes scoped key", 0, count);

    if (test_publisher_start(&publisher, "legacy",
        (unsigned short)(base + 1U), (unsigned short)(base + 6U)) != 0)
        goto cleanup;
    publisher_started = 1;
    if (test_key_list(names, 8, &count) != 0 || count != 1 ||
        test_key_path(names[0], paths[0], sizeof(paths[0])) != 0 ||
        test_file_read(paths[0], key_data, sizeof(key_data), &key_len) != 0 ||
        test_key_path("legacy", legacy_path, sizeof(legacy_path)) != 0)
    {
        rc++;
        goto cleanup;
    }
    rc += expect_int("create legacy key", 0,
        test_file_write(legacy_path, key_data, key_len));
    rc += expect_int("remove scoped key for migration", 0, remove(paths[0]));
    rc += expect_int("legacy deregistration", REDP2P_OK,
        redp2p_deregister(client, TEST_HOST, (unsigned short)(base + 1U),
            "legacy"));
    rc += expect_true("successful legacy lookup removes legacy key",
        !test_path_exists(legacy_path));
    test_publisher_stop(&publisher);
    publisher_started = 0;

#ifdef _WIN32
    test_setenv("USERPROFILE", test_home_path);
    test_setenv("HOME", NULL);
    rc += expect_int("missing HOME uses USERPROFILE", REDP2P_ENOENT,
        redp2p_deregister(client, TEST_HOST, base, "absent"));
    test_setenv("HOME", "");
    rc += expect_int("empty HOME uses USERPROFILE", REDP2P_ENOENT,
        redp2p_deregister(client, TEST_HOST, base, "absent"));
#else
    test_setenv("HOME", NULL);
    rc += expect_int("missing HOME category", REDP2P_ERROR,
        redp2p_deregister(client, TEST_HOST, base, "absent"));
    rc += expect_true("missing HOME detail", redp2p_get_error(client)[0] != '\0');
    test_setenv("HOME", "");
    rc += expect_int("empty HOME category", REDP2P_ERROR,
        redp2p_deregister(client, TEST_HOST, base, "absent"));
#endif
    memset(long_home, 'x', sizeof(long_home) - 1);
    long_home[sizeof(long_home) - 1] = '\0';
    test_setenv("HOME", long_home);
    rc += expect_int("overlong HOME category", REDP2P_ERROR,
        redp2p_deregister(client, TEST_HOST, base, "absent"));
    test_setenv("HOME", test_home_path);

    if (snprintf(blocked_home, sizeof(blocked_home), "%s/blocked-home",
        test_home_path) < 0 || strlen(blocked_home) >= sizeof(blocked_home) ||
        test_file_write(blocked_home, "blocked", 7) != 0)
    {
        rc++;
        goto cleanup;
    }
    test_setenv("HOME", blocked_home);
    if (test_publisher_start(&publisher, "nosave",
        (unsigned short)(base + 1U), (unsigned short)(base + 7U)) != 0)
        goto cleanup;
    publisher_started = 1;
    rc += expect_true("unwritable HOME publisher returns",
        test_publisher_wait_result(&publisher, 3000U));
    rc += expect_int("unwritable HOME publication fails", REDP2P_ERROR,
        atomic_load(&publisher.result));
    test_setenv("HOME", test_home_path);
    test_publisher_finish(&publisher);
    publisher_started = 0;
    memset(&publishers, 0, sizeof(publishers));
    rc += expect_int("list after save rollback", REDP2P_OK,
        redp2p_list_publishers(client, TEST_HOST,
            (unsigned short)(base + 1U), test_on_publisher, &publishers));
    rc += expect_true("save failure registration rolled back",
        !test_has_publisher(&publishers, "nosave"));

cleanup:
    test_setenv("HOME", test_home_path);
    if (publisher_started) test_publisher_stop(&publisher);
    if (second_publisher_started) test_publisher_stop(&second_publisher);
    if (first_publisher_started) test_publisher_stop(&first_publisher);
    if (second_index_started) test_index_stop(&second_index);
    if (first_index_started) test_index_stop(&first_index);
    if (client) redp2p_close(client);
#ifndef _WIN32
    umask(old_umask);
#endif
    return rc == 0 ? 0 : 1;
}

/**
 * Tests publisher heartbeat survival past heartbeat interval.
 * Verifies a publisher remains registered well beyond the heartbeat interval
 * (15s) with the default eviction timeout (120s).
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_heartbeat(void) {
    test_index_t index;
    test_publisher_t publisher;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 100U);
    if (test_index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
    if (test_publisher_start(&publisher, "hbping", (unsigned short)(base + 1U),
        (unsigned short)(base + 2U)) != 0) {
        test_index_stop(&index);
        return 1;
    }
    test_sleep_ms(20000U);
    rc += expect_int("publisher survives past heartbeat interval", 0,
        test_http_request((unsigned short)(base + 1U),
            "{\"op\":\"lookup\",\"id\":\"hbping\"}",
            strlen("{\"op\":\"lookup\",\"id\":\"hbping\"}"), 200,
            "\"udp_port\":"));
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_list_publishers.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_list_publishers(void) {
    test_index_t index;
    test_publisher_t publisher;
    test_publisher_t replacement;
    test_publishers_t publishers;
    redp2p_t *client;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 80U);
    rc += expect_int("list NULL ctx", REDP2P_ERROR,
        redp2p_list_publishers(NULL, TEST_HOST, base, test_on_publisher, NULL));
    rc += expect_int("open client", REDP2P_OK, redp2p_open(&client));
    rc += expect_int("list NULL host", REDP2P_ERROR,
        redp2p_list_publishers(client, NULL, base, test_on_publisher, NULL));
    rc += expect_int("list NULL callback", REDP2P_ERROR,
        redp2p_list_publishers(client, TEST_HOST, base, NULL, NULL));
    rc += expect_int("list without index", REDP2P_ENET,
        redp2p_list_publishers(client, TEST_HOST, base, test_on_publisher, NULL));
    redp2p_close(client);
    if (test_index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
#ifndef _WIN32
    if (REDP2P_TEST_CLI[0])
        rc += test_cli_list("empty CLI --list", (unsigned short)(base + 1U),
            "--list", NULL, NULL, 0, "");
#endif
    if (test_publisher_start(&publisher, "listed", (unsigned short)(base + 1U),
        (unsigned short)(base + 2U)) != 0) return 1;
    memset(&publishers, 0, sizeof(publishers));
    rc += expect_int("open client", REDP2P_OK, redp2p_open(&client));
    rc += expect_int("seed stale list detail", REDP2P_EINVAL,
        redp2p_set_protocol(client, 7));
    rc += expect_int("list publishers", REDP2P_OK,
        redp2p_list_publishers(client, TEST_HOST, (unsigned short)(base + 1U),
            test_on_publisher, &publishers));
    rc += expect_true("publisher listed", test_has_publisher(&publishers, "listed"));
    rc += expect_string("successful list clears detail", "",
        redp2p_get_error(client));
    redp2p_close(client);
#ifdef _WIN32
    rc += expect_true("CLI publisher listing skipped on Windows", 1);
#else
    if (!REDP2P_TEST_CLI[0]) {
        printf("[SKIP] CLI publisher listing fixture unavailable\n");
    } else {
        rc += test_cli_list("CLI --list", (unsigned short)(base + 1U),
            "--list", NULL, NULL, 0, "listed\n");
        rc += test_cli_list("CLI -l", (unsigned short)(base + 1U),
            "-l", NULL, NULL, 0, "listed\n");
        rc += test_cli_list("CLI list seats conflict",
            (unsigned short)(base + 1U), "--list", "--seats", "1", 1, "");
        rc += test_cli_list("CLI list pow conflict",
            (unsigned short)(base + 1U), "-l", "--pow", "1", 1, "");
    }
#endif
    test_publisher_stop(&publisher);
    rc += expect_int("start original duplicate publisher", 0,
        test_publisher_start(&publisher, "duplicate",
            (unsigned short)(base + 1U), (unsigned short)(base + 3U)));
    rc += expect_int("start replacement duplicate publisher", 0,
        test_publisher_start(&replacement, "duplicate",
            (unsigned short)(base + 1U), (unsigned short)(base + 4U)));
    rc += expect_true("replacement duplicate remains active",
        atomic_load(&replacement.result) == 999);
    test_publisher_stop(&publisher);
    memset(&publishers, 0, sizeof(publishers));
    rc += expect_int("open duplicate list client", REDP2P_OK,
        redp2p_open(&client));
    rc += expect_int("list after old duplicate disconnect", REDP2P_OK,
        redp2p_list_publishers(client, TEST_HOST,
            (unsigned short)(base + 1U), test_on_publisher, &publishers));
    rc += expect_true("stable key survives duplicate re-registration",
        !test_has_publisher(&publishers, "duplicate"));
    redp2p_close(client);
    test_publisher_stop(&replacement);
    rc += expect_int("lookup after current publisher disconnect", 0,
        test_http_request((unsigned short)(base + 1U),
            "{\"op\":\"lookup\",\"id\":\"duplicate\"}",
            strlen("{\"op\":\"lookup\",\"id\":\"duplicate\"}"), 404,
            "\"error\":\"not_found\""));
    test_index_stop(&index);
#ifndef _WIN32
    if (REDP2P_TEST_CLI[0])
        rc += test_cli_list("unavailable CLI --list",
            (unsigned short)(base + 1U), "--list", NULL, NULL, 1, "");
#endif
    return rc == 0 ? 0 : 1;
}

/**
 * Tests context-owned error detail lifetime and clearing.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_get_error(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_string("NULL ctx empty", "", redp2p_get_error(NULL));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_string("cleared default", "", redp2p_get_error(ctx));
    rc += expect_int("invalid protocol category", REDP2P_EINVAL,
        redp2p_set_protocol(ctx, 7));
    rc += expect_string("captured detail",
        "protocol must be REDP2P_PROTO_TCP or REDP2P_PROTO_UDP",
        redp2p_get_error(ctx));
    rc += expect_int("valid protocol", REDP2P_OK,
        redp2p_set_protocol(ctx, REDP2P_PROTO_TCP));
    rc += expect_string("success clears detail", "", redp2p_get_error(ctx));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_seats.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_seats(void) {
    redp2p_t *ctx;
    int rc;
    size_t max_peer_count;

    rc = 0;
    rc += expect_int("set seats NULL", REDP2P_EINVAL, redp2p_set_seats(NULL, 1));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    max_peer_count = SIZE_MAX / sizeof(redp2p_peer_t);
    rc += expect_int("set zero seats", REDP2P_OK, redp2p_set_seats(ctx, 0));
    rc += expect_int("set seats positive", REDP2P_OK, redp2p_set_seats(ctx, 2));
    rc += expect_int("reject allocation count overflow", REDP2P_EINVAL,
        redp2p_set_seats(ctx, max_peer_count + 1));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_pow.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_pow(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set pow NULL", REDP2P_EINVAL, redp2p_set_pow(NULL, 1));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set pow positive", REDP2P_OK, redp2p_set_pow(ctx, 2));
    rc += expect_int("set pow negative", REDP2P_EINVAL, redp2p_set_pow(ctx, -1));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_port.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_port(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set port NULL", REDP2P_EINVAL, redp2p_set_port(NULL, 1));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set port value", REDP2P_OK, redp2p_set_port(ctx, 12345));
    rc += expect_int("set port zero", REDP2P_EINVAL, redp2p_set_port(ctx, 0));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_protocol.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_protocol(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set protocol NULL", REDP2P_EINVAL,
        redp2p_set_protocol(NULL, REDP2P_PROTO_TCP));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set TCP", REDP2P_OK, redp2p_set_protocol(ctx, REDP2P_PROTO_TCP));
    rc += expect_int("set UDP", REDP2P_OK, redp2p_set_protocol(ctx, REDP2P_PROTO_UDP));
    rc += expect_int("set invalid protocol", REDP2P_EINVAL,
        redp2p_set_protocol(ctx, 99));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_pass.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_pass(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set pass NULL ctx", REDP2P_EINVAL,
        redp2p_set_pass(NULL, "x"));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set pass", REDP2P_OK, redp2p_set_pass(ctx, "secret"));
    rc += expect_int("clear pass", REDP2P_OK, redp2p_set_pass(ctx, ""));
    rc += expect_int("set NULL pass", REDP2P_EINVAL, redp2p_set_pass(ctx, NULL));
    rc += expect_int("set unsafe pass", REDP2P_EINVAL,
        redp2p_set_pass(ctx, "bad`pass"));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_vip.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_vip(void) {
    redp2p_t *ctx;
    char err[128];
    int rc;

    rc = 0;
    rc += expect_int("set vip NULL ctx", REDP2P_ERROR,
        redp2p_set_vip(NULL, "vip pass", err, sizeof(err)));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set vip pair", REDP2P_OK,
        redp2p_set_vip(ctx, "vip pass", err, sizeof(err)));
    rc += expect_int("clear vip NULL", REDP2P_OK,
        redp2p_set_vip(ctx, NULL, err, sizeof(err)));
    rc += expect_int("clear vip empty", REDP2P_OK,
        redp2p_set_vip(ctx, "", err, sizeof(err)));
    rc += expect_int("reject odd vip tokens", REDP2P_ERROR,
        redp2p_set_vip(ctx, "vip", err, sizeof(err)));
    rc += expect_int("reject bad vip id", REDP2P_ERROR,
        redp2p_set_vip(ctx, "bad:id pass", err, sizeof(err)));
    rc += expect_int("reject bad vip pass", REDP2P_ERROR,
        redp2p_set_vip(ctx, "vip bad`pass", err, sizeof(err)));
    rc += expect_int("reject duplicate vip", REDP2P_ERROR,
        redp2p_set_vip(ctx, "vip pass vip other", err, sizeof(err)));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_sweep.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_sweep(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set sweep NULL", REDP2P_EINVAL,
        redp2p_set_sweep(NULL, 1));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set sweep positive", REDP2P_OK, redp2p_set_sweep(ctx, 10));
    rc += expect_int("set sweep zero", REDP2P_OK, redp2p_set_sweep(ctx, 0));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests redp2p_set_stun_url.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_set_stun_url(void) {
    redp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set stun NULL ctx", REDP2P_ERROR,
        redp2p_set_stun_url(NULL, "stun:example.com:3478"));
    rc += expect_int("open context", REDP2P_OK, redp2p_open(&ctx));
    rc += expect_int("set stun", REDP2P_OK,
        redp2p_set_stun_url(ctx, "stun:example.com:3478"));
    rc += expect_int("clear stun", REDP2P_OK, redp2p_set_stun_url(ctx, NULL));
    redp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Verifies that the runner rejects malformed and unknown payloads.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_run_errors(void) {
    const char *payloads[] = {
        NULL,
        "not json",
        "{\"cmd\":\"bogus\",\"args\":{}}",
        "{\"cmd\":\"del\",\"args\":{}}",
        "{\"cmd\":\"del\",\"args\":{\"addr\":\"no-at-sign\"}}",
        "{\"cmd\":\"list\",\"args\":{\"port\":9876}}",
        "{\"cmd\":\"open\",\"args\":{\"op\":\"bogus\",\"port\":9876}}",
        NULL
    };
    int rc;
    int i;

    rc = 0;
    for (i = 0; payloads[i] != NULL; i++) {
        char *err = NULL;
        char *res;

        res = kc_redp2p_run(payloads[i], &err);
        rc += expect_true("run rejects bad payload", res == NULL);
        rc += expect_true("run sets error", err != NULL);
        free(res);
        free(err);
    }
    return rc == 0 ? 0 : 1;
}

/**
 * Opens, polls, and closes a local index through the runner.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_run_idx_lifecycle(void) {
    char payload[256];
    char status[256];
    char *err = NULL;
    char *res;
    int rc;
    int i;

    rc = 0;
    snprintf(payload, sizeof(payload),
        "{\"cmd\":\"open\",\"args\":{\"op\":\"idx\",\"port\":%u}}",
        (unsigned)test_port_base());
    res = kc_redp2p_run(payload, &err);
    rc += expect_true("run open idx returns result", res != NULL);
    rc += expect_true("run open idx clears error", err == NULL);
    free(res);
    free(err);
    err = NULL;

    for (i = 0; i < 20; i++) {
        const char *state;

        snprintf(status, sizeof(status),
            "{\"cmd\":\"status\",\"args\":{\"handle\":1}}");
        res = kc_redp2p_run(status, &err);
        if (res == NULL) {
            free(err);
            err = NULL;
            continue;
        }
        state = strstr(res, "\"state\":\"running\"");
        free(res);
        if (state != NULL) break;
        test_sleep_ms(100);
    }
    rc += expect_true("run idx status running", i < 20);

    res = kc_redp2p_run("{\"cmd\":\"close\",\"args\":{\"handle\":1}}", &err);
    rc += expect_true("run close idx returns result", res != NULL);
    rc += expect_true("run close idx clears error", err == NULL);
    free(res);
    free(err);
    return rc == 0 ? 0 : 1;
}

/**
 * Publishes one runner list request and verifies the exact JSON result.
 * @return 0 on success, 1 on failure.
 */
static int case_redp2p_run_list(void) {
    char payload[256];
    char *err = NULL;
    char *res;
    int rc;

    rc = 0;
    snprintf(payload, sizeof(payload),
        "{\"cmd\":\"open\",\"args\":{\"op\":\"idx\",\"port\":%u}}",
        (unsigned)test_port_base());
    res = kc_redp2p_run(payload, &err);
    rc += expect_true("run list open idx", res != NULL);
    free(res);
    free(err);
    err = NULL;
    test_sleep_ms(300);

    snprintf(payload, sizeof(payload),
        "{\"cmd\":\"list\",\"args\":{\"host\":\"127.0.0.1\",\"port\":%u}}",
        (unsigned)test_port_base());
    res = kc_redp2p_run(payload, &err);
    rc += expect_true("run list returns result", res != NULL);
    rc += expect_true("run list has publishers",
        res != NULL && strstr(res, "\"publishers\"") != NULL);
    free(res);
    free(err);
    err = NULL;

    res = kc_redp2p_run("{\"cmd\":\"close\",\"args\":{\"handle\":1}}", &err);
    rc += expect_true("run list close idx", res != NULL);
    free(res);
    free(err);
    return rc == 0 ? 0 : 1;
}

/**
 * Dispatches one named test case.
 * @param name Public API function name.
 * @return 0 on success, 1 on failure, 2 for an unknown case.
 */
static int run_case(const char *name) {
    if (strcmp(name, "redp2p_options_default") == 0) return case_redp2p_options_default();
    if (strcmp(name, "redp2p_options_load_env") == 0) return case_redp2p_options_load_env();
    if (strcmp(name, "redp2p_options_load_env_invalid") == 0) return case_redp2p_options_load_env_invalid();
    if (strcmp(name, "redp2p_options_free") == 0) return case_redp2p_options_free();
    if (strcmp(name, "redp2p_open") == 0) return case_redp2p_open();
    if (strcmp(name, "redp2p_close") == 0) return case_redp2p_close();
    if (strcmp(name, "redp2p_stop") == 0) return case_redp2p_stop();
    if (strcmp(name, "redp2p_version") == 0) return case_redp2p_version();
    if (strcmp(name, "redp2p_strerror") == 0) return case_redp2p_strerror();
    if (strcmp(name, "redp2p_is_valid_id") == 0) return case_redp2p_is_valid_id();
    if (strcmp(name, "redp2p_is_valid_pass_token") == 0) return case_redp2p_is_valid_pass_token();
    if (strcmp(name, "redp2p_serve_index") == 0) return case_redp2p_serve_index();
    if (strcmp(name, "redp2p_wait") == 0) return case_redp2p_wait();
    if (strcmp(name, "redp2p_connect") == 0) return case_redp2p_connect();
    if (strcmp(name, "redp2p_udp_tunnel") == 0) return case_redp2p_udp_tunnel();
    if (strcmp(name, "redp2p_tcp_stream") == 0) return case_redp2p_tcp_stream();
    if (strcmp(name, "redp2p_deregister") == 0) return case_redp2p_deregister();
    if (strcmp(name, "redp2p_heartbeat") == 0) return case_redp2p_heartbeat();
    if (strcmp(name, "redp2p_list_publishers") == 0) return case_redp2p_list_publishers();
    if (strcmp(name, "redp2p_get_error") == 0) return case_redp2p_get_error();
    if (strcmp(name, "redp2p_set_seats") == 0) return case_redp2p_set_seats();
    if (strcmp(name, "redp2p_set_pow") == 0) return case_redp2p_set_pow();
    if (strcmp(name, "redp2p_set_port") == 0) return case_redp2p_set_port();
    if (strcmp(name, "redp2p_set_protocol") == 0) return case_redp2p_set_protocol();
    if (strcmp(name, "redp2p_set_pass") == 0) return case_redp2p_set_pass();
    if (strcmp(name, "redp2p_set_vip") == 0) return case_redp2p_set_vip();
    if (strcmp(name, "redp2p_set_sweep") == 0) return case_redp2p_set_sweep();
    if (strcmp(name, "redp2p_set_stun_url") == 0) return case_redp2p_set_stun_url();
    if (strcmp(name, "redp2p_run_errors") == 0) return case_redp2p_run_errors();
    if (strcmp(name, "redp2p_run_idx_lifecycle") == 0) return case_redp2p_run_idx_lifecycle();
    if (strcmp(name, "redp2p_run_list") == 0) return case_redp2p_run_list();
    fprintf(stderr, "unknown test case: %s\n", name);
    return 2;
}

/**
 * Runs one public API contract test case.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, non-zero on failure.
 */
int main(int argc, char **argv) {
    int rc;

    if (argc != 2) {
        fprintf(stderr, "expected one test case argument\n");
        return 2;
    }
    test_case_name = argv[1];
    if (test_home() != 0) return 1;
    if (test_socket_start() != 0) {
        test_home_cleanup();
        return 1;
    }
    rc = run_case(argv[1]);
    test_port_base_release();
    test_socket_stop();
    if (test_home_cleanup() != 0 && rc == 0) rc = 1;
    return rc;
}
