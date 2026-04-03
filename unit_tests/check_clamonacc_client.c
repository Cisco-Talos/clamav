/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <check.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "clamav.h"
#include "others.h"
#include "output.h"

#include "../clamonacc/client/client.h"
#include "../clamonacc/client/socket.h"
#include "../clamonacc/clamonacc.h"
#include "../common/clamdcom.h"
#include "../common/optparser.h"

#define TEST_HOST_URL "http://127.0.0.1"
#define TEST_TIMEOUT_MS 5000
#define TEST_MAXSTREAM (1024 * 1024)
#define TEST_THREAD_COUNT 8

enum fake_reply_mode {
    FAKE_REPLY_STREAM_FOUND = 0,
    FAKE_REPLY_ALLMATCH_DOUBLE_FOUND
};

struct fake_server {
    int listen_fd;
    uint16_t port;
    int expected_connections;
    int accepted_connections;
    int ready;
    int reply_mode;
    int first_reply_count;
    int release_second_reply;
    int failed;
    char failure_msg[256];
    pthread_mutex_t lock;
    pthread_cond_t ready_cond;
    pthread_cond_t first_reply_cond;
    pthread_cond_t second_reply_cond;
    pthread_t accept_thread;
    pthread_t client_threads[TEST_THREAD_COUNT];
};

struct fake_connect_server {
    int listen_fd;
    uint16_t port;
    int expected_connections;
    int accepted_connections;
    int ready;
    int failed;
    char failure_msg[256];
    int accepted_fds[TEST_THREAD_COUNT];
    pthread_mutex_t lock;
    pthread_cond_t ready_cond;
    pthread_t accept_thread;
};

struct fake_fdpass_server {
    int listen_fd;
    int expected_connections;
    int accepted_connections;
    int ready;
    int failed;
    char socket_dir[PATH_MAX];
    char socket_path[PATH_MAX];
    char failure_msg[256];
    pthread_mutex_t lock;
    pthread_cond_t ready_cond;
    pthread_t accept_thread;
    pthread_t client_threads[TEST_THREAD_COUNT];
};

struct fake_client_request {
    struct fake_server *server;
    int conn_fd;
    char filename[PATH_MAX];
};

struct fake_fdpass_request {
    struct fake_fdpass_server *server;
    int conn_fd;
};

struct scan_thread_args {
    const char *tcpaddr;
    uint16_t port;
    int scantype;
    int expect_infected;
    char filename[PATH_MAX];
    char temp_file[PATH_MAX];
    int result;
    int infected;
    int err;
    cl_error_t ret_code;
};

static int recv_all(int fd, void *buf, size_t len)
{
    char *cursor = buf;

    while (len > 0) {
        ssize_t bread = recv(fd, cursor, len, 0);
        if (bread <= 0) {
            return -1;
        }

        cursor += bread;
        len -= bread;
    }

    return 0;
}

static void fake_server_set_failure(struct fake_server *server, const char *message)
{
    pthread_mutex_lock(&server->lock);
    if (!server->failed) {
        server->failed = 1;
        strncpy(server->failure_msg, message, sizeof(server->failure_msg) - 1);
        server->failure_msg[sizeof(server->failure_msg) - 1] = '\0';
    }
    pthread_mutex_unlock(&server->lock);
}

static void fake_connect_server_set_failure(struct fake_connect_server *server, const char *message)
{
    pthread_mutex_lock(&server->lock);
    if (!server->failed) {
        server->failed = 1;
        strncpy(server->failure_msg, message, sizeof(server->failure_msg) - 1);
        server->failure_msg[sizeof(server->failure_msg) - 1] = '\0';
    }
    pthread_mutex_unlock(&server->lock);
}

static void fake_fdpass_server_set_failure(struct fake_fdpass_server *server, const char *message)
{
    pthread_mutex_lock(&server->lock);
    if (!server->failed) {
        server->failed = 1;
        strncpy(server->failure_msg, message, sizeof(server->failure_msg) - 1);
        server->failure_msg[sizeof(server->failure_msg) - 1] = '\0';
    }
    pthread_mutex_unlock(&server->lock);
}

static int recv_command(int fd, char *buf, size_t buf_len)
{
    size_t used = 0;

    while (used + 1 < buf_len) {
        ssize_t bread = recv(fd, buf + used, 1, 0);
        if (bread <= 0) {
            return -1;
        }

        if (buf[used] == '\0') {
            return 0;
        }

        used++;
    }

    return -1;
}

static int send_reply_line(int fd, const char *line)
{
    size_t len = strlen(line) + 1;

    if (send(fd, line, len, 0) != (ssize_t)len) {
        return -1;
    }

    return 0;
}

static int recv_fdpass_descriptor(int fd, int *received_fd)
{
    char dummy = '\0';
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char control[CMSG_SPACE(sizeof(int))];
    ssize_t bread;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));

    iov.iov_base       = &dummy;
    iov.iov_len        = sizeof(dummy);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control;
    msg.msg_controllen = sizeof(control);

    bread = recvmsg(fd, &msg, 0);
    if (bread <= 0) {
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if ((NULL == cmsg) ||
        (cmsg->cmsg_level != SOL_SOCKET) ||
        (cmsg->cmsg_type != SCM_RIGHTS) ||
        (cmsg->cmsg_len != CMSG_LEN(sizeof(int)))) {
        return -1;
    }

    memcpy(received_fd, CMSG_DATA(cmsg), sizeof(*received_fd));
    return 0;
}

static int read_fd_payload(int fd, char *buf, size_t buf_len)
{
    ssize_t bytes_read;

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        return -1;
    }

    bytes_read = read(fd, buf, buf_len - 1);
    if (bytes_read < 0) {
        return -1;
    }

    buf[bytes_read] = '\0';
    return 0;
}

static void *fake_client_thread(void *arg)
{
    struct fake_client_request *request = arg;
    struct fake_server *server          = request->server;
    char command[PATH_MAX + 64];
    char reply[PATH_MAX + 64];
    const char *filename;
    uint32_t payload_len;
    uint32_t payload_end;
    int conn_fd;

    conn_fd = request->conn_fd;

    if (recv_command(conn_fd, command, sizeof(command)) != 0) {
        fake_server_set_failure(server, "failed to read command");
        close(conn_fd);
        free(request);
        return NULL;
    }

    if (server->reply_mode == FAKE_REPLY_STREAM_FOUND) {
        if (strcmp(command, "zINSTREAM") != 0) {
            fake_server_set_failure(server, "unexpected stream command");
            close(conn_fd);
            free(request);
            return NULL;
        }

        if (recv_all(conn_fd, &payload_len, sizeof(payload_len)) != 0) {
            fake_server_set_failure(server, "failed to read stream length");
            close(conn_fd);
            free(request);
            return NULL;
        }
        payload_len = ntohl(payload_len);

        if (payload_len > 0) {
            char payload[32];
            size_t chunk = payload_len;

            if (chunk > sizeof(payload)) {
                chunk = sizeof(payload);
            }

            if (recv_all(conn_fd, payload, chunk) != 0) {
                fake_server_set_failure(server, "failed to read stream payload");
                close(conn_fd);
                free(request);
                return NULL;
            }
            if (payload_len > chunk) {
                char discard[256];
                size_t remaining = payload_len - chunk;

                while (remaining > 0) {
                    size_t piece = remaining;
                    if (piece > sizeof(discard)) {
                        piece = sizeof(discard);
                    }
                    if (recv_all(conn_fd, discard, piece) != 0) {
                        fake_server_set_failure(server, "failed to drain stream payload");
                        close(conn_fd);
                        free(request);
                        return NULL;
                    }
                    remaining -= piece;
                }
            }
        }

        if ((recv_all(conn_fd, &payload_end, sizeof(payload_end)) != 0) || (ntohl(payload_end) != 0)) {
            fake_server_set_failure(server, "invalid stream terminator");
            close(conn_fd);
            free(request);
            return NULL;
        }

        snprintf(reply, sizeof(reply), "%s: Fake.Test FOUND", request->filename);
        if (send_reply_line(conn_fd, reply) != 0) {
            fake_server_set_failure(server, "failed to send stream reply");
        }
    } else {
        if (0 != strncmp(command, "zALLMATCHSCAN ", strlen("zALLMATCHSCAN "))) {
            fake_server_set_failure(server, "unexpected allmatch command");
            close(conn_fd);
            free(request);
            return NULL;
        }

        filename = command + strlen("zALLMATCHSCAN ");

        snprintf(reply, sizeof(reply), "%s: Fake.First FOUND", filename);
        if (send_reply_line(conn_fd, reply) != 0) {
            fake_server_set_failure(server, "failed to send first allmatch reply");
            close(conn_fd);
            free(request);
            return NULL;
        }

        pthread_mutex_lock(&server->lock);
        server->first_reply_count++;
        if (server->first_reply_count == server->expected_connections) {
            pthread_cond_broadcast(&server->first_reply_cond);
        }
        while (!server->release_second_reply) {
            pthread_cond_wait(&server->second_reply_cond, &server->lock);
        }
        pthread_mutex_unlock(&server->lock);

        snprintf(reply, sizeof(reply), "%s: Fake.Second FOUND", filename);
        if (send_reply_line(conn_fd, reply) != 0) {
            fake_server_set_failure(server, "failed to send second allmatch reply");
        }
    }

    close(conn_fd);
    free(request);
    return NULL;
}

static void *fake_fdpass_client_thread(void *arg)
{
    struct fake_fdpass_request *request = arg;
    struct fake_fdpass_server *server   = request->server;
    char command[64];
    char payload[128];
    int received_fd = -1;

    if (recv_command(request->conn_fd, command, sizeof(command)) != 0) {
        fake_fdpass_server_set_failure(server, "failed to read fdpass command");
        close(request->conn_fd);
        free(request);
        return NULL;
    }

    if (strcmp(command, "zFILDES") != 0) {
        fake_fdpass_server_set_failure(server, "unexpected fdpass command");
        close(request->conn_fd);
        free(request);
        return NULL;
    }

    if (recv_fdpass_descriptor(request->conn_fd, &received_fd) != 0) {
        fake_fdpass_server_set_failure(server, "failed to receive passed fd");
        close(request->conn_fd);
        free(request);
        return NULL;
    }

    if (read_fd_payload(received_fd, payload, sizeof(payload)) != 0) {
        fake_fdpass_server_set_failure(server, "failed to read passed fd payload");
        close(received_fd);
        close(request->conn_fd);
        free(request);
        return NULL;
    }

    if (strncmp(payload, "fdpass payload ", strlen("fdpass payload ")) != 0) {
        fake_fdpass_server_set_failure(server, "unexpected fdpass payload");
        close(received_fd);
        close(request->conn_fd);
        free(request);
        return NULL;
    }

    if (send_reply_line(request->conn_fd, "fdpass: Fake.FD FOUND") != 0) {
        fake_fdpass_server_set_failure(server, "failed to send fdpass reply");
    }

    close(received_fd);
    close(request->conn_fd);
    free(request);
    return NULL;
}

static void *fake_connect_accept_thread(void *arg)
{
    struct fake_connect_server *server = arg;

    pthread_mutex_lock(&server->lock);
    server->ready = 1;
    pthread_cond_broadcast(&server->ready_cond);
    pthread_mutex_unlock(&server->lock);

    while (server->accepted_connections < server->expected_connections) {
        int conn_fd;

        conn_fd = accept(server->listen_fd, NULL, NULL);
        if (conn_fd == -1) {
            fake_connect_server_set_failure(server, "connect-only accept failed");
            break;
        }

        server->accepted_fds[server->accepted_connections] = conn_fd;
        server->accepted_connections++;
    }

    return NULL;
}

static void *fake_server_accept_thread(void *arg)
{
    struct fake_server *server = arg;

    pthread_mutex_lock(&server->lock);
    server->ready = 1;
    pthread_cond_broadcast(&server->ready_cond);
    pthread_mutex_unlock(&server->lock);

    while (server->accepted_connections < server->expected_connections) {
        struct fake_client_request *request;
        int conn_fd;

        request = calloc(1, sizeof(*request));
        if (NULL == request) {
            fake_server_set_failure(server, "failed to allocate client request");
            break;
        }
        request->server = server;
        snprintf(request->filename, sizeof(request->filename), "thread-%d", server->accepted_connections);

        conn_fd = accept(server->listen_fd, NULL, NULL);
        if (conn_fd == -1) {
            fake_server_set_failure(server, "accept failed");
            free(request);
            break;
        }
        request->conn_fd = conn_fd;

        if (pthread_create(&server->client_threads[server->accepted_connections], NULL, fake_client_thread, request) != 0) {
            fake_server_set_failure(server, "failed to create client thread");
            close(conn_fd);
            free(request);
            break;
        }

        server->accepted_connections++;
    }

    return NULL;
}

static void *fake_fdpass_accept_thread(void *arg)
{
    struct fake_fdpass_server *server = arg;

    pthread_mutex_lock(&server->lock);
    server->ready = 1;
    pthread_cond_broadcast(&server->ready_cond);
    pthread_mutex_unlock(&server->lock);

    while (server->accepted_connections < server->expected_connections) {
        struct fake_fdpass_request *request;
        int conn_fd;

        request = calloc(1, sizeof(*request));
        if (NULL == request) {
            fake_fdpass_server_set_failure(server, "failed to allocate fdpass request");
            break;
        }
        request->server = server;

        conn_fd = accept(server->listen_fd, NULL, NULL);
        if (conn_fd == -1) {
            fake_fdpass_server_set_failure(server, "fdpass accept failed");
            free(request);
            break;
        }
        request->conn_fd = conn_fd;

        if (pthread_create(&server->client_threads[server->accepted_connections], NULL, fake_fdpass_client_thread, request) != 0) {
            fake_fdpass_server_set_failure(server, "failed to create fdpass client thread");
            close(conn_fd);
            free(request);
            break;
        }

        server->accepted_connections++;
    }

    return NULL;
}

static void fake_server_start(struct fake_server *server, int expected_connections, int reply_mode)
{
    struct sockaddr_in addr;
    socklen_t addr_len;
    int enable = 1;

    memset(server, 0, sizeof(*server));
    server->listen_fd            = -1;
    server->expected_connections = expected_connections;
    server->reply_mode           = reply_mode;

    ck_assert_int_eq(pthread_mutex_init(&server->lock, NULL), 0);
    ck_assert_int_eq(pthread_cond_init(&server->ready_cond, NULL), 0);
    ck_assert_int_eq(pthread_cond_init(&server->first_reply_cond, NULL), 0);
    ck_assert_int_eq(pthread_cond_init(&server->second_reply_cond, NULL), 0);

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ne(server->listen_fd, -1);
    ck_assert_int_eq(setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)), 0);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    ck_assert_int_eq(bind(server->listen_fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(listen(server->listen_fd, expected_connections), 0);

    addr_len = sizeof(addr);
    ck_assert_int_eq(getsockname(server->listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    server->port = ntohs(addr.sin_port);

    ck_assert_int_eq(pthread_create(&server->accept_thread, NULL, fake_server_accept_thread, server), 0);

    pthread_mutex_lock(&server->lock);
    while (!server->ready) {
        pthread_cond_wait(&server->ready_cond, &server->lock);
    }
    pthread_mutex_unlock(&server->lock);
}

static void fake_server_release_second_reply(struct fake_server *server)
{
    pthread_mutex_lock(&server->lock);
    while (server->first_reply_count < server->expected_connections) {
        pthread_cond_wait(&server->first_reply_cond, &server->lock);
    }
    server->release_second_reply = 1;
    pthread_cond_broadcast(&server->second_reply_cond);
    pthread_mutex_unlock(&server->lock);
}

static void fake_server_stop(struct fake_server *server)
{
    if (server->listen_fd != -1) {
        close(server->listen_fd);
    }

    pthread_join(server->accept_thread, NULL);
    while (server->accepted_connections > 0) {
        server->accepted_connections--;
        pthread_join(server->client_threads[server->accepted_connections], NULL);
    }
    pthread_cond_destroy(&server->ready_cond);
    pthread_cond_destroy(&server->first_reply_cond);
    pthread_cond_destroy(&server->second_reply_cond);
    pthread_mutex_destroy(&server->lock);
}

static void fake_fdpass_server_start(struct fake_fdpass_server *server, int expected_connections)
{
    struct sockaddr_un addr;
    char *socket_dir;

    memset(server, 0, sizeof(*server));
    server->listen_fd            = -1;
    server->expected_connections = expected_connections;

    ck_assert_ptr_nonnull(strcpy(server->socket_dir, "/tmp/check-clamonacc-client.XXXXXX"));
    socket_dir = mkdtemp(server->socket_dir);
    ck_assert_ptr_nonnull(socket_dir);

    ck_assert_int_eq(pthread_mutex_init(&server->lock, NULL), 0);
    ck_assert_int_eq(pthread_cond_init(&server->ready_cond, NULL), 0);

    server->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ck_assert_int_ne(server->listen_fd, -1);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    ck_assert_uint_lt(strlen(server->socket_dir) + strlen("/clamd.sock"), sizeof(server->socket_path));
    strcpy(server->socket_path, server->socket_dir);
    strcat(server->socket_path, "/clamd.sock");
    ck_assert_uint_lt(strlen(server->socket_path), sizeof(addr.sun_path));
    strncpy(addr.sun_path, server->socket_path, sizeof(addr.sun_path) - 1);

    ck_assert_int_eq(bind(server->listen_fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(listen(server->listen_fd, expected_connections), 0);
    ck_assert_int_eq(pthread_create(&server->accept_thread, NULL, fake_fdpass_accept_thread, server), 0);

    pthread_mutex_lock(&server->lock);
    while (!server->ready) {
        pthread_cond_wait(&server->ready_cond, &server->lock);
    }
    pthread_mutex_unlock(&server->lock);
}

static void fake_fdpass_server_stop(struct fake_fdpass_server *server)
{
    if (server->listen_fd != -1) {
        close(server->listen_fd);
    }

    pthread_join(server->accept_thread, NULL);
    while (server->accepted_connections > 0) {
        server->accepted_connections--;
        pthread_join(server->client_threads[server->accepted_connections], NULL);
    }

    if (server->socket_path[0] != '\0') {
        unlink(server->socket_path);
    }
    if (server->socket_dir[0] != '\0') {
        rmdir(server->socket_dir);
    }

    pthread_cond_destroy(&server->ready_cond);
    pthread_mutex_destroy(&server->lock);
}

static void fake_connect_server_start(struct fake_connect_server *server, int expected_connections)
{
    struct sockaddr_in addr;
    socklen_t addr_len;
    int enable = 1;

    memset(server, 0, sizeof(*server));
    server->listen_fd            = -1;
    server->expected_connections = expected_connections;

    ck_assert_int_eq(pthread_mutex_init(&server->lock, NULL), 0);
    ck_assert_int_eq(pthread_cond_init(&server->ready_cond, NULL), 0);

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ne(server->listen_fd, -1);
    ck_assert_int_eq(setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)), 0);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    ck_assert_int_eq(bind(server->listen_fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    ck_assert_int_eq(listen(server->listen_fd, expected_connections), 0);

    addr_len = sizeof(addr);
    ck_assert_int_eq(getsockname(server->listen_fd, (struct sockaddr *)&addr, &addr_len), 0);
    server->port = ntohs(addr.sin_port);

    ck_assert_int_eq(pthread_create(&server->accept_thread, NULL, fake_connect_accept_thread, server), 0);

    pthread_mutex_lock(&server->lock);
    while (!server->ready) {
        pthread_cond_wait(&server->ready_cond, &server->lock);
    }
    pthread_mutex_unlock(&server->lock);
}

static void fake_connect_server_stop(struct fake_connect_server *server)
{
    int i;

    if (server->listen_fd != -1) {
        close(server->listen_fd);
    }

    pthread_join(server->accept_thread, NULL);
    for (i = 0; i < server->accepted_connections; i++) {
        close(server->accepted_fds[i]);
    }
    pthread_cond_destroy(&server->ready_cond);
    pthread_mutex_destroy(&server->lock);
}

static struct optstruct *add_test_option(struct optstruct *opts, int toolmask, const char *name, const char *arg)
{
    struct optstruct *new_opts;

    new_opts = optadditem(name, arg, 0, toolmask, 0, opts);
    ck_assert_ptr_nonnull(new_opts);
    return new_opts;
}

static void setup_fdpass_context(struct onas_context *ctx, const char *socket_path)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->opts = add_test_option(NULL, OPT_CLAMONACC, "fdpass", "yes");
    ctx->clamdopts = add_test_option(NULL, OPT_CLAMD, "LocalSocket", socket_path);

    ck_assert_int_eq(onas_set_sock_only_once(ctx), CL_SUCCESS);
}

static void cleanup_fdpass_context(struct onas_context *ctx)
{
    optfree((struct optstruct *)ctx->opts);
    optfree((struct optstruct *)ctx->clamdopts);
}

static void *run_scan_thread(void *arg)
{
    struct scan_thread_args *scan = arg;
    struct stat sb;
    char url[64];
    int fd = -1;

    memset(&sb, 0, sizeof(sb));
    if ((scan->scantype == STREAM) || (scan->scantype == FILDES)) {
        fd = open(scan->temp_file, O_RDONLY);
        ck_assert_int_ne(fd, -1);
        ck_assert_int_eq(fstat(fd, &sb), 0);
    } else {
        sb.st_mode = S_IFREG;
    }

    snprintf(url, sizeof(url), "%s", scan->tcpaddr ? scan->tcpaddr : TEST_HOST_URL);
    scan->result = onas_client_scan(url, scan->port, scan->scantype, TEST_MAXSTREAM, scan->filename,
                                    fd, TEST_TIMEOUT_MS, sb, &scan->infected, &scan->err, &scan->ret_code);

    if (fd != -1) {
        close(fd);
    }

    return NULL;
}

START_TEST(test_onas_client_scan_stream_concurrent)
{
    struct fake_server server;
    struct scan_thread_args scans[TEST_THREAD_COUNT];
    pthread_t threads[TEST_THREAD_COUNT];
    int i;

    fake_server_start(&server, TEST_THREAD_COUNT, FAKE_REPLY_STREAM_FOUND);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        FILE *tmp;

        memset(&scans[i], 0, sizeof(scans[i]));
        scans[i].tcpaddr = TEST_HOST_URL;
        scans[i].port = server.port;
        scans[i].scantype = STREAM;
        scans[i].expect_infected = 1;
        snprintf(scans[i].filename, sizeof(scans[i].filename), "stream-%d", i);
        snprintf(scans[i].temp_file, sizeof(scans[i].temp_file), "tmp.stream.%d", i);

        tmp = fopen(scans[i].temp_file, "w");
        ck_assert_ptr_nonnull(tmp);
        ck_assert_int_eq(fputs("stream payload\n", tmp) >= 0, 1);
        fclose(tmp);

        ck_assert_int_eq(pthread_create(&threads[i], NULL, run_scan_thread, &scans[i]), 0);
    }

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        ck_assert_int_eq(scans[i].infected, scans[i].expect_infected);
        ck_assert_int_eq(scans[i].result, CL_VIRUS);
        unlink(scans[i].temp_file);
    }

    fake_server_stop(&server);
    ck_assert_msg(!server.failed, "%s", server.failure_msg);
}
END_TEST

START_TEST(test_onas_client_scan_allmatch_concurrent)
{
    struct fake_server server;
    struct scan_thread_args scans[TEST_THREAD_COUNT];
    pthread_t threads[TEST_THREAD_COUNT];
    int i;

    fake_server_start(&server, TEST_THREAD_COUNT, FAKE_REPLY_ALLMATCH_DOUBLE_FOUND);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        memset(&scans[i], 0, sizeof(scans[i]));
        scans[i].tcpaddr = TEST_HOST_URL;
        scans[i].port = server.port;
        scans[i].scantype = ALLMATCH;
        scans[i].expect_infected = 1;
        snprintf(scans[i].filename, sizeof(scans[i].filename), "thread-%d", i);

        ck_assert_int_eq(pthread_create(&threads[i], NULL, run_scan_thread, &scans[i]), 0);
    }

    fake_server_release_second_reply(&server);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        ck_assert_int_eq(scans[i].infected, scans[i].expect_infected);
        ck_assert_int_eq(scans[i].result, CL_VIRUS);
    }

    fake_server_stop(&server);
    ck_assert_msg(!server.failed, "%s", server.failure_msg);
}
END_TEST

START_TEST(test_onas_client_scan_fdpass_concurrent)
{
#ifdef HAVE_FD_PASSING
    struct fake_connect_server connect_server;
    struct fake_fdpass_server server;
    struct onas_context ctx;
    struct scan_thread_args scans[TEST_THREAD_COUNT];
    pthread_t threads[TEST_THREAD_COUNT];
    int i;

    fake_connect_server_start(&connect_server, TEST_THREAD_COUNT);
    fake_fdpass_server_start(&server, TEST_THREAD_COUNT);
    setup_fdpass_context(&ctx, server.socket_path);

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        FILE *tmp;

        memset(&scans[i], 0, sizeof(scans[i]));
        scans[i].tcpaddr = TEST_HOST_URL;
        scans[i].port = connect_server.port;
        scans[i].scantype = FILDES;
        scans[i].expect_infected = 1;
        snprintf(scans[i].filename, sizeof(scans[i].filename), "fdpass-%d", i);
        snprintf(scans[i].temp_file, sizeof(scans[i].temp_file), "tmp.fdpass.%d", i);

        tmp = fopen(scans[i].temp_file, "w");
        ck_assert_ptr_nonnull(tmp);
        ck_assert_int_eq(fprintf(tmp, "fdpass payload %d\n", i) >= 0, 1);
        fclose(tmp);

        ck_assert_int_eq(pthread_create(&threads[i], NULL, run_scan_thread, &scans[i]), 0);
    }

    for (i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        ck_assert_int_eq(scans[i].infected, scans[i].expect_infected);
        ck_assert_int_eq(scans[i].result, CL_VIRUS);
        unlink(scans[i].temp_file);
    }

    fake_connect_server_stop(&connect_server);
    fake_fdpass_server_stop(&server);
    cleanup_fdpass_context(&ctx);
    ck_assert_msg(!connect_server.failed, "%s", connect_server.failure_msg);
    ck_assert_msg(!server.failed, "%s", server.failure_msg);
#endif
}
END_TEST

Suite *clamonacc_client_suite(void)
{
    Suite *suite;
    TCase *testcase;

    suite = suite_create("clamonacc_client");
    testcase = tcase_create("client");

    tcase_add_test(testcase, test_onas_client_scan_stream_concurrent);
    tcase_add_test(testcase, test_onas_client_scan_allmatch_concurrent);
    tcase_add_test(testcase, test_onas_client_scan_fdpass_concurrent);
    suite_add_tcase(suite, testcase);

    return suite;
}

int main(void)
{
    Suite *suite;
    SRunner *runner;
    int failed;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    suite = clamonacc_client_suite();
    runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);
    failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    curl_global_cleanup();

    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
