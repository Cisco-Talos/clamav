/*
 *  Unit tests for clamd.
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <sys/stat.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <check.h>

// libclamav
#include "clamav.h"
#include "platform.h"
#include "version.h"
#include "str.h"

// common
#include "fdpassing.h"

static int conn_tcp(int port)
{
    struct sockaddr_in server;
    int rc;
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_msg(sd != -1, "Unable to create socket: %s\n", strerror(errno));

    memset(&server, 0, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_port        = htons(port);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    rc = connect(sd, (struct sockaddr *)&server, (socklen_t)sizeof(server));
    ck_assert_msg(rc != -1, "Unable to connect(): %s\n", strerror(errno));
    return sd;
}

static int sockd;
#ifndef _WIN32
#define SOCKET "clamd-test.socket"
static void conn_setup_mayfail(int may)
{
    int rc;
    struct sockaddr_un nixsock;
    memset((void *)&nixsock, 0, sizeof(nixsock));
    nixsock.sun_family = AF_UNIX;
    strncpy(nixsock.sun_path, SOCKET, sizeof(nixsock.sun_path));

    sockd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockd == -1 && (may && (errno == EMFILE || errno == ENFILE)))
        return;
    ck_assert_msg(sockd != -1, "Unable to create socket: %s\n", strerror(errno));

    rc = connect(sockd, (struct sockaddr *)&nixsock, (socklen_t)sizeof(nixsock));
    if (rc == -1 && (may && (errno == ECONNREFUSED))) {
        close(sockd);
        sockd = -1;
        return;
    }
    ck_assert_msg(rc != -1, "Unable to connect(): %s: %s\n", strerror(errno), SOCKET);

    signal(SIGPIPE, SIG_IGN);
}
#else
#define PORT 3319
static void conn_setup_mayfail(int may)
{
    sockd = conn_tcp(PORT);
    if (sockd == -1 && (may && (errno == ECONNREFUSED)))
        return;
    ck_assert_msg(sockd != -1, "Unable to connect(): %s\n", strerror(errno));
}
#endif

static void conn_setup(void)
{
    conn_setup_mayfail(0);
}

static void conn_teardown(void)
{
    if (sockd != -1)
#ifndef _WIN32
        close(sockd);
#else
        closesocket(sockd);
#endif
}

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

#define SCANFILE OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam.exe"
#define FOUNDREPLY "clam.exe: ClamAV-Test-File.UNOFFICIAL FOUND"

/* some clean file */
#define CLEANFILE SRCDIR PATHSEP "CMakeLists.txt"
#define CLEANREPLY CLEANFILE ": OK"
#define UNKNOWN_REPLY "UNKNOWN COMMAND"

#define NONEXISTENT PATHSEP "nonexistentfilename"

#define NONEXISTENT_REPLY NONEXISTENT ": File path check failure: No such file or directory. ERROR"

static int isroot = 0;

static void commands_setup(void)
{
#ifndef _WIN32
    const char *nonempty = "NONEMPTYFILE";
#endif

    /*
     * Verify that our NONEXISTENT filepath indeed does not exist.
     */
    int fd = open(NONEXISTENT, O_RDONLY | O_BINARY);
    if (fd != -1) close(fd);
    ck_assert_msg(fd == -1, "Nonexistent file exists!\n");

#ifndef _WIN32
    /* Prepare the "isroot" global so we can skip some tests when run as root */
    if (!geteuid()) {
        isroot = 1;
    }
#endif
}

static void commands_teardown(void)
{
}

#define VERSION_REPLY "ClamAV " REPO_VERSION "" VERSION_SUFFIX

#define VCMDS_REPLY VERSION_REPLY "| COMMANDS: SCAN QUIT RELOAD PING CONTSCAN VERSIONCOMMANDS VERSION END SHUTDOWN MULTISCAN FILDES STATS IDSESSION INSTREAM DETSTATSCLEAR DETSTATS ALLMATCHSCAN"

enum idsession_support {
    IDS_OK, /* accepted */
    IDS_REJECT,
    /* after sending this message, clamd will reply,  then accept
     * no further commands, but still reply to all active commands */
    IDS_END /* the END command */
};

static struct basic_test {
    const char *command;
    const char *extra;
    const char *reply;
    int support_old;
    int skiproot;
    enum idsession_support ids;
} basic_tests[] = {
    {"PING", NULL, "PONG", 1, 0, IDS_OK},
    {"RELOAD", NULL, "RELOADING", 1, 0, IDS_REJECT},
    {"VERSION", NULL, VERSION_REPLY, 1, 0, IDS_OK},
    {"VERSIONCOMMANDS", NULL, VCMDS_REPLY, 0, 0, IDS_REJECT},
    {"SCAN " SCANFILE, NULL, FOUNDREPLY, 1, 0, IDS_OK},
    {"SCAN " CLEANFILE, NULL, CLEANREPLY, 1, 0, IDS_OK},
    {"CONTSCAN " SCANFILE, NULL, FOUNDREPLY, 1, 0, IDS_REJECT},
    {"CONTSCAN " CLEANFILE, NULL, CLEANREPLY, 1, 0, IDS_REJECT},
    {"MULTISCAN " SCANFILE, NULL, FOUNDREPLY, 1, 0, IDS_REJECT},
    {"MULTISCAN " CLEANFILE, NULL, CLEANREPLY, 1, 0, IDS_REJECT},
    /* unknown commands */
    {"RANDOM", NULL, UNKNOWN_REPLY, 1, 0, IDS_REJECT},
    /* commands invalid as first */
    {"END", NULL, UNKNOWN_REPLY, 1, 0, IDS_END},
    /* commands for nonexistent files */
    {"SCAN " NONEXISTENT, NULL, NONEXISTENT_REPLY, 1, 0, IDS_OK},
    {"CONTSCAN " NONEXISTENT, NULL, NONEXISTENT_REPLY, 1, 0, IDS_REJECT},
    {"MULTISCAN " NONEXISTENT, NULL, NONEXISTENT_REPLY, 1, 0, IDS_REJECT},
    /* commands with invalid/missing arguments */
    {"SCAN", NULL, UNKNOWN_REPLY, 1, 0, IDS_REJECT},
    {"CONTSCAN", NULL, UNKNOWN_REPLY, 1, 0, IDS_REJECT},
    {"MULTISCAN", NULL, UNKNOWN_REPLY, 1, 0, IDS_REJECT},
    /* commands with invalid data */
    {"INSTREAM", "\xff\xff\xff\xff", "INSTREAM size limit exceeded. ERROR", 0, 0, IDS_REJECT}, /* too big chunksize */
    {"FILDES", "X", "No file descriptor received. ERROR", 1, 0, IDS_REJECT},                   /* FILDES w/o ancillary data */
};

static void *recvpartial(int sd, size_t *len, int partial)
{
    char *buf       = NULL;
    size_t buf_size = 0;
    size_t off      = 0;
    ssize_t bread;

    *len = 0;

    do {
        if (off + BUFSIZ > buf_size) {
            buf_size += BUFSIZ + 1;
            buf = realloc(buf, buf_size);
            ck_assert_msg(!!buf, "Cannot realloc buffer\n");
        }
        bread = recv(sd, buf + off, BUFSIZ, 0);
        ck_assert_msg(bread != -1, "recv() failed: %s\n", strerror(errno));

        off += bread;
    } while (bread && (!partial || !memchr(buf, '\0', off)));

    // Make sure the response buffer is NULL terminated.
    // But note that off-1 will likely be a '\n' newline character, and we don't want to overwrite that.
    buf[MIN(off, buf_size - 1)] = '\0';

    *len = off;
    return buf;
}

static void *recvfull(int sd, size_t *len)
{
    return recvpartial(sd, len, 0);
}

static void test_command(const char *cmd, size_t len, const char *extra, const char *expect, size_t expect_len)
{
    char *recvdata;
    ssize_t rc;
    char *expected_string_offset = NULL;

    rc = send(sockd, cmd, len, 0);
    ck_assert_msg((size_t)rc == len, "Unable to send(): %s\n", strerror(errno));

    if (extra) {
        rc = send(sockd, extra, strlen(extra), 0);
        ck_assert_msg((size_t)rc == strlen(extra), "Unable to send() extra for %s: %s\n", cmd, strerror(errno));
    }
#ifdef _WIN32
    shutdown(sockd, SD_SEND);
#else
    shutdown(sockd, SHUT_WR);
#endif
    recvdata = (char *)recvfull(sockd, &len);

    // The path which comes back may be an absolute real path, not a relative path with symlinks ...
    // ... so this length check isn't really meaningful anymore.
    // For the same reasons, we can't expect the path to match exactly, so we'll
    // just make sure expect is found in recvdata and use the basename instead of the full path.
    expected_string_offset = CLI_STRNSTR(recvdata, expect, len);
    ck_assert_msg(expected_string_offset != NULL, "Wrong reply for command %s.\nReceived: \n%s\nExpected: \n%s\n", cmd, recvdata, expect);
    free(recvdata);
}

START_TEST(test_basic_commands)
{
    struct basic_test *test = &basic_tests[_i];
    char nsend[BUFSIZ], nreply[BUFSIZ];

    if (test->skiproot && isroot)
        return;
    /* send nCOMMAND */
    snprintf(nreply, sizeof(nreply), "%s\n", test->reply);
    snprintf(nsend, sizeof(nsend), "n%s\n", test->command);
    conn_setup();
    test_command(nsend, strlen(nsend), test->extra, nreply, strlen(nreply));
    conn_teardown();

    /* send zCOMMAND */
    snprintf(nsend, sizeof(nsend), "z%s", test->command);
    conn_setup();
    test_command(nsend, strlen(nsend) + 1, test->extra, test->reply, strlen(test->reply) + 1);
    conn_teardown();
}
END_TEST

START_TEST(test_compat_commands)
{
    /* test sending the command the "old way" */
    struct basic_test *test = &basic_tests[_i];
    char nsend[BUFSIZ], nreply[BUFSIZ];

    if (test->skiproot && isroot)
        return;

    if (!test->support_old) {
        snprintf(nreply, sizeof(nreply), "UNKNOWN COMMAND\n");
        test->extra = NULL;
    } else {
        snprintf(nreply, sizeof(nreply), "%s\n", test->reply);
    }
    /* one command = one packet, no delimiter */
    if (!test->extra) {
        conn_setup();
        test_command(test->command, strlen(test->command), test->extra, nreply, strlen(nreply));
        conn_teardown();
    }

    /* one packet, \n delimited command, followed by "extra" if needed */
    snprintf(nsend, sizeof(nsend), "%s\n", test->command);
    conn_setup();
    test_command(nsend, strlen(nsend), test->extra, nreply, strlen(nreply));
    conn_teardown();

    if (!test->extra) {
        /* FILDES won't support this, because it expects
         * strlen("FILDES\n") characters, then 1 character and the FD. */
        /* one packet, \r\n delimited command, followed by "extra" if needed */
        snprintf(nsend, sizeof(nsend), "%s\r\n", test->command);
        conn_setup();
        test_command(nsend, strlen(nsend), test->extra, nreply, strlen(nreply));
        conn_teardown();
    }
}
END_TEST

#define EXPECT_INSTREAM "stream: ClamAV-Test-File.UNOFFICIAL FOUND\n"
#define EXPECT_INSTREAM0 "stream: ClamAV-Test-File.UNOFFICIAL FOUND"

#define STATS_REPLY "POOLS: 1\n\nSTATE: VALID PRIMARY\n"
START_TEST(test_stats)
{
    char *recvdata;
    size_t len = strlen("nSTATS\n");
    int rc;

    conn_setup();
    rc = send(sockd, "nSTATS\n", len, 0);
    ck_assert_msg((size_t)rc == len, "Unable to send(): %s\n", strerror(errno));

    recvdata = (char *)recvfull(sockd, &len);

    ck_assert_msg(len > strlen(STATS_REPLY), "Reply has wrong size: %lu, minimum %lu, reply: %s\n",
                  len, strlen(STATS_REPLY), recvdata);

    if (len > strlen(STATS_REPLY))
        len = strlen(STATS_REPLY);
    rc = strncmp(recvdata, STATS_REPLY, len);

    ck_assert_msg(rc == 0, "Wrong reply: %s\n", recvdata);
    free(recvdata);
    conn_teardown();
}
END_TEST

static size_t prepare_instream(char *buf, size_t off, size_t buflen)
{
    STATBUF stbuf;
    int fd, nread;
    uint32_t chunk;
    ck_assert_msg(CLAMSTAT(SCANFILE, &stbuf) != -1, "stat failed for %s: %s", SCANFILE, strerror(errno));

    fd = open(SCANFILE, O_RDONLY | O_BINARY);
    ck_assert_msg(fd != -1, "open failed: %s\n", strerror(errno));

    chunk = htonl(stbuf.st_size);
    memcpy(&buf[off], &chunk, sizeof(chunk));
    off += 4;
    nread = read(fd, &buf[off], buflen - off - 4);
    ck_assert_msg(nread == stbuf.st_size, "read failed: %d != " STDi64 ", %s\n", nread, (int64_t)stbuf.st_size, strerror(errno));
    off += nread;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    close(fd);
    return off;
}

START_TEST(test_instream)
{
    char *recvdata;
    size_t len, expect_len;
    char buf[4096] = "nINSTREAM\n";
    size_t off     = strlen(buf);
    int rc;

    off = prepare_instream(buf, off, sizeof(buf));

    conn_setup();
    ck_assert_msg((size_t)send(sockd, buf, off, 0) == off, "send() failed: %s\n", strerror(errno));

    recvdata = (char *)recvfull(sockd, &len);

    expect_len = strlen(EXPECT_INSTREAM);
    ck_assert_msg(len == expect_len, "Reply has wrong size: %lu, expected %lu, reply: %s\n",
                  len, expect_len, recvdata);

    rc = memcmp(recvdata, EXPECT_INSTREAM, expect_len);
    ck_assert_msg(!rc, "Wrong reply for command INSTREAM:\nReceived: \n%s\nExpected: \n%s\n", recvdata, EXPECT_INSTREAM);
    free(recvdata);

    conn_teardown();
}
END_TEST

#ifndef _WIN32
static int sendmsg_fd(int sockd, const char *mesg, size_t msg_len, int fd, int singlemsg)
{
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[BUFSIZ];
    struct iovec iov[1];
    int rc;

    if (!singlemsg) {
        /* send FILDES\n and then a single character + ancillary data */
        dummy[0]        = '\0';
        iov[0].iov_base = dummy;
        iov[0].iov_len  = 1;
    } else {
        /* send single message with ancillary data */
        ck_assert_msg(msg_len < sizeof(dummy) - 1, "message too large");
        memcpy(dummy, mesg, msg_len);
        dummy[msg_len]  = '\0';
        iov[0].iov_base = dummy;
        iov[0].iov_len  = msg_len + 1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_control    = fdbuf;
    msg.msg_iov        = iov;
    msg.msg_iovlen     = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    cmsg                    = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len          = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level        = SOL_SOCKET;
    cmsg->cmsg_type         = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;

    if (!singlemsg) {
        rc = send(sockd, mesg, msg_len, 0);
        if (rc == -1)
            return rc;
    }

    return sendmsg(sockd, &msg, 0);
}

static void tst_fildes(const char *cmd, size_t len, int fd,
                       const char *expect, size_t expect_len, int closefd, int singlemsg)
{
    char *recvdata, *p;
    int rc;

    conn_setup();
    ck_assert_msg(sendmsg_fd(sockd, cmd, len, fd, singlemsg) != -1,
                  "Failed to sendmsg: %s\n", strerror(errno));

    if (closefd)
        close(fd);

    recvdata = (char *)recvfull(sockd, &len);
    p        = strchr(recvdata, ':');

    ck_assert_msg(!!p, "Reply doesn't contain ':' : %s\n", recvdata);
    *p++ = '\0';

    ck_assert_msg(sscanf(recvdata, "fd[%u]", &rc) == 1, "Reply doesn't contain fd: %s\n", recvdata);

    len -= p - recvdata;
    ck_assert_msg(len == expect_len, "Reply has wrong size: %lu, expected %lu, reply: %s, expected: %s\n",
                  len, expect_len, p, expect);

    rc = memcmp(p, expect, expect_len);
    ck_assert_msg(!rc, "Wrong reply for command %s:\nReceived: \n%s\nExpected: \n%s\n", cmd, p, expect);
    free(recvdata);
    conn_teardown();
}

#define FOUNDFDREPLY " ClamAV-Test-File.UNOFFICIAL FOUND"
#define CLEANFDREPLY " OK"

static struct cmds {
    const char *cmd;
    const char term;
    const char *file;
    const char *reply;
} fildes_cmds[] =
    {
        {"FILDES", '\n', SCANFILE, FOUNDFDREPLY},
        {"nFILDES", '\n', SCANFILE, FOUNDFDREPLY},
        {"zFILDES", '\0', SCANFILE, FOUNDFDREPLY},
        {"FILDES", '\n', CLEANFILE, CLEANFDREPLY},
        {"nFILDES", '\n', CLEANFILE, CLEANFDREPLY},
        {"zFILDES", '\0', CLEANFILE, CLEANFDREPLY}};

START_TEST(test_fildes)
{
    char nreply[BUFSIZ], nsend[BUFSIZ];
    int fd;
    int closefd   = 0;
    int singlemsg = 0;
    const struct cmds *cmd;
    size_t nreply_len, nsend_len;

    switch (_i & 3) {
        case 0:
            closefd   = 0;
            singlemsg = 0;
            break;
        case 1:
            closefd   = 1;
            singlemsg = 0;
            break;
        case 2:
            closefd   = 0;
            singlemsg = 1;
            break;
        case 3:
            closefd   = 1;
            singlemsg = 1;
            break;
    }

    cmd        = &fildes_cmds[_i / 4];
    nreply_len = snprintf(nreply, sizeof(nreply), "%s%c", cmd->reply, cmd->term);
    nsend_len  = snprintf(nsend, sizeof(nsend), "%s%c", cmd->cmd, cmd->term);

    fd = open(cmd->file, O_RDONLY);
    ck_assert_msg(fd != -1, "Failed to open: %s\n", strerror(errno));

    tst_fildes(nsend, nsend_len, fd, nreply, nreply_len, closefd, singlemsg);

    if (!closefd) {
        /* closefd:
         *  1 - close fd right after sending
         *  0 - close fd after receiving reply */
        close(fd);
    }
}
END_TEST

START_TEST(test_fildes_many)
{
    const char idsession[] = "zIDSESSION";
    const char fildes[]    = "zFILDES";
    const char end[]       = "zEND";
    const char ping[]      = "zPING";

    int dummyfd, i, killed = 0;
    conn_setup();
    dummyfd = open(SCANFILE, O_RDONLY);
    ck_assert_msg(dummyfd != -1, "failed to open %s: %s\n", SCANFILE, strerror(errno));

    ck_assert_msg(send(sockd, idsession, sizeof(idsession), 0) == sizeof(idsession), "send IDSESSION failed\n");
    for (i = 0; i < 1024; i++) {
        if (sendmsg_fd(sockd, fildes, sizeof(fildes), dummyfd, 1) == -1) {
            killed = 1;
            break;
        }
    }
    close(dummyfd);
    if (send(sockd, end, sizeof(end), 0) == -1) {
        killed = 1;
    }
    conn_teardown();

    conn_setup();
    test_command(ping, sizeof(ping), NULL, "PONG", 5);
    conn_teardown();
}
END_TEST

START_TEST(test_fildes_unwanted)
{
    char *recvdata;
    size_t len;
    int dummyfd;
    const char idsession[] = "zIDSESSION";
    conn_setup();
    dummyfd = open(SCANFILE, O_RDONLY);

    /* send a 'zVERSION\0' including the ancillary data.
     * The \0 is from the extra char needed when sending ancillary data */
    ck_assert_msg(sendmsg_fd(sockd, idsession, sizeof(idsession), dummyfd, 1) != -1,
                  "sendmsg failed: %s\n", strerror(errno));

    recvdata = (char *)recvfull(sockd, &len);

    ck_assert_msg(!strcmp(recvdata, "1: PROTOCOL ERROR: ancillary data sent without FILDES. ERROR"),
                  "Wrong reply: %s\n", recvdata);

    free(recvdata);
    close(dummyfd);
    conn_teardown();
}
END_TEST
#endif

START_TEST(test_idsession_stress)
{
    char buf[BUFSIZ];
    size_t i;
    char *data, *p;
    size_t len;
    const char idsession[] = "zIDSESSION";
    const char version[]   = "zVERSION";

    conn_setup();

    ck_assert_msg(send(sockd, idsession, sizeof(idsession), 0) == sizeof(idsession),
                  "send() failed: %s\n", strerror(errno));
    for (i = 0; i < 1024; i++) {
        snprintf(buf, sizeof(buf), "%u", (unsigned)(i + 1));
        ck_assert_msg(send(sockd, version, sizeof(version), 0) == sizeof(version),
                      "send failed: %s\n", strerror(errno));
        data = recvpartial(sockd, &len, 1);
        p    = strchr(data, ':');
        ck_assert_msg(!!p, "wrong VERSION reply (%zu): %s\n", i, data);
        *p++ = '\0';
        ck_assert_msg(*p == ' ', "wrong VERSION reply (%zu): %s\n", i, p);
        *p++ = '\0';

        ck_assert_msg(!strcmp(p, VERSION_REPLY), "wrong VERSION reply: %s\n", data);
        ck_assert_msg(!strcmp(data, buf), "wrong IDSESSION id: %s\n", data);

        free(data);
    }

    conn_teardown();
}
END_TEST

#define TIMEOUT_REPLY "TIMED OUT WAITING FOR COMMAND\n"

#ifndef _WIN32
/*
 * Test that we can still interact with clamd when it has a lot of active connections.
 *
 * Porting this test to work on Windows is too tedious at present.
 * I suspect it should be rewritten using threads. For now, skip on Windows.
 */
START_TEST(test_connections)
{
    int rc;
    int i;
    struct rlimit rlim;
    int *sock;
    int num_fds, maxfd = 0;
    ck_assert_msg(getrlimit(RLIMIT_NOFILE, &rlim) != -1,
                  "Failed to get RLIMIT_NOFILE: %s\n", strerror(errno));

    num_fds = MIN(rlim.rlim_cur - 5, 250);

    sock = malloc(sizeof(int) * num_fds);
    memset(sock, -1, sizeof(int) * num_fds);

    ck_assert_msg(!!sock, "malloc failed\n");

    for (i = 0; i < num_fds; i++) {
        /* just open connections, and let them time out */
        conn_setup_mayfail(1);
        if (sockd == -1) {
            /* close the previous one, to leave space for one more connection */
            i--;
            if (sock[i] > 0) {
                close(sock[i]);
                sock[i] = -1;
            }

            num_fds = i;
            break;
        }
        sock[i] = sockd;
        if (sockd > maxfd)
            maxfd = sockd;
    }

    rc = fork();
    ck_assert_msg(rc != -1, "fork() failed: %s\n", strerror(errno));
    if (rc == 0) {
        /* Child */
        char dummy;
        int ret;
        fd_set rfds;
        FD_ZERO(&rfds);
        for (i = 0; i < num_fds; i++) {
            FD_SET(sock[i], &rfds);
        }
        while (1) {
            ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
            if (ret < 0)
                break;
            for (i = 0; i < num_fds; i++) {
                if (FD_ISSET(sock[i], &rfds)) {
                    if (recv(sock[i], &dummy, 1, 0) == 0) {
                        close(sock[i]);
                        FD_CLR(sock[i], &rfds);
                    }
                }
            }
        }
        free(sock);
        exit(0);
    } else {
        /* Parent */
        for (i = 0; i < num_fds; i++) {
            close(sock[i]);
        }
        free(sock);
        /* now see if clamd is able to do anything else */
        for (i = 0; i < 10; i++) {
            conn_setup();
            test_command("RELOAD", sizeof("RELOAD") - 1, NULL, "RELOADING\n", sizeof("RELOADING\n") - 1);
            conn_teardown();
        }
        /* Ok we're done, kill the child process if it's still up, else it might hang the test framework */
        kill(rc, SIGKILL);
    }
}
END_TEST
#endif

#define END_CMD "zEND"
#define INSTREAM_CMD "zINSTREAM"
static void test_idsession_commands(int split, int instream)
{
    char buf[20480];
    size_t i, len = 0, j = 0;
    char *recvdata;
    char *p = buf;
    const char *replies[2 + sizeof(basic_tests) / sizeof(basic_tests[0])];

    /* test all commands that must be accepted inside an IDSESSION */
    for (i = 0; i < sizeof(basic_tests) / sizeof(basic_tests[0]); i++) {
        const struct basic_test *test = &basic_tests[i];
        if (test->skiproot && isroot)
            continue;
        if (test->ids == IDS_OK) {
            ck_assert_msg(p + strlen(test->command) + 2 < buf + sizeof(buf), "Buffer too small");
            *p++ = 'z';
            strcpy(p, test->command);
            p += strlen(test->command);
            *p++ = '\0';
            if (test->extra) {
                ck_assert_msg(p + strlen(test->extra) < buf + sizeof(buf), "Buffer too small");
                strcpy(p, test->extra);
                p += strlen(test->extra);
            }
            replies[j++] = test->reply;
        }
        if (instream && test->ids == IDS_END) {
            uint32_t chunk;
            /* IDS_END - in middle of other commands, perfect for inserting
             * INSTREAM */
            ck_assert_msg(p + sizeof(INSTREAM_CMD) + 544 < buf + sizeof(buf), "Buffer too small");
            memcpy(p, INSTREAM_CMD, sizeof(INSTREAM_CMD));
            p += sizeof(INSTREAM_CMD);
            p += prepare_instream(p, 0, 552);
            replies[j++] = EXPECT_INSTREAM0;
            ck_assert_msg(p + sizeof(INSTREAM_CMD) + 16388 < buf + sizeof(buf), "Buffer too small");
            memcpy(p, INSTREAM_CMD, sizeof(INSTREAM_CMD));
            p += sizeof(INSTREAM_CMD);
            chunk = htonl(16384);
            memcpy(p, &chunk, 4);
            p += 4;
            memset(p, 0x5a, 16384);
            p += 16384;
            *p++         = '\0';
            *p++         = '\0';
            *p++         = '\0';
            *p++         = '\0';
            replies[j++] = "stream: OK";
        }
    }
    ck_assert_msg(p + sizeof(END_CMD) < buf + sizeof(buf), "Buffer too small");
    memcpy(p, END_CMD, sizeof(END_CMD));
    p += sizeof(END_CMD);

    if (split) {
        /* test corner-cases: 1-byte sends */
        for (i = 0; i < (size_t)(p - buf); i++)
            ck_assert_msg((size_t)send(sockd, &buf[i], 1, 0) == 1, "send() failed: %zu, %s\n", i, strerror(errno));
    } else {
        ck_assert_msg(send(sockd, buf, p - buf, 0) == p - buf, "send() failed: %s\n", strerror(errno));
    }
    recvdata = (char *)recvfull(sockd, &len);
    p        = recvdata;
    for (i = 0; i < sizeof(basic_tests) / sizeof(basic_tests[0]); i++) {
        const struct basic_test *test = &basic_tests[i];
        if (test->skiproot && isroot)
            continue;
        if (test->ids == IDS_OK) {
            unsigned id;
            char *q = strchr(p, ':');
            ck_assert_msg(!!q, "No ID in reply: %s\n", p);
            *q = '\0';
            ck_assert_msg(sscanf(p, "%u", &id) == 1, "Wrong ID in reply: %s\n", p);
            ck_assert_msg(id > 0, "ID cannot be zero");
            ck_assert_msg(id <= j, "ID too big: %u, max: %zu\n", id, j);
            q += 2;
            ck_assert_msg(NULL != strstr(q, replies[id - 1]),
                          "Wrong ID reply for ID %u:\nReceived: \n%s\nExpected: \n%s\n",
                          id,
                          q, replies[id - 1]);
            p = q + strlen(q) + 1;
        }
    }
    free(recvdata);
    conn_teardown();
}

#define ID_CMD "zIDSESSION"
START_TEST(test_idsession)
{
    conn_setup();
    ck_assert_msg((size_t)send(sockd, ID_CMD, sizeof(ID_CMD), 0) == sizeof(ID_CMD),
                  "send() failed: %s\n", strerror(errno));
    test_idsession_commands(0, 0);
    conn_setup();
    ck_assert_msg((size_t)send(sockd, ID_CMD, sizeof(ID_CMD), 0) == sizeof(ID_CMD),
                  "send() failed: %s\n", strerror(errno));
    test_idsession_commands(1, 0);
    conn_setup();
    ck_assert_msg((size_t)send(sockd, ID_CMD, sizeof(ID_CMD), 0) == sizeof(ID_CMD),
                  "send() failed: %s\n", strerror(errno));
    test_idsession_commands(0, 1);
}
END_TEST

static Suite *test_clamd_suite(void)
{
    Suite *s = suite_create("clamd");
    TCase *tc_commands, *tc_stress;
    tc_commands = tcase_create("clamd commands");
    suite_add_tcase(s, tc_commands);
    tcase_add_unchecked_fixture(tc_commands, commands_setup, commands_teardown);

    tcase_add_loop_test(tc_commands, test_basic_commands, 0, sizeof(basic_tests) / sizeof(basic_tests[0]));
    tcase_add_loop_test(tc_commands, test_compat_commands, 0, sizeof(basic_tests) / sizeof(basic_tests[0]));
#ifndef _WIN32 // Disabled on Windows because fd-passing not supported on Windows
    tcase_add_loop_test(tc_commands, test_fildes, 0, 4 * sizeof(fildes_cmds) / sizeof(fildes_cmds[0]));
#endif

    tcase_add_test(tc_commands, test_stats);
    tcase_add_test(tc_commands, test_instream);
    tcase_add_test(tc_commands, test_idsession);

#ifndef _WIN32 // Disabled because fd-passing not supported on Windows
    tc_stress = tcase_create("clamd stress test");
    suite_add_tcase(s, tc_stress);
    tcase_set_timeout(tc_stress, 20);
    tcase_add_test(tc_stress, test_fildes_many);
    tcase_add_test(tc_stress, test_idsession_stress);
    tcase_add_test(tc_stress, test_fildes_unwanted);
#ifndef C_BSD
    /* FreeBSD and Darwin: connect() says connection refused on both
     * tcp/unix sockets, if I too quickly connect ~193 times, even if
     * listen backlog is higher.
     * Don't run this test on BSD for now */
    tcase_add_test(tc_stress, test_connections); // Disabled on Windows because test uses fork() instead of threads, and needs to be rewritten.
#endif
#endif
    return s;
}

int main(int argc, char **argv)
{
    int num_fds;

    UNUSEDPARAM(argc);
    UNUSEDPARAM(argv);

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        fprintf(stderr, "Error at WSAStartup(): %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }
#endif

    Suite *s    = test_clamd_suite();
    SRunner *sr = srunner_create(s);
    srunner_set_log(sr, OBJDIR PATHSEP "test-clamd.log");
    srunner_run_all(sr, CK_NORMAL);
    num_fds = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (num_fds == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
