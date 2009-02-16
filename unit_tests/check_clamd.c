#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <check.h>
#include "checks_common.h"
#include "libclamav/version.h"
#include "libclamav/cltypes.h"
#include "shared/fdpassing.h"

#ifdef CHECK_HAVE_LOOPS

static int sockd;
#define SOCKET "clamd-test.socket"
static void conn_setup(void)
{
    int rc;
    struct sockaddr_un nixsock;
    memset((void *)&nixsock, 0, sizeof(nixsock));
    nixsock.sun_family = AF_UNIX;
    strncpy(nixsock.sun_path, SOCKET, sizeof(nixsock.sun_path));

    sockd = socket(AF_UNIX, SOCK_STREAM, 0);
    fail_unless_fmt(sockd != -1, "Unable to create socket: %s\n", strerror(errno));

    rc = connect(sockd, (struct sockaddr *)&nixsock, sizeof(nixsock));
    fail_unless_fmt(rc != -1, "Unable to connect(): %s\n", strerror(errno));

    signal(SIGPIPE, SIG_IGN);
}

static void conn_teardown(void)
{
    if (sockd != -1)
	close(sockd);
}

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

#define SCANFILE BUILDDIR"/../test/clam.exe"
#define FOUNDREPLY SCANFILE": ClamAV-Test-File.UNOFFICIAL FOUND"

/* some clean file */
#define CLEANFILE SRCDIR"/Makefile.am"
#define CLEANREPLY CLEANFILE": OK"
#define UNKNOWN_REPLY "UNKNOWN COMMAND"

#define NONEXISTENT "/nonexistent\vfilename"
#define NONEXISTENT_REPLY NONEXISTENT": lstat() failed: No such file or directory. ERROR"

#define ACCDENIED BUILDDIR"/accdenied"
#define ACCDENIED_REPLY ACCDENIED": Access denied. ERROR"

static void commands_setup(void)
{
    const char *nonempty = "NONEMPTYFILE";
    int fd = open(NONEXISTENT, O_RDONLY);
    int rc;
    if (fd != -1) close(fd);
    fail_unless(fd == -1, "Nonexistent file exists!\n");

    fd = open(ACCDENIED, O_CREAT | O_WRONLY, S_IWUSR);
    fail_unless_fmt(fd != -1,
		    "Failed to create file for access denied tests: %s\n", strerror(errno));


    fail_unless_fmt(fchmod(fd,  S_IWUSR) != -1,
		    "Failed to chmod: %s\n", strerror(errno));
    /* must not be empty file */
    fail_unless_fmt(write(fd, nonempty, strlen(nonempty)) == strlen(nonempty),
		    "Failed to write into testfile: %s\n", strerror(errno));
    close(fd);
}

static void commands_teardown(void)
{
    int rc = unlink(ACCDENIED);
    fail_unless_fmt(rc != -1, "Failed to unlink access denied testfile: %s\n", strerror(errno));
}

static struct basic_test {
    const char *command;
    const char *extra;
    const char *reply;
} basic_tests[] = {
    {"PING", NULL, "PONG"},
    {"RELOAD", NULL, "RELOADING"},
    {"VERSION", NULL, "ClamAV "REPO_VERSION""VERSION_SUFFIX},
    {"SCAN "SCANFILE, NULL, FOUNDREPLY},
    {"SCAN "CLEANFILE, NULL, CLEANREPLY},
    {"CONTSCAN "SCANFILE, NULL, FOUNDREPLY},
    {"CONTSCAN "CLEANFILE, NULL, CLEANREPLY},
    {"MULTISCAN "SCANFILE, NULL, FOUNDREPLY},
    {"MULTISCAN "CLEANFILE, NULL, CLEANREPLY},
    /* unknown commnads */
    {"RANDOM", NULL, UNKNOWN_REPLY},
    /* commands invalid as first */
    {"END", NULL, UNKNOWN_REPLY},
    /* commands for nonexistent files */
    {"SCAN "NONEXISTENT, NULL, NONEXISTENT_REPLY},
    {"CONTSCAN "NONEXISTENT, NULL, NONEXISTENT_REPLY},
    {"MULTISCAN "NONEXISTENT, NULL, NONEXISTENT_REPLY},
    /* commands for access denied files */
    {"SCAN "ACCDENIED, NULL, ACCDENIED_REPLY},
    {"CONTSCAN "ACCDENIED, NULL, ACCDENIED_REPLY},
    {"MULTISCAN "ACCDENIED, NULL, ACCDENIED_REPLY},
    /* commands with invalid/missing arguments */
    {"SCAN", NULL, UNKNOWN_REPLY},
    {"CONTSCAN", NULL, UNKNOWN_REPLY},
    {"MULTISCAN", NULL, UNKNOWN_REPLY},
    /* commands with invalid data */
    {"INSTREAM", "\xff\xff\xff\xff", "INSTREAM size limit exceeded. ERROR"}, /* too big chunksize */
    {"FILDES", "X", "No file descriptor received. ERROR"}, /* FILDES w/o ancillary data */
};

static void *recvfull(int sd, size_t *len)
{
    char *buf = NULL;
    size_t off = 0;
    int rc;

    *len = 0;
    do {
       if (off + BUFSIZ > *len) {
	    *len += BUFSIZ+1;
	    buf = realloc(buf, *len);
	    fail_unless(!!buf, "Cannot realloc buffer\n");
	}

	rc = recv(sd, buf + off, BUFSIZ, 0);
	fail_unless_fmt(rc != -1, "recv() failed: %s\n", strerror(errno));
	off += rc;
    } while (rc);
    *len = off;
    buf[*len] = '\0';
    return buf;
}

static void test_command(const char *cmd, size_t len, const char *extra, const char *expect, size_t expect_len)
{
    void *recvdata;
    ssize_t rc;
    rc = send(sockd, cmd, len, 0);
    fail_unless_fmt((size_t)rc == len, "Unable to send(): %s\n", strerror(errno));

    if (extra) {
	rc = send(sockd, extra, strlen(extra), 0);
	fail_unless_fmt((size_t)rc == strlen(extra), "Unable to send() extra for %s: %s\n", cmd, strerror(errno));
    }

    recvdata = recvfull(sockd, &len);

    fail_unless_fmt(len == expect_len, "Reply has wrong size: %lu, expected %lu, reply: %s, expected: %s\n",
		    len, expect_len, recvdata, expect);

    rc = memcmp(recvdata, expect, expect_len);
    fail_unless_fmt(!rc, "Wrong reply for command %s: |%s|, expected: |%s|\n", cmd, recvdata, expect);
    free(recvdata);
}

START_TEST (test_basic_commands)
{
    struct basic_test *test = &basic_tests[_i];
    char nsend[BUFSIZ], nreply[BUFSIZ];

    /* send nCOMMAND */
    snprintf(nreply, sizeof(nreply), "%s\n", test->reply);
    snprintf(nsend, sizeof(nsend), "n%s\n", test->command);
    conn_setup();
    test_command(nsend, strlen(nsend), test->extra, nreply, strlen(nreply));
    conn_teardown();

    /* send zCOMMAND */
    snprintf(nsend, sizeof(nsend), "z%s", test->command);
    conn_setup();
    test_command(nsend, strlen(nsend)+1, test->extra, test->reply, strlen(test->reply)+1);
    conn_teardown();
}
END_TEST

START_TEST (test_compat_commands)
{
    /* test sending the command the "old way" */
    struct basic_test *test = &basic_tests[_i];
    char nsend[BUFSIZ], nreply[BUFSIZ];

    snprintf(nreply, sizeof(nreply), "%s\n", test->reply);
    if (!test->extra) {
	/* one command = one packet, no delimiter */
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

#define STATS_REPLY "POOLS: 1\n\nSTATE: VALID PRIMARY\n"
START_TEST (test_stats)
{
    char *recvdata;
    size_t len = strlen("nSTATS\n");
    int rc;

    conn_setup();
    rc = send(sockd, "nSTATS\n", len, 0);
    fail_unless_fmt((size_t)rc == len, "Unable to send(): %s\n", strerror(errno));

    recvdata = recvfull(sockd, &len);

    fail_unless_fmt(len > strlen(STATS_REPLY), "Reply has wrong size: %lu, minimum %lu, reply: %s\n",
		    len, strlen(STATS_REPLY), recvdata);

    if (len > strlen(STATS_REPLY))
	len = strlen(STATS_REPLY);
    rc = strncmp(recvdata, STATS_REPLY, len);

    fail_unless_fmt(rc == 0, "Wrong reply: %s\n", recvdata);
    free(recvdata);
    conn_teardown();
}
END_TEST

START_TEST (test_instream)
{
    int fd, nread, rc;
    struct stat stbuf;
    uint32_t chunk;
    void *recvdata;
    size_t len, expect_len;
    char buf[4096] = "nINSTREAM\n";
    size_t off = strlen(buf);

    fail_unless_fmt(stat(SCANFILE, &stbuf) != -1, "stat failed for %s: %s", SCANFILE, strerror(errno));

    fd = open(SCANFILE, O_RDONLY);
    fail_unless_fmt(fd != -1, "open failed: %s\n", strerror(errno));

    chunk = htonl(stbuf.st_size);
    memcpy(&buf[off], &chunk, sizeof(chunk));
    off += 4;
    nread = read(fd, &buf[off], sizeof(buf)-off-4);
    fail_unless_fmt(nread == stbuf.st_size, "read failed: %s\n", strerror(errno));
    off += nread;
    buf[off++]=0;
    buf[off++]=0;
    buf[off++]=0;
    buf[off++]=0;
    close(fd);

    conn_setup();
    fail_unless((size_t)send(sockd, buf, off, 0) == off, "send() failed: %s\n", strerror(errno));

    recvdata = recvfull(sockd, &len);

    expect_len = strlen(EXPECT_INSTREAM);
    fail_unless_fmt(len == expect_len, "Reply has wrong size: %lu, expected %lu, reply: %s\n",
		    len, expect_len, recvdata);

    rc = memcmp(recvdata, EXPECT_INSTREAM, expect_len);
    fail_unless_fmt(!rc, "Wrong reply for command INSTREAM: |%s|, expected: |%s|\n", recvdata, EXPECT_INSTREAM);
    free(recvdata);

    conn_teardown();
}
END_TEST

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
	dummy[0] = '\0';
	iov[0].iov_base = dummy;
	iov[0].iov_len = 1;
    } else {
	/* send single message with ancillary data */
	fail_unless(msg_len < sizeof(dummy)-1);
	memcpy(dummy, mesg, msg_len);
	dummy[msg_len] = '\0';
	iov[0].iov_base = dummy;
	iov[0].iov_len = msg_len + 1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = fdbuf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
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
    off_t pos;
    char *recvdata, *p;
    int rc;

    conn_setup();
    fail_unless_fmt(sendmsg_fd(sockd, cmd, len, fd, singlemsg) != -1,
		     "Failed to sendmsg: %s\n", strerror(errno));

    if (closefd)
	close(fd);

    recvdata = recvfull(sockd, &len);
    p = strchr(recvdata, ':');

    fail_unless_fmt(!!p, "Reply doesn't contain ':' : %s\n", recvdata);
    *p++ = '\0';

    fail_unless_fmt(sscanf(recvdata, "fd[%u]", &rc) == 1, "Reply doesn't contain fd: %s\n", recvdata);

    len -= p - recvdata;
    fail_unless_fmt(len == expect_len, "Reply has wrong size: %lu, expected %lu, reply: %s, expected: %s\n",
		    len, expect_len, p, expect);

    rc = memcmp(p, expect, expect_len);
    fail_unless_fmt(!rc, "Wrong reply for command %s: |%s|, expected: |%s|\n", cmd, p, expect);
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
    {"zFILDES", '\0', CLEANFILE, CLEANFDREPLY}
};

START_TEST (test_fildes)
{
    char nreply[BUFSIZ], nsend[BUFSIZ];
    int fd = open(SCANFILE, O_RDONLY);
    int closefd;
    int singlemsg;
    size_t i;
    const struct cmds *cmd;
    size_t nreply_len, nsend_len;

    switch (_i&3) {
	case 0:
	    closefd = 0;
	    singlemsg = 0;
	    break;
	case 1:
	    closefd = 1;
	    singlemsg = 0;
	    break;
	case 2:
	    closefd = 0;
	    singlemsg = 1;
	    break;
	case 3:
	    closefd = 1;
	    singlemsg = 1;
	    break;
    }

    cmd = &fildes_cmds[_i/4];
    nreply_len = snprintf(nreply, sizeof(nreply), "%s%c", cmd->reply, cmd->term);
    nsend_len = snprintf(nsend, sizeof(nsend), "%s%c", cmd->cmd, cmd->term);

    fd = open(cmd->file, O_RDONLY);
    fail_unless_fmt(fd != -1, "Failed to open: %s\n", strerror(errno));

    tst_fildes(nsend, nsend_len, fd, nreply, nreply_len, closefd, singlemsg);

    if (!closefd) {
	/* closefd: 
	 *  1 - close fd right after sending
	 *  0 - close fd after receiving reply */
	close(fd);
    }
}
END_TEST

START_TEST (test_fildes_many)
{
    const char idsession[] = "zIDSESSION";
    int dummyfd, dummycleanfd, i, killed = 0;

    conn_setup();
    dummyfd = open(SCANFILE, O_RDONLY);
    fail_unless_fmt(dummyfd != -1, "failed to open %s: %s\n", SCANFILE, strerror(errno));

    fail_unless_fmt(send(sockd, idsession, sizeof(idsession), 0) == sizeof(idsession), "send IDSESSION failed\n");
    for (i=0; i < 2048; i++) {
	if (sendmsg_fd(sockd, "zFILDES", sizeof("zFILDES"), dummyfd, 1) == -1) {
	    killed = 1;
	    break;
	}
    }

    fail_unless(killed, "Clamd did not kill connection when overloaded!\n");

    close(dummyfd);
    conn_teardown();
}
END_TEST

static Suite *test_clamd_suite(void)
{
    Suite *s = suite_create("clamd");
    TCase *tc_commands, *tc_stress;

    tc_commands = tcase_create("clamd commands");
    suite_add_tcase(s, tc_commands);
    tcase_add_unchecked_fixture(tc_commands, commands_setup, commands_teardown);
    tcase_add_loop_test(tc_commands, test_basic_commands, 0, sizeof(basic_tests)/sizeof(basic_tests[0]));
    tcase_add_loop_test(tc_commands, test_compat_commands, 0, sizeof(basic_tests)/sizeof(basic_tests[0]));
    tcase_add_loop_test(tc_commands, test_fildes, 0, 4*sizeof(fildes_cmds)/sizeof(fildes_cmds[0]));
    tcase_add_test(tc_commands, test_stats);
    tcase_add_test(tc_commands, test_instream);

    tc_stress = tcase_create("clamd stress test");
    suite_add_tcase(s, tc_stress);
    tcase_add_test(tc_stress, test_fildes_many);

    return s;
}

int main(void)
{
    int nf;
    Suite *s = test_clamd_suite();
    SRunner *sr = srunner_create(s);
    srunner_set_log(sr, "test-clamd.log");
    srunner_run_all(sr, CK_NORMAL);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else
int main(void)
{
    puts("\n*** Check version too old, clamd tests not run!\n");
    /* tell automake the test was skipped */
    return 77;
}
#endif
