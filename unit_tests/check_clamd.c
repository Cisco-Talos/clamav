#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <check.h>
#include "checks_common.h"
#include "libclamav/version.h"

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
static struct basic_test {
    const char *command;
    const char *reply;
} basic_tests[] = {
    {"PING", "PONG"},
    {"RELOAD","RELOADING"},
    {"VERSION", "ClamAV "REPO_VERSION""VERSION_SUFFIX}
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
    buf[*len] = '\0';
    *len = off;
    return buf;
}

static void test_command(const char *cmd, size_t len, const char *expect, size_t expect_len)
{
    void *recvdata;
    int rc;
    rc = send(sockd, cmd, len, 0);
    fail_unless_fmt(rc != -1, "Unable to send(): %s\n", strerror(errno));

    recvdata = recvfull(sockd, &len);

    fail_unless_fmt(len == expect_len, "Reply has wrong size: %lu, expected %lu, reply: %s\n",
		    len, expect_len, recvdata);

    rc = memcmp(recvdata, expect, expect_len);
    fail_unless_fmt(!rc, "Wrong reply for command %s: |%s|, expected: |%s|\n", cmd, recvdata, expect);
    free(recvdata);
}

START_TEST (test_basic_commands)
{
    int rc;
    struct basic_test *test = &basic_tests[_i];
    size_t len;
    char nsend[BUFSIZ], nreply[BUFSIZ];
    /* send the command the "old way" */
    conn_setup();
    snprintf(nreply, sizeof(nreply), "%s\n", test->reply);
    test_command(test->command, strlen(test->command), nreply, strlen(nreply));
    conn_teardown();

    /* send nCOMMAND */
    conn_setup();
    snprintf(nsend, sizeof(nsend), "n%s\n", test->command);
    test_command(nsend, strlen(nsend), nreply, strlen(nreply));
    conn_teardown();

    /* send zCOMMAND */
    conn_setup();
    snprintf(nsend, sizeof(nsend), "z%s\0", test->command);
    test_command(nsend, strlen(nsend)+1, test->reply, strlen(test->reply)+1);
    conn_teardown();
}
END_TEST

static Suite *test_clamd_suite(void)
{
    Suite *s = suite_create("clamd");
    TCase *tc_commands = tcase_create("clamd commands");
    suite_add_tcase(s, tc_commands);
    tcase_add_loop_test(tc_commands, test_basic_commands, 0, sizeof(basic_tests)/sizeof(basic_tests[0]));

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
