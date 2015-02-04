
AC_DEFUN([CONFTEST_FDPASS],[[
AC_LANG_SOURCE([[
$1 
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <signal.h>
#include <sys/socket.h>

#if !defined CMSG_SPACE || !defined CMSG_LEN
#ifndef ALIGN
#define ALIGN(len) len
#endif

#ifndef CMSG_SPACE
#define CMSG_SPACE(len) (ALIGN(sizeof(struct cmsghdr)) + ALIGN(len))
#endif

#ifndef CMSG_LEN
#define CMSG_LEN(len) (ALIGN(sizeof(struct cmsghdr)) + len)
#endif
#endif

#define TEST "test"

static int send_fd(int s, int fd)
{
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov[1];
    char dummy[] = "";

    iov[0].iov_base = dummy;
    iov[0].iov_len = 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = fdbuf;
    /* must send/receive at least one byte */
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;

    if (sendmsg(s, &msg, 0) == -1) {
        perror("sendmsg");
        close(s);
        return -1;
    }
    return 0;
}

static int testfd(int desc)
{
    char buf[256];
    if(read(desc, buf, sizeof(buf)) != sizeof(TEST)) {
        fprintf(stderr, "test data not received correctly!");
        return 1;
    }
    return memcmp(buf, TEST, sizeof(TEST));
}

static int recv_fd(int desc)
{
    unsigned char buf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec iov[1];
    char dummy;
    int ret=2;

    memset(&msg, 0, sizeof(msg));
    iov[0].iov_base = &dummy;
    iov[0].iov_len = 1;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(desc, &msg, 0) == -1) {
        perror("recvmsg failed!");
        return -1;
    }
    if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
        fprintf(stderr, "control message truncated");
        return -1;
    }
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
        cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
            cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS) {
            int fd = *(int *)CMSG_DATA(cmsg);
            ret = testfd(fd);
            close(fd);
        }
    }
    return ret;
}

int main(void)
{
    int fd[2];
    int pip[2];
    pid_t pid;
    int status;

    if(pipe(pip)) {
        perror("pipe");
        return 1;
    }

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
        perror("socketpair");
        return 1;
    }

    if((pid=fork()) < 0) {
        perror("fork");
    } else if (!pid) {
        exit( recv_fd(fd[1]) );
    } else {
        /* parent */
        if(send_fd(fd[0], pip[0]) == -1) {
            kill(pid, 9);
            waitpid(pid, NULL, 0);
            return 2;
        }
        if(write(pip[1], TEST, sizeof(TEST)) != sizeof(TEST)) {
		close(pip[1]);
		return -1;
	}
        close(pip[1]);
        waitpid(pid, &status, 0);
    }
    return status;
}
]])
]])

AC_DEFUN([AC_C_FDPASSING],[
dnl Check if we can do fd passing
dnl Submitted by Richard Lyons <frob-clamav@webcentral.com.au>
AC_CHECK_FUNCS([recvmsg sendmsg])
AC_CACHE_CHECK([for msg_control field in struct msghdr],
    [ac_cv_have_control_in_msghdr], [
    AC_TRY_COMPILE(
[
#define _XOPEN_SOURCE 500
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
],
[
#ifdef msg_control
#error msg_control defined
#endif
struct msghdr m;
m.msg_control = 0;
return 0;
], [ ac_cv_have_control_in_msghdr="yes" ], [ ac_cv_have_control_in_msghdr="no" ])
])
if test "x$ac_cv_have_control_in_msghdr" = "xyes" ; then
    dnl Check whether FD passing works <edwin@clamav.net>
    AC_MSG_CHECKING([BSD 4.4 / RFC2292 style fd passing])
    AC_ARG_ENABLE([fdpassing],[AS_HELP_STRING([--disable-fdpassing], [do not build file descriptor passing support])],
        want_fdpassing=$enableval, want_fdpassing="yes")

    if test "x$want_fdpassing" = "xyes"; then
        dnl Try without _XOPEN_SOURCE first
        AC_RUN_IFELSE(CONFTEST_FDPASS([]), [have_fdpass=1; fdpass_need_xopen=0], [have_fdpass=0],[have_fdpass=0])

        if test $have_fdpass = 0; then
            AC_RUN_IFELSE(CONFTEST_FDPASS([#define _XOPEN_SOURCE 500]), [have_fdpass=1; fdpass_need_xopen=1],[have_fdpass=0],[have_fdpass=0])
        fi

        if test $have_fdpass = 1; then
            AC_DEFINE([HAVE_FD_PASSING],1,[have working file descriptor passing support])
            if test $fdpass_need_xopen = 1; then
                AC_DEFINE([FDPASS_NEED_XOPEN],1,[whether _XOPEN_SOURCE needs to be defined for fd passing to work])
                AC_MSG_RESULT([yes, by defining _XOPEN_SOURCE])
            else
                AC_MSG_RESULT([yes])
            fi
        else
            AC_MSG_RESULT([no])
        fi

    else
        AC_MSG_RESULT([disabled])
    fi
fi
])
