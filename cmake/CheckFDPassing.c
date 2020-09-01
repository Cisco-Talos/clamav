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
    iov[0].iov_len  = 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = fdbuf;
    /* must send/receive at least one byte */
    msg.msg_iov        = iov;
    msg.msg_iovlen     = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    cmsg                    = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len          = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level        = SOL_SOCKET;
    cmsg->cmsg_type         = SCM_RIGHTS;
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
    if (read(desc, buf, sizeof(buf)) != sizeof(TEST)) {
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
    int ret = 2;

    memset(&msg, 0, sizeof(msg));
    iov[0].iov_base    = &dummy;
    iov[0].iov_len     = 1;
    msg.msg_iov        = iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = buf;
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
            ret    = testfd(fd);
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

    if (pipe(pip)) {
        perror("pipe");
        return 1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
        perror("socketpair");
        return 1;
    }

    if ((pid = fork()) < 0) {
        perror("fork");
    } else if (!pid) {
        exit(recv_fd(fd[1]));
    } else {
        /* parent */
        if (send_fd(fd[0], pip[0]) == -1) {
            kill(pid, 9);
            waitpid(pid, NULL, 0);
            return 2;
        }
        if (write(pip[1], TEST, sizeof(TEST)) != sizeof(TEST)) {
            close(pip[1]);
            return -1;
        }
        close(pip[1]);
        waitpid(pid, &status, 0);
    }
    return status;
}
