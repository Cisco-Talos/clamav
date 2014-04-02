/*
 *  Copyright 2006 Everton da Silva Marques <everton.marques@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "nonblock.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <ctype.h>
#ifndef	_WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "shared/output.h"
#include "libclamav/clamav.h"

#ifdef SO_ERROR

#ifndef timercmp
#define timercmp(a, b, cmp)          \
  (((a)->tv_sec == (b)->tv_sec) ?     \
   ((a)->tv_usec cmp (b)->tv_usec) :  \
   ((a)->tv_sec cmp (b)->tv_sec))
#endif /* timercmp */

#ifndef timersub
#define timersub(a, b, result)                       \
  do {                                                \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;  \
    if ((result)->tv_usec < 0) {                      \
      --(result)->tv_sec;                             \
      (result)->tv_usec += 1000000;                   \
    }                                                 \
  } while (0)
#endif /* timersub */

#define NONBLOCK_SELECT_MAX_FAILURES 3
#define NONBLOCK_MAX_BOGUS_LOOPS     10
#undef  NONBLOCK_DEBUG

static int
connect_error (int sock)
{
    int optval;
    socklen_t optlen;

    optlen = sizeof (optval);
    getsockopt (sock, SOL_SOCKET, SO_ERROR, &optval, (socklen_t *)&optlen);

    if (optval)
    {
        logg ("connect_error: getsockopt(SO_ERROR): fd=%d error=%d: %s\n",
              sock, optval, strerror (optval));
    }

    return optval ? -1 : 0;
}

static int
nonblock_connect (int sock, const struct sockaddr *addr, socklen_t addrlen,
                  int secs)
{
    /* Max. of unexpected select() failures */
    int select_failures = NONBLOCK_SELECT_MAX_FAILURES;
    /* Max. of useless loops */
    int bogus_loops = NONBLOCK_MAX_BOGUS_LOOPS;
    struct timeval timeout;     /* When we should time out */
    int numfd;                  /* Highest fdset fd plus 1 */

    /* Calculate into 'timeout' when we should time out */
    gettimeofday (&timeout, 0);
    timeout.tv_sec += secs;

    /* Launch (possibly) non-blocking connect() request */
    if (connect (sock, addr, addrlen))
    {
        int e = errno;
#ifdef NONBLOCK_DEBUG
        logg ("DEBUG nonblock_connect: connect(): fd=%d errno=%d: %s\n",
              sock, e, strerror (e));
#endif
        switch (e)
        {
        case EALREADY:
        case EINPROGRESS:
        case EAGAIN:
            break;              /* wait for connection */
        case EISCONN:
            return 0;           /* connected */
        default:
            logg ("nonblock_connect: connect(): fd=%d errno=%d: %s\n",
                  sock, e, strerror (e));
            return -1;          /* failed */
        }
    }
    else
    {
        return connect_error (sock);
    }

    numfd = sock + 1;           /* Highest fdset fd plus 1 */

    for (;;)
    {
        fd_set fds;
        struct timeval now;
        struct timeval wait;
        int n;

        /* Force timeout if we ran out of time */
        gettimeofday (&now, 0);
        if (timercmp (&now, &timeout, >))
        {
            logg ("nonblock_connect: connect timing out (%d secs)\n", secs);
            break;              /* failed */
        }

        /* Calculate into 'wait' how long to wait */
        timersub (&timeout, &now, &wait);   /* wait = timeout - now */

        /* Init fds with 'sock' as the only fd */
        FD_ZERO (&fds);
        FD_SET (sock, &fds);

        n = select (numfd, 0, &fds, 0, &wait);
        if (n < 0)
        {
            logg ("nonblock_connect: select() failure %d: errno=%d: %s\n",
                  select_failures, errno, strerror (errno));
            if (--select_failures >= 0)
                continue;       /* keep waiting */
            break;              /* failed */
        }

#ifdef NONBLOCK_DEBUG
        logg ("DEBUG nonblock_connect: select = %d\n", n);
#endif

        if (n)
        {
            return connect_error (sock);
        }

        /* Select returned, but there is no work to do... */
        if (--bogus_loops < 0)
        {
            logg ("nonblock_connect: giving up due to excessive bogus loops\n");
            break;              /* failed */
        }

    }                           /* for loop: keep waiting */

    return -1;                  /* failed */
}

static ssize_t
nonblock_recv (int sock, void *buf, size_t len, int flags, int secs)
{
    /* Max. of unexpected select() failures */
    int select_failures = NONBLOCK_SELECT_MAX_FAILURES;
    /* Max. of useless loops */
    int bogus_loops = NONBLOCK_MAX_BOGUS_LOOPS;
    struct timeval timeout;     /* When we should time out */
    int numfd;                  /* Highest fdset fd plus 1 */

    /* Zero buffer to maintain sanity in case we're dealing with strings */
    memset(buf, 0x00, len);

    /* Calculate into 'timeout' when we should time out */
    gettimeofday (&timeout, 0);
    timeout.tv_sec += secs;

    numfd = sock + 1;           /* Highest fdset fd plus 1 */

    for (;;)
    {
        fd_set fds;
        struct timeval now;
        struct timeval wait;
        int n;
        ssize_t recvd;

        /* Force timeout if we ran out of time */
        gettimeofday (&now, 0);
        if (timercmp (&now, &timeout, >))
        {
            logg ("nonblock_recv: recv timing out (%d secs)\n", secs);
            break;              /* failed */
        }

        /* Calculate into 'wait' how long to wait */
        timersub (&timeout, &now, &wait);   /* wait = timeout - now */

        /* Init fds with 'sock' as the only fd */
        FD_ZERO (&fds);
        FD_SET (sock, &fds);

        n = select (numfd, &fds, 0, 0, &wait);
        if (n < 0)
        {
            logg ("nonblock_recv: select() failure %d: errno=%d: %s\n",
                  select_failures, errno, strerror (errno));
            if (--select_failures >= 0)
                continue;       /* keep waiting */
            break;              /* failed */
        }

        if (FD_ISSET(sock, &fds))
        {
            recvd = recv(sock, buf, len, flags);
            if (recvd < 0) {
                if (errno == EINTR)
                    continue;

                return -1;
            }

            return recvd;
        }

        /* Select returned, but there is no work to do... */
        if (--bogus_loops < 0)
        {
            logg ("nonblock_recv: giving up due to excessive bogus loops\n");
            break;              /* failed */
        }

    }                           /* for loop: keep waiting */

    return -1;                  /* failed */
}

static long
nonblock_fcntl (int sock)
{
#ifdef	F_GETFL
    long fcntl_flags;           /* Save fcntl() flags */

    fcntl_flags = fcntl (sock, F_GETFL, 0);
    if (fcntl_flags == -1)
    {
        logg ("nonblock_fcntl: saving: fcntl(%d, F_GETFL): errno=%d: %s\n",
              sock, errno, strerror (errno));
    }
    else if (fcntl (sock, F_SETFL, fcntl_flags | O_NONBLOCK))
    {
        logg ("nonblock_fcntl: fcntl(%d, F_SETFL, O_NONBLOCK): errno=%d: %s\n", sock, errno, strerror (errno));
    }

    return fcntl_flags;
#else
    return 0;
#endif
}

static void
restore_fcntl (int sock, long fcntl_flags)
{
#ifdef	F_SETFL
    if (fcntl_flags != -1)
    {
        if (fcntl (sock, F_SETFL, fcntl_flags))
        {
            logg ("restore_fcntl: restoring: fcntl(%d, F_SETFL): errno=%d: %s\n", sock, errno, strerror (errno));
        }
    }
#endif
}

/*
	wait_connect(): wrapper for connect(), with explicit 'secs' timeout
*/
int
wait_connect (int sock, const struct sockaddr *addr, socklen_t addrlen,
              int secs)
{
    long fcntl_flags;           /* Save fcntl() flags */
    int ret;

    /* Temporarily set socket to non-blocking mode */
    fcntl_flags = nonblock_fcntl (sock);

    ret = nonblock_connect (sock, addr, addrlen, secs);

    /* Restore socket's default blocking mode */
    restore_fcntl (sock, fcntl_flags);

    return ret;
}

/*
	wait_recv(): wrapper for recv(), with explicit 'secs' timeout
*/
ssize_t
wait_recv (int sock, void *buf, size_t len, int flags, int secs)
{
    long fcntl_flags;           /* Save fcntl() flags */
    int ret;

    /* Temporarily set socket to non-blocking mode */
    fcntl_flags = nonblock_fcntl (sock);

    ret = nonblock_recv (sock, buf, len, flags, secs);

    /* Restore socket's default blocking mode */
    restore_fcntl (sock, fcntl_flags);

    return ret;
}

#endif /* SO_ERROR */
