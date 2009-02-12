/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifdef	_MSC_VER
#include <winsock.h>
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef	C_WINDOWS
#include <sys/time.h>
#include <sys/wait.h>
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifndef	C_WINDOWS
#include <sys/socket.h>
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <pthread.h>
/* submitted by breiter@wolfereiter.com: do not use poll(2) on Interix */
#ifdef C_INTERIX
#undef HAVE_POLL
#undef HAVE_POLL_H
#endif

#if HAVE_POLL
#if HAVE_POLL_H
#include <poll.h>
#else /* HAVE_POLL_H */
#undef HAVE_POLL
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#endif /* HAVE_POLL_H */
#endif /* HAVE_POLL */

#include "shared/optparser.h"
#include "shared/output.h"

#include "session.h"
#include "others.h"

#ifdef	C_WINDOWS
void virusaction(const char *filename, const char *virname, const struct optstruct *opts)
{
    if(optget(opts, "VirusEvent")->enabled)
	logg("^VirusEvent is not supported on this platform");	/* Yet */
}

#else

#define VE_FILENAME  "CLAM_VIRUSEVENT_FILENAME"
#define VE_VIRUSNAME "CLAM_VIRUSEVENT_VIRUSNAME"

static pthread_mutex_t virusaction_lock = PTHREAD_MUTEX_INITIALIZER;

void virusaction(const char *filename, const char *virname, const struct optstruct *opts)
{
	pid_t pid;
	const struct optstruct *opt;
	char *buffer_file, *buffer_vir, *buffer_cmd;
	const char *pt;
	size_t i, j, v = 0, len;
	char *env[4];

	if(!(opt = optget(opts, "VirusEvent"))->enabled)
		return;

	env[0] = getenv("PATH");
	j = env[0] ? 1 : 0;
	/* Allocate env vars.. to be portable env vars should not be freed */
	buffer_file = (char *) malloc(strlen(VE_FILENAME) + strlen(filename) + 2);
	if(buffer_file) {
		sprintf(buffer_file, "%s=%s", VE_FILENAME, filename);
		env[j++] = buffer_file;
	}

	buffer_vir = (char *) malloc(strlen(VE_VIRUSNAME) + strlen(virname) + 2);
	if(buffer_vir) {
		sprintf(buffer_vir, "%s=%s", VE_VIRUSNAME, virname);
		env[j++] = buffer_vir;
	}
	env[j++] = NULL;

	pt = opt->strarg;
	while((pt = strstr(pt, "%v"))) {
	    pt += 2;
	    v++;
	}
	len = strlen(opt->strarg);
	buffer_cmd = (char *) calloc(len + v * strlen(virname) + 1, sizeof(char));
	if(!buffer_cmd) {
	    free(buffer_file);
	    free(buffer_vir);
	    return;
	}
	for(i = 0, j = 0; i < len; i++) {
	    if(i + 1 < len && opt->strarg[i] == '%' && opt->strarg[i + 1] == 'v') {
		strcat(buffer_cmd, virname);
		j += strlen(virname);
		i++;
	    } else {
		buffer_cmd[j++] = opt->strarg[i];
	    }
	}

	pthread_mutex_lock(&virusaction_lock);
	/* We can only call async-signal-safe functions after fork(). */
	pid = fork();
	if(!pid) { /* child */
	    exit(execle("/bin/sh", "sh", "-c", buffer_cmd, NULL, env));
	} else if(pid > 0) { /* parent */
	    pthread_mutex_unlock(&virusaction_lock);
	    waitpid(pid, NULL, 0);
	} else {
	    logg("!VirusEvent: fork failed.\n");
	}
	free(buffer_cmd);
	free(buffer_file);
	free(buffer_vir);
}
#endif /* C_WINDOWS */

/* Function: writen
	Try hard to write the specified number of bytes
*/
int writen(int fd, void *buff, unsigned int count)
{
	int retval;
	unsigned int todo;
	unsigned char *current;
 
    todo = count;
    current = (unsigned char *) buff;
 
    do {
	retval = write(fd, current, todo);
	if (retval < 0) {
	    if (errno == EINTR) {
		continue;
	    }
	    return -1;
	}
	todo -= retval;
	current += retval;
    } while (todo > 0);
 
    return count;
}

static int realloc_polldata(struct fd_data *data)
{
#ifdef HAVE_POLL
    if (data->poll_data_nfds == data->nfds)
	return 0;
    if (data->poll_data)
	free(data->poll_data);
    data->poll_data = malloc(data->nfds*sizeof(*data->poll_data));
    if (!data->poll_data) {
	logg("!realloc_polldata: Memory allocation failed for poll_data\n");
	return -1;
    }
    data->poll_data_nfds = data->nfds;
#endif
    return 0;
}

int poll_fd(int fd, int timeout_sec, int check_signals)
{
    int ret;
    struct fd_data fds;

    memset(&fds, 0, sizeof(fds));
    if (fds_add(&fds, fd, 1) == -1)
	return -1;
    ret = fds_poll_recv(&fds, timeout_sec, check_signals);
    fds_free(&fds);
    return ret;
}

static void cleanup_fds(struct fd_data *data)
{
    struct fd_buf *newbuf;
    unsigned i,j;
    for (i=0,j=0;i < data->nfds; i++) {
	if (data->buf[i].fd < 0) {
	    if (data->buf[i].buffer)
		free(data->buf[i].buffer);
	    continue;
	}
	if (i != j)
	    data->buf[j] = data->buf[i];
	j++;
    }
    for (i = j ; i < data->nfds; i++)
	data->buf[i].fd = -1;
    data->nfds = j;
    /* Shrink buffer */
    newbuf = realloc(data->buf, j*sizeof(*newbuf));
    if (newbuf)
	data->buf = newbuf;/* non-fatal if shrink fails */
}

static int read_fd_data(struct fd_buf *buf)
{
    ssize_t n;

    buf->got_newdata=1;
    if (!buf->buffer) /* listen-only socket */
	return 1;

    if (buf->off >= buf->bufsize)
	return -1;

   /* Read the pending packet, it may contain more than one command, but
    * that is to the cmdparser to handle. 
    * It will handle 1st command, and then move leftover to beginning of buffer
    */
#ifdef HAVE_FD_PASSING
  {
      struct msghdr msg;
      struct cmsghdr *cmsg;
      unsigned char buff[CMSG_SPACE(sizeof(int))];
      struct iovec iov[1];

      if (buf->recvfd != -1) {
	  close(buf->recvfd);
	  buf->recvfd = -1;
      }
      memset(&msg, 0, sizeof(msg));
      iov[0].iov_base = buf->buffer + buf->off;
      iov[0].iov_len = buf->bufsize - buf->off;
      msg.msg_iov = iov;
      msg.msg_iovlen = 1;
      msg.msg_control = buff;
      msg.msg_controllen = sizeof(buff);

      n = recvmsg(buf->fd, &msg, 0);
      if (n < 0)
	  return -1;
      if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
	  logg("!control message truncated");
	  return -1;
      }
      if (msg.msg_controllen) {
	  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	      if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
		  cmsg->cmsg_level == SOL_SOCKET &&
		  cmsg->cmsg_type == SCM_RIGHTS) {
		  if (buf->recvfd != -1) {
		      logg("^Unclaimed file descriptor received. closing\n");
		      close(buf->recvfd);
		  }
		  buf->recvfd = *(int *)CMSG_DATA(cmsg);
		  logg("*RECVMSG: got FD %d\n", buf->recvfd);
	      }
	  }
      }
  }
#else
   n = recv(buf->fd, buf->buffer + buf->off, buf->bufsize - buf->off,0);
   if (n < 0)
       return -1;
#endif
   buf->off += n;
   return n;
}

static int buf_init(struct fd_buf *buf, int listen_only)
{
    buf->off = 0;
    buf->got_newdata = 0;
    buf->recvfd = -1;
    buf->mode = MODE_COMMAND;
    buf->id = 0;
    buf->dumpfd = -1;
    buf->chunksize = 0;
    buf->quota = 0;
    buf->dumpname = NULL;
    buf->group = NULL;
    buf->term = '\0';
    if (!listen_only) {
	if (!buf->buffer) {
	    buf->bufsize = PATH_MAX+8;
	    /* plus extra space for a \0 so we can make sure every command is \0
	     * terminated */
	    if (!(buf->buffer = malloc(buf->bufsize + 1))) {
		logg("!add_fd: Memory allocation failed for command buffer\n");
		return -1;
	    }
	}
    } else {
	if (buf->buffer)
	    free(buf->buffer);
	buf->bufsize = 0;
	buf->buffer = NULL;
    }
    return 0;
}

int fds_add(struct fd_data *data, int fd, int listen_only)
{
    struct fd_buf *buf;
    unsigned n;
    if (fd < 0) {
	logg("!add_fd: invalid fd passed to add_fd\n");
	return -1;
    }
    /* we may already have this fd, if
     * the old FD got closed, and the kernel reused the FD */
    for (n = 0; n < data->nfds; n++)
	if (data->buf[n].fd == fd) {
	    /* clear stale data in buffer */
	    if (buf_init(&data->buf[n], listen_only) < 0)
		return -1;
	    return 0;
	}

    n++;
    buf = realloc(data->buf, n*sizeof(*buf));
    if (!buf) {
	logg("!add_fd: Memory allocation failed for fd_buf\n");
	return -1;
    }
    data->buf = buf;
    data->nfds = n;
    data->buf[n-1].buffer = NULL;
    if (buf_init(&data->buf[n-1], listen_only) < 0)
	return -1;
    data->buf[n-1].fd = fd;
    return 0;
}

void fds_remove(struct fd_data *data, int fd)
{
    size_t i;
    pthread_mutex_lock(&data->buf_mutex);
    if (data->buf) {
	for (i=0;i<data->nfds;i++) {
	    if (data->buf[i].fd == fd) {
		data->buf[i].fd = -1;
		break;
	    }
	}
    }
    pthread_mutex_unlock(&data->buf_mutex);
}

#ifndef	C_WINDOWS
#define	closesocket(s)	close(s)
#endif
#define BUFFSIZE 1024
/* Wait till data is available to be read on any of the fds,
 * read available data on all fds, and mark them as appropriate.
 * One of the fds should be a pipe, used by the accept thread to wake us.
 * timeout is specified in seconds, if check_signals is non-zero, then
 * poll_recv_fds() will return upon receipt of a signal, even if no data
 * is received on any of the sockets.
 * Must be called with buf_mutex held.
 */
/* TODO: handle ReadTimeout */
int fds_poll_recv(struct fd_data *data, int timeout, int check_signals)
{
    unsigned fdsok = data->nfds;
    size_t i;
    int retval;

    /* we must have at least one fd, the control fd! */
    if (!data->nfds)
	return 0;
    for (i=0;i < data->nfds;i++)
	data->buf[i].got_newdata = 0;
#ifdef HAVE_POLL
    /* Use poll() if available, preferred because:
     *  - can poll any number of FDs
     *  - can notify of both data available / socket disconnected events
     *  - when it says POLLIN it is guaranteed that a following recv() won't
     *  block (select may say that data is available to read, but a following 
     *  recv() may still block according to the manpage
     */

    if (realloc_polldata(data) == -1)
	return -1;
    if (timeout > 0) {
	/* seconds to ms */
	timeout *= 1000;
    }
    for (i=0;i < data->nfds;i++) {
	data->poll_data[i].fd = data->buf[i].fd;
	data->poll_data[i].events = POLLIN;
	data->poll_data[i].revents = 0;
    }
    do {
	int n = data->nfds;

	pthread_mutex_unlock(&data->buf_mutex);
	retval = poll(data->poll_data, n, timeout);
	pthread_mutex_lock(&data->buf_mutex);

	if (retval > 0) {
	    fdsok = 0;
	    /* nfds may change during poll, but not
	     * poll_data_nfds */
	    for (i=0;i < data->poll_data_nfds; i++) {
		short revents;
		if (data->buf[i].fd < 0)
		    continue;
		if (data->buf[i].fd != data->poll_data[i].fd) {
		    /* should never happen */
		    logg("!poll_recv_fds FD mismatch\n");
		    continue;
		}
		revents = data->poll_data[i].revents;
		if (revents & (POLLIN|POLLHUP)) {
		    logg("*POLL: POLLIN|POLLHUP on fd %d\n",data->poll_data[i].fd);
		}
		if (revents & POLLIN) {
		    int ret = read_fd_data(&data->buf[i]);
		    /* Data available to be read */
		    if (ret == -1)
			revents |= POLLERR;
		    else if (!ret)
			revents = POLLHUP;
		}

		if (revents & (POLLHUP | POLLERR | POLLNVAL)) {
		    if (revents & (POLLHUP| POLLNVAL)) {
			/* remote disconnected */
			logg("^poll_recv_fds: Client disconnected (FD %d)\n",
			     data->poll_data[i].fd);
		    } else {
			/* error on file descriptor */
			logg("!poll_recv_fds: Error condition on fd %d\n",
			     data->poll_data[i].fd);
		    }
		    data->buf[i].got_newdata = -1;
		} else {
		    fdsok++;
		}
	    }
	}
    } while (retval == -1 && !check_signals && errno == EINTR);
#else
    fd_set rfds;
    struct timeval tv;
    int maxfd = -1;

    for (i=0;i < data->nfds; i++) {
	int fd = data->buf[i].fd;
	if (fd >= FD_SETSIZE) {
	    logg ("!poll_recv_fds: file descriptor is not valid for FD_SET\n");
	    return -1;
	}

	maxfd = MAX(maxfd, fd);
    }

    do {
	FD_ZERO(&rfds);
	for(i=0;i < data->nfds;i++) {
	    int fd = data->buf[i].fd;
	    if (fd >= 0)
		FD_SET(fd, &rfds);
	}
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	pthread_mutex_unlock(&data->buf_mutex);
	retval = select(maxfd+1, &rfds, NULL, NULL, timeout > 0 ? &tv : NULL);
	pthread_mutex_lock(&data->buf_mutex);
	if (retval > 0) {
	    fdsok = data->nfds;
	    for (i=0; i < data->nfds; i++) {
		if (data->buf[i].fd < 0) {
		    fdsok--;
		    continue;
		}
		if (FD_ISSET(data->buf[i].fd, &rfds)) {
		    int ret = read_fd_data(&data->buf[i]);
		    if (ret == -1 || !ret) {
			if (ret == -1)
			    logg("!poll_recv_fds: Error condition on fd %d\n",
				 data->buf[i].fd);
			else
			    logg("^poll_recv_fds: Client disconnected\n");
			data->buf[i].got_newdata = -1;
		    }
		}
	    }
	}
	if (retval < 0 && errno == EBADF) {
	    /* unlike poll(),  select() won't tell us which FD is bad, so
	     * we have to check them one by one. */
	    tv.tv_sec = 0;
	    tv.tv_usec = 0;
	    /* with tv == 0 it doesn't check for EBADF */
	    FD_ZERO(&rfds);
	    for (i=0; i< data->nfds; i++) {
		if (data->buf[i].fd == -1)
		    continue;
		FD_SET(data->buf[i].fd, &rfds);
		do {
		    retval = select(data->buf[i].fd+1, &rfds, NULL, NULL, &tv);
		} while (retval == -1 && errno == EINTR);
		if (retval == -1) {
		    data->buf[i].fd = -1;
		} else {
		    FD_CLR(data->buf[i].fd, &rfds);
		}
	    }
	    retval = -1;
	    errno = EINTR;
	    continue;
	}
    } while (retval == -1 && !check_signals && errno == EINTR);
#endif

    if (retval == -1 && errno != EINTR) {
	char buff[BUFFSIZE + 1];
#ifdef HAVE_STRERROR_R
	strerror_r(errno, buff, BUFFSIZE);
#else
	buff[0] = '\0';
#endif
#ifdef HAVE_POLL
	logg("!poll_recv_fds: poll failed: %s\n", buff);
#else
	logg("!poll_recv_fds: select failed: %s\n", buff);
#endif
    }

    /* Remove closed / error fds */
    if (fdsok != data->poll_data_nfds)
	cleanup_fds(data);
    return retval;
}

void fds_free(struct fd_data *data)
{
    unsigned i;
    pthread_mutex_lock(&data->buf_mutex);
    for (i=0;i < data->nfds;i++) {
	if (data->buf[i].buffer) {
	    free(data->buf[i].buffer);
	}
    }
    if (data->buf)
	free(data->buf);
#ifdef HAVE_POLL
    if (data->poll_data)
	free(data->poll_data);
#endif
    data->buf = NULL;
    data->nfds = 0;
    pthread_mutex_unlock(&data->buf_mutex);
}
