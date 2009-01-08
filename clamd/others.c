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

#define ENV_FILE  "CLAM_VIRUSEVENT_FILENAME"
#define ENV_VIRUS "CLAM_VIRUSEVENT_VIRUSNAME"

#ifdef	C_WINDOWS
void virusaction(const char *filename, const char *virname, const struct optstruct *opts)
{
    if(optget(opts, "VirusEvent")->enabled)
	logg("^VirusEvent is not supported on this platform");	/* Yet */
}

#else
static pthread_mutex_t virusaction_lock = PTHREAD_MUTEX_INITIALIZER;

void virusaction(const char *filename, const char *virname, const struct optstruct *opts)
{
	pid_t pid;
	const struct optstruct *opt;
	char *buffer, *pt, *cmd, *buffer_file, *buffer_vir;
	size_t j;
	char *env[4];

	if(!(opt = optget(opts, "VirusEvent"))->enabled)
		return;

	env[0] = getenv("PATH");
	j = env[0] ? 1 : 0;
	/* Allocate env vars.. to be portable env vars should not be freed */
	buffer_file = (char *) malloc(strlen(ENV_FILE) + strlen(filename) + 2);
	if(buffer_file) {
		sprintf(buffer_file, "%s=%s", ENV_FILE, filename);
		env[j++] = buffer_file;
	}

	buffer_vir = (char *) malloc(strlen(ENV_VIRUS) + strlen(virname) + 2);
	if(buffer_vir) {
		sprintf(buffer_vir, "%s=%s", ENV_VIRUS, virname);
		env[j++] = buffer_vir;
	}
	env[j++] = NULL;

	cmd = strdup(opt->strarg);

	if(cmd && (pt = strstr(cmd, "%v"))) {
		buffer = (char *) malloc(strlen(cmd) + strlen(virname) + 10);
		if(buffer) {
			*pt = 0; pt += 2;
			strcpy(buffer, cmd);
			strcat(buffer, virname);
			strcat(buffer, pt);
			free(cmd);
			cmd = strdup(buffer);
			free(buffer);
		}
	}

	if(!cmd) {
		free(buffer_file);
		free(buffer_vir);
		return;
	}
	pthread_mutex_lock(&virusaction_lock);
	/* We can only call async-signal-safe functions after fork(). */
	pid = fork();

	if ( pid == 0 ) {
		/* child... */
		/* WARNING: this is uninterruptable ! */
		exit(execle("/bin/sh", "sh", "-c", cmd, NULL, env));
	} else if (pid > 0) {
		pthread_mutex_unlock(&virusaction_lock);
		/* parent */
		waitpid(pid, NULL, 0);
	} else {
		pthread_mutex_unlock(&virusaction_lock);
		/* error.. */
		logg("!VirusAction: fork failed.\n");
	}
	free(cmd);
	free(buffer_file);
	free(buffer_vir);
}
#endif /* C_WINDOWS */

int poll_fds(int *fds, int nfds, int timeout_sec, int check_signals)
{
	int retval;
	int i;
#ifdef HAVE_POLL
	struct pollfd poll_1[1];
	struct pollfd *poll_data = poll_1;

    if (nfds>1) {
	poll_data = malloc(nfds*sizeof(*poll_data));
	if(!poll_data) {
	    logg("!poll_fds: Can't allocate memory for poll_data\n");
	    return -1;
	}
    }

    for (i=0; i<nfds; i++) {
	poll_data[i].fd = fds[i];
	poll_data[i].events = POLLIN;
	poll_data[i].revents = 0;
    }

    if (timeout_sec > 0) {
    	timeout_sec *= 1000;
    }
    while (1) {
    	retval = poll(poll_data, nfds, timeout_sec);
	if (retval == -1) {
	    if (errno == EINTR && !check_signals) {
		continue;
	    }
	    if (nfds>1)
		free(poll_data);
	    return -1;
	}
	if (nfds>1) {
	    if (retval>0) {
		for (i=0; i<nfds; i++) {
		    if (poll_data[i].revents) {
			retval = i+1;
			break;
		    }
		}
	    }
	    free(poll_data);
	}
	return retval;
    }

#else
	fd_set rfds;
	struct timeval tv;
	int maxfd = 0;

    for (i=0; i<nfds; i++) {
#ifndef	C_WINDOWS
	if (fds[i] >= DEFAULT_FD_SETSIZE) {
	    return -1;
	}
#endif
	if (fds[i] > maxfd)
	    maxfd = fds[i];
    }

    while (1) {
	FD_ZERO(&rfds);
	for (i=0; i<nfds; i++)
	    FD_SET(fds[i], &rfds);
	tv.tv_sec = timeout_sec;
	tv.tv_usec = 0;

	retval = select(maxfd+1, &rfds, NULL, NULL,
			(timeout_sec>0 ? &tv : NULL));
	if (retval == -1) {
	    if (errno == EINTR && !check_signals) {
		continue;
	    }
	    return -1;
	}
	if ((nfds>1) && (retval>0)) {
	    for (i=0; i<nfds; i++) {
		if (FD_ISSET(fds[i],&rfds)) {
		    retval = i+1;
		    break;
		}
	    }
	}
	return retval;
    }
#endif

    return -1;
}

int poll_fd(int fd, int timeout_sec, int check_signals)
{
    return poll_fds(&fd, 1, timeout_sec, check_signals);
}

int is_fd_connected(int fd)
{
#ifdef HAVE_POLL
	struct pollfd poll_data[1];
	int count;

    poll_data[0].fd = fd;
    poll_data[0].events = POLLIN;
    poll_data[0].revents = 0;

    if ((count=poll(poll_data, 1, 0)) == -1) {
    	if (errno == EINTR) {
		return 1;
	}
	return 0;
    }
    if (count == 0) {
    	return 1;
    }
    if (poll_data[0].revents & POLLHUP) {
	return 0;
    }
    if ((poll_data[0].revents & POLLIN) && (ioctl(fd, FIONREAD, &count) == 0)) {
    	if (count == 0) {
		return 0;
	}
    }
    return 1;

#else
	fd_set rfds;
	struct timeval tv;
	char buff[1];

#ifndef	C_WINDOWS
    if (fd >= DEFAULT_FD_SETSIZE) {
        return 1;
    }
#endif

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (select(fd+1, &rfds, NULL, NULL, &tv) <= 0) {
	return 1;
    }
    if (FD_ISSET(fd, &rfds)) {
	if (recv(fd, buff, 1, MSG_PEEK) != 1) {
	    return 0;
	}
    }
    return 1;
#endif
}

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

/* FD Support Submitted by Richard Lyons <frob-clamav*webcentral.com.au> */
/*
   This procedure does timed clamd command and delimited input processing.  
   It is complex for several reasons:
       2) Newline delimited commands are indicated by a command which is prefixed by an 'n' character.  
          This character serves to indicate that the command will contain a newline which will cause
          command data to be read until the command input buffer is full or a newline is encountered.
          Once the delimiter is encountered, the data is returned without the prefixing 'n' byte.
       3) Legacy clamd clients presented commands which may or may not have been delimited by a newline.
          If a command happens to be delimted by a newline, then only that command (and its newline) is
          read and passed back, otherwise, all data read (in a single read) which fits in the specified
          buffer will be returned.
*/
int readsock(int sockfd, char *buf, size_t size, unsigned char delim, int timeout_sec, int force_delim, int read_command)
{
	ssize_t n;
	size_t boff = 0;
	char *pdelim;
	time_t starttime, timenow;

    time(&starttime);
    while(1) {
	time(&timenow);
	switch(poll_fd(sockfd, (timeout_sec && ((timeout_sec-(timenow-starttime)) > 0)) ? timeout_sec-(timenow-starttime) : 0, 0)) {
	    case 0: /* timeout */
		return -2;
	    case -1:
		if(errno == EINTR)
		    continue;
		return -1;
	}
	break;
    }
    n = recv(sockfd, buf, size, MSG_PEEK);
    if(n < 0)
	return -1;
    if(read_command) {
	if((n >= 1) && (buf[0] == 'n')) { /* Newline delimited command */
	    force_delim = 1;
	    delim = '\n';
	}
    }
    while(boff < size) {
	if(force_delim) {
	    pdelim = memchr(buf, delim, n+boff);
	    if(pdelim) {
		n = recv(sockfd, buf+boff, pdelim-buf+1-boff, 0);
		break;
	    } else {
		n = recv(sockfd, buf+boff, n, 0);
		if(n < 0)
		    return -1;
		if((boff+n) == size)
		    break;
		boff += n;
	    }
	} else {
	    pdelim = memchr(buf, delim, n+boff);
	    if(pdelim)
		n = recv(sockfd, buf+boff, pdelim-buf+1-boff, 0);
	    else
		n = recv(sockfd, buf+boff, size-boff, 0);
	    break;
	}
	while(1) {
	    time(&timenow);
	    switch(poll_fd(sockfd, ((timeout_sec-(timenow-starttime)) > 0) ? timeout_sec-(timenow-starttime) : 0, 0)) {
		case 0: /* timeout */
		    return -2;
		case -1:
		    if(errno == EINTR)
			continue;
		    return -1;
	    }
	    break;
	}
        n = recv(sockfd, buf+boff, size-boff, MSG_PEEK);
	if(n < 0)
	    return -1;
	if(n == 0)
	    break;
    }
    if(n < 0)
	return -1;
    n += boff;
    if(read_command) {
	if((n >= 1) && (buf[0] == 'n')) { /* Need to strip leading 'n' from command to attain standard command */
	    --n;
	    memcpy(buf, buf+1, n);
	    buf[n] = '\0';
	}
	return !strncmp(buf, "FD", 2) ? -1 : n; /* an explicit FD command is invalid */
    }
    return n;
}


static int realloc_polldata(struct fd_data *data)
{
#ifdef HAVE_POLL
    if (data->poll_data)
	free(data->poll_data);
    data->poll_data = malloc(data->nfds*sizeof(*data->poll_data));
    if (!data->poll_data) {
	logg("!realloc_polldata: Memory allocation failed for poll_data\n");
	return -1;
    }
#endif
    return 0;
}

static void cleanup_fds(struct fd_data *data)
{
    struct fd_buf *newbuf;
    unsigned i,j, ok = 0;
    for (i=0,j=0;i < data->nfds; i++) {
	if (data->buf[i].fd < 0)
	    continue;
	if (i != j)
	    data->buf[j++] = data->buf[i];
	ok++;
    }
    while (j < data->nfds)
	data->buf[j++].fd = -1;
    /* Shrink buffer */
    newbuf = realloc(data->buf, ok*sizeof(*newbuf));
    if (newbuf)
	data->buf = newbuf;/* non-fatal if shrink fails */
}

static int read_fd_data(struct fd_buf *buf)
{
    if (!buf->buffer) /* listen-only socket */
	return 0;
   /* Read the pending packet, it may contain more than one command, but
    * that is to the cmdparser to handle. 
    * It will handle 1st command, and then move leftover to beginning of buffer
    */
   ssize_t n = recv(buf->fd, buf->buffer + buf->off, buf->bufsize - buf->off,0);
   if (n < 0)
       return -1;
   buf->off += n;
   buf->got_newdata=1;
}

int fds_add(struct fd_data *data, int fd, int listen_only)
{
    struct fd_buf *buf;
    unsigned  n = data->nfds + 1;
    if (fd < 0) {
	logg("!add_fd: invalid fd passed to add_fd\n");
	return -1;
    }
    buf = realloc(data->buf, n*sizeof(*buf));
    if (!buf) {
	logg("!add_fd: Memory allocation failed for fd_buf\n");
	return -1;
    }
    data->buf = buf;
    data->nfds = n;
    data->buf[n-1].fd = -1;
    if (!listen_only) {
	data->buf[n-1].bufsize = PATH_MAX+8;
	if (!(data->buf[n-1].buffer = malloc(data->buf[n-1].bufsize))) {
	    logg("!add_fd: Memory allocation failed for command buffer\n");
	    return -1;
	}
    } else {
	data->buf[n-1].bufsize = 0;
	data->buf[n-1].buf = NULL;
    }
    data->buf[n-1].fd = fd;
    data->buf[n-1].off = 0;
    data->buf[n-1].got_newdata = 0;
    return realloc_polldata(data);
}

/* Wait till data is available to be read on any of the fds,
 * read available data on all fds, and mark them as appropriate.
 * One of the fds should be a pipe, used by the accept thread to wake us.
 * timeout is specified in seconds, if check_signals is non-zero, then
 * poll_recv_fds() will return upon receipt of a signal, even if no data
 * is received on any of the sockets.
 * Must be called with buf_mutex held.
 */
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

    if (!data->poll_data) {
	data->poll_data = malloc(data->nfds*sizeof(*data->poll_data));
    }
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
	    for (i=0;i < data->nfds; i++) {
		short revents;
		if (data->buf[i].fd < 0)
		    continue;
		revents = data->poll_data[i].revents;
		if (revents & POLLIN) {
		    /* Data available to be read */
		    if (read_fd_data(&data->buf[i]) == -1)
			revents |= POLLERR;
		}

		if (revents & (POLLHUP | POLLERR)) {
		    if (revents & POLLHUP) {
			/* remote disconnected */
			logg("!poll_recv_fds: Client disconnected\n");
		    } else {
			/* error on file descriptor */
			logg("!poll_recv_fds: Error condition on fd %d\n",
			     data->poll_data[i].fd);
		    }
		    data->buf[i].fd = -1;
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
		if (data->buf[i].fd < 0)
		    continue;
		if (FD_ISSET(data->buf[i].fd, &rfds))
		    if (read_fd_data(&data->buf[i] == -1)) {
			logg("!poll_recv_fds: Error condition on fd %d\n",
			     data->buf[i].fd);
			data->buf[i].fd = -1;
			fdsok--;
		    }
	    }
	}
    } while (retval == -1 && !check_signals && errno == EINTR);
#endif

    if (retval == -1) {
#ifdef HAVE_POLL
	logg("!poll_recv_fds: poll failed\n");
#else
	logg("!poll_recv_fds: select failed\n");
#endif
    }

    /* Remove closed / error fds */
    if (fdsok != data->nfds)
	cleanup_fds(data);
    return retval;
}

void fds_free(struct fd_data *data)
{
    if (data->buf)
	free(data->buf);
#ifdef HAVE_POLL
    if (data->poll_data)
	free(data->poll_data);
#endif
}
