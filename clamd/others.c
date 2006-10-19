/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

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

#include "shared/memory.h"
#include "shared/cfgparser.h"
#include "shared/output.h"

#include "session.h"
#include "others.h"

#define ENV_FILE  "CLAM_VIRUSEVENT_FILENAME"
#define ENV_VIRUS "CLAM_VIRUSEVENT_VIRUSNAME"

#ifdef	C_WINDOWS
void virusaction(const char *filename, const char *virname, const struct cfgstruct *copt)
{
    if(cfgopt(copt, "VirusEvent")->enabled)
	logg("^VirusEvent is not supported on this platform");	/* Yet */
}

#else

void virusaction(const char *filename, const char *virname, const struct cfgstruct *copt)
{
	pid_t pid;
	struct cfgstruct *cpt;

    if(!(cpt = cfgopt(copt, "VirusEvent"))->enabled)
	return;

    /* NB: we need to fork here since this function modifies the environment. 
       (Modifications to the env. are not reentrant, but we need to be.) */
    pid = fork();

    if ( pid == 0 ) {
	/* child... */
	char *buffer, *pt, *cmd;

	cmd = strdup(cpt->strarg);

	if((pt = strstr(cmd, "%v"))) {
	    buffer = (char *) mcalloc(strlen(cmd) + strlen(virname) + 10, sizeof(char));
	    *pt = 0; pt += 2;
	    strcpy(buffer, cmd);
	    strcat(buffer, virname);
	    strcat(buffer, pt);
	    free(cmd);
	    cmd = strdup(buffer);
	    free(buffer);
	}
	
	/* Allocate env vars.. to be portable env vars should not be freed */
	buffer = (char *) mcalloc(strlen(ENV_FILE) + strlen(filename) + 2, sizeof(char));
	sprintf(buffer, "%s=%s", ENV_FILE, filename);
	putenv(buffer);

	buffer = (char *) mcalloc(strlen(ENV_VIRUS) + strlen(virname) + 2, sizeof(char));
	sprintf(buffer, "%s=%s", ENV_VIRUS, virname);
	putenv(buffer);
	
    
	/* WARNING: this is uninterruptable ! */
	exit(system(cmd));
	
	/* The below is not reached but is here for completeness to remind
	   maintainers that this buffer is still allocated.. */
	free(cmd);
    } else if (pid > 0) {
	/* parent */      
	waitpid(pid, NULL, 0);
    } else {
	/* error.. */
	logg("!VirusAction: fork failed.\n");
    }
}
#endif /* C_WINDOWS */

int poll_fds(int *fds, int nfds, int timeout_sec)
{
	int retval;
	int i;
#ifdef HAVE_POLL
	struct pollfd poll_1[1];
	struct pollfd *poll_data = poll_1;

    if (nfds>1) {
	poll_data = mmalloc(nfds*sizeof(*poll_data));
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
   	    if (errno == EINTR) {
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
	    if (errno == EINTR) {
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

int poll_fd(int fd, int timeout_sec)
{
    return poll_fds(&fd, 1, timeout_sec);
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
       1) FD commands are delivered on Unix domain sockets via recvnsg() on platforms which can do this.  
          These command messages are accompanied by a single byte of data which is a NUL character.
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
	int fd;
	ssize_t n;
	size_t boff = 0;
	char *pdelim;
	struct msghdr msg;
	struct iovec iov[1];
#ifdef HAVE_CONTROL_IN_MSGHDR
#ifndef CMSG_SPACE
#define CMSG_SPACE(len)	    (_CMSG_ALIGN(sizeof(struct cmsghdr)) + _CMSG_ALIGN(len))
#endif
#ifndef CMSG_LEN
#define CMSG_LEN(len)	    (_CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif
	struct cmsghdr *cmsg;
	char tmp[CMSG_SPACE(sizeof(fd))];
#endif
	time_t starttime, timenow;

    time(&starttime);
    while(1) {
	time(&timenow);
	switch(poll_fd(sockfd, (timeout_sec && ((timeout_sec-(timenow-starttime)) > 0)) ? timeout_sec-(timenow-starttime) : 0)) {
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
    if(read_command) {
    	if((n >= 1) && (buf[0] == 0)) { /* FD message */
	    iov[0].iov_base = buf;
	    iov[0].iov_len = size;
	    memset(&msg, 0, sizeof(msg));
	    msg.msg_iov = iov;
	    msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	    msg.msg_accrights = (caddr_t)&fd;
	    msg.msg_accrightslen = sizeof(fd);
#endif
#ifdef HAVE_CONTROL_IN_MSGHDR
	    msg.msg_control = tmp;
	    msg.msg_controllen = sizeof(tmp);
#endif
#if defined(HAVE_RECVMSG) && !defined(C_OS2) && !defined(INCOMPLETE_CMSG)
	    n = recvmsg(sockfd, &msg, 0);
#else
	    n = recv(sockfd, buf, size, 0);
#endif
	    if (n <= 0)
		return n;
	    errno = EBADF;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	    if(msg.msg_accrightslen != sizeof(fd))
		return -1;
#endif
#ifdef HAVE_CONTROL_IN_MSGHDR
	    cmsg = CMSG_FIRSTHDR(&msg);
	    if(cmsg == NULL)
		return -1;
	    if(cmsg->cmsg_type != SCM_RIGHTS)
		return -1;
	    if(cmsg->cmsg_len != CMSG_LEN(sizeof(fd)))
		return -1;
	    fd = *(int *)CMSG_DATA(cmsg);
#endif
	    if(fd < 0)
		return -1;
	    n = snprintf(buf, size, "FD %d", fd);
	    if((size_t) n >= size)
		return -1;
	    return n;
	}
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
	    switch(poll_fd(sockfd, ((timeout_sec-(timenow-starttime)) > 0) ? timeout_sec-(timenow-starttime) : 0)) {
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
