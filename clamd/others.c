/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
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

#include "memory.h"
#include "cfgparser.h"

void virusaction(const char *virname, const struct cfgstruct *copt)
{
	char *buffer, *pt, *cmd;
	struct cfgstruct *cpt;


    if(!(cpt = cfgopt(copt, "VirusEvent")))
	return;

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

    /* WARNING: this is uninterruptable ! */
    system(cmd);

    free(cmd);
}

int poll_fd(int fd, int timeout_sec)
{
	int retval;
#ifdef HAVE_POLL
	struct pollfd poll_data[1];

    poll_data[0].fd = fd;
    poll_data[0].events = POLLIN;
    poll_data[0].revents = 0;

    if (timeout_sec > 0) {
    	timeout_sec *= 1000;
    }
    while (1) {
    	retval = poll(poll_data, 1, timeout_sec);
	if (retval == -1) {
   	    if (errno == EINTR) {
		continue;
	    }
	    return -1;
	}
	return retval;
    }

#else
	fd_set rfds;
	struct timeval tv;

    if (fd >= DEFAULT_FD_SETSIZE) {
	return -1;
    }

    while (1) {
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = timeout_sec;
	tv.tv_usec = 0;

	retval = select(fd+1, &rfds, NULL, NULL,
			(timeout_sec>0 ? &tv : NULL));
	if (retval == -1) {
	    if (errno == EINTR) {
		continue;
	    }
	    return -1;
	}
	return retval;
    }
#endif

    return -1;
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

    if (fd >= DEFAULT_FD_SETSIZE) {
        return 1;
    }

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
