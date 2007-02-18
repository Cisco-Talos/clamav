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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __CLAMD_OTHERS_H
#define __CLAMD_OTHERS_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include "cfgparser.h"

int poll_fd(int fd, int timeout_sec);
int is_fd_connected(int fd);
void virusaction(const char *filename, const char *virname, const struct cfgstruct *copt);
int writen(int fd, void *buff, unsigned int count);

#if defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR)) && !defined(C_CYGWIN) && !defined(C_OS2) && !defined(INCOMPLETE_CMSG)
int readsock(int sockfd, char *buf, size_t size);
#else
#define	readsock	read
#endif

#endif
