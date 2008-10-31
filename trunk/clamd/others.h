/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __CLAMD_OTHERS_H
#define __CLAMD_OTHERS_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include "shared/cfgparser.h"

int poll_fds(int *fds, int nfds, int timeout_sec, int check_signals);
int poll_fd(int fd, int timeout_sec, int check_signals);
int is_fd_connected(int fd);
void virusaction(const char *filename, const char *virname, const struct cfgstruct *copt);
int writen(int fd, void *buff, unsigned int count);

int readsock(int sockfd, char *buf, size_t size, unsigned char delim, int timeout_sec, int force_delim, int read_command);

#endif
