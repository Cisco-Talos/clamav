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

#ifndef __NONBLOCK_H
#define __NONBLOCK_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#ifndef	_WIN32
#include <sys/socket.h>
#endif

/*
	wait_connect(): wrapper for connect(), with explicit 'secs' timeout
*/
int wait_connect (int sock, const struct sockaddr *addr, socklen_t addrlen,
                  int secs);

/*
        wait_recv(): wrapper for recv(), with explicit 'secs' timeout
*/
ssize_t wait_recv (int sock, void *buf, size_t len, int flags, int secs);

#endif /* NONBLOCK_H */
