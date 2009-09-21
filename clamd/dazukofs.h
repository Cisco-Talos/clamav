/* userspace library to interface with dazukofs

   Copyright (C) 2008 John Ogness
     Author: John Ogness <dazukocode@ogness.net>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef __DAZUKOFS_H
#define __DAZUKOFS_H

#include <stdio.h>

/* dazukofs_open() flags */
#define DAZUKOFS_TRACK_GROUP 1

/* dazukofs_close() flags */
#define DAZUKOFS_REMOVE_GROUP 1

struct dazukofs_handle;
typedef struct dazukofs_handle * dazukofs_handle_t;

struct dazukofs_access
{
	int fd;
	int deny;
	unsigned long pid;
};

dazukofs_handle_t dazukofs_open(const char *gname, int flags);
int dazukofs_get_access(dazukofs_handle_t hndl, struct dazukofs_access *acc);
int dazukofs_return_access(dazukofs_handle_t hndl, struct dazukofs_access *acc);
int dazukofs_close(dazukofs_handle_t hndl, int flags);
int dazukofs_get_filename(struct dazukofs_access *acc, char *buf, size_t bufsiz);

#endif /* __DAZUKOFS_H */
