/* Dazuko Interface. Interace with Dazuko for file access control.
   Copyright (C) 2002 H+BEDV Datentechnik GmbH
   Written by John Ogness <jogness@antivir.de>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef CLAMUKO

#ifndef DAZUKOIO_H
#define DAZUKOIO_H

#include "dazuko.h"

struct option_t
{
	int	command;
	int	buffer_length;
	char	buffer[DAZUKO_FILENAME_MAX_LENGTH];
};

int dazukoRegister(void);
int dazukoSetAccessMask(unsigned long accessMask);
int dazukoAddIncludePath(const char *path);
int dazukoAddExcludePath(const char *path);
int dazukoRemoveAllPaths(void);
int dazukoGetAccess(struct access_t *acc);
int dazukoReturnAccess(struct access_t *acc);
int dazukoUnregister(void);

#endif
#endif
