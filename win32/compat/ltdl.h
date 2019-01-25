/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __LTDL_H
#define __LTDL_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

typedef HANDLE lt_dlhandle;

int lt_dlinit(void);
lt_dlhandle lt_dlopen(const char *filename);
void *lt_dlsym(lt_dlhandle handle, const char *name);
const char *lt_dlerror(void);
int lt_dlclose (lt_dlhandle handle);
int lt_dladdsearchdir(const char *search_dir);
const char *lt_dlgetsearchpath(void);

typedef	struct {
  char *	filename;	/* file name */
  char *	name;		/* module name */
  int		ref_count;	/* number of times lt_dlopened minus
				   number of times lt_dlclosed. */
  unsigned int	is_resident:1;	/* module can't be unloaded. */
  unsigned int	is_symglobal:1;	/* module symbols can satisfy
				   subsequently loaded modules.  */
  unsigned int	is_symlocal:1;	/* module symbols are only available
				   locally. */
} lt_dlinfo;
const lt_dlinfo *lt_dlgetinfo(lt_dlhandle handle);

#endif /* __LTDL_H */