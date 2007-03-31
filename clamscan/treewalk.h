/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __TREEWALK_H
#define __TREEWALK_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include "libclamav/clamav.h"
#include "shared/options.h"

struct s_du {
    unsigned int files;
    unsigned long int space; /* in kilobytes */
};

int treewalk(const char *dirname, struct cl_engine *engine, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, unsigned int options, unsigned int depth);

int clamav_rmdirs(const char *dir);
int fixperms(const char *dirname);
int du(const char *dirname, struct s_du *n);

#endif
