/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifndef __TREEWALK_H
#define __TREEWALK_H

#include <pwd.h>
#include <clamav.h>

#include "options.h"

struct s_du {
    int files;
    long int space; /* in kilobytes */
};

int treewalk(const char *dirname, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, int options, unsigned int depth);

int rmdirs(const char *dirname);
int clamav_rmdirs(const char *dir);
int fixperms(const char *dirname);
int du(const char *dirname, struct s_du *n);

#endif
