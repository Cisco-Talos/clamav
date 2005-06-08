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

#ifndef __MANAGER_H
#define __MANAGER_H

#include <clamav.h>
#include <pwd.h>
#include "options.h"

int scanmanager(const struct optstruct *opt);

int scanfile(const char *filename, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, int options);

int scancompressed(const char *filename, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, int options);

int scandenied(const char *filename, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, int options);

int scandirs(const char *dirname, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, int options);

int checkfile(const char *filename, const struct cl_node *root, const struct cl_limits *limits, int options, short printclean);

int checkstdin(const struct cl_node *root, const struct cl_limits *limits, int options);

#ifdef CLAMSCAN_THREADS
 int thr_exitno, thr_pid;
 void thr_exit(int sig);
#endif

int clamav_unpack(const char *prog, char **args, const char *tmpdir, const struct passwd *user, const struct optstruct *opt);

void move_infected(const char *filename, const struct optstruct *opt);

#endif
