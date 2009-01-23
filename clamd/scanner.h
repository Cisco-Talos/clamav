/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __SCANNER_H
#define __SCANNER_H

#define TYPE_SCAN	0
#define TYPE_CONTSCAN	1
#define TYPE_MULTISCAN	2

#include "libclamav/clamav.h"
#include "shared/optparser.h"

int scan(const char *filename, const char term, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, int odesc, unsigned int type);

int scanfd(const int fd, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, int odesc);

int scanstream(int odesc, unsigned long int *scanned, const struct cl_engine *engine, unsigned int options, const struct optstruct *opts, char term);

#endif
