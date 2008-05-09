/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __SESSION_H
#define __SESSION_H

#define COMMAND_SHUTDOWN 1
#define COMMAND_RELOAD 2
#define COMMAND_END 3
#define COMMAND_SESSION 4

#define CMD1 "SCAN"
/* #define CMD2 "RAWSCAN" */
#define CMD3 "QUIT" /* deprecated */
#define CMD4 "RELOAD"
#define CMD5 "PING"
#define CMD6 "CONTSCAN"
#define CMD7 "VERSION"
#define CMD8 "STREAM"
#define CMD9 "SESSION"
#define CMD10 "END"
#define CMD11 "SHUTDOWN"
/* #define CMD12 "FD" */
#define CMD13 "MULTISCAN"
#define CMD14 "FILDES"

#include "libclamav/clamav.h"
#include "shared/cfgparser.h"

int command(int desc, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, const struct cfgstruct *copt, int timeout);

#endif
