/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __SESSION_H
#define __SESSION_H

#define COMMAND_SHUTDOWN 1
#define COMMAND_RELOAD 2
#define COMMAND_END 3
#define COMMAND_SESSION 4

#define CMD1 "SCAN"
#define CMD2 "RAWSCAN"
#define CMD3 "QUIT" /* deprecated */
#define CMD4 "RELOAD"
#define CMD5 "PING"
#define CMD6 "CONTSCAN"
#define CMD7 "VERSION"
#define CMD8 "STREAM"
#define CMD9 "SESSION"
#define CMD10 "END"
#define CMD11 "SHUTDOWN"
#define CMD12 "FD"

#include <clamav.h>
#include "cfgparser.h"

int command(int desc, const struct cl_node *root, const struct cl_limits *limits, int options, const struct cfgstruct *copt, int timeout);

#endif
