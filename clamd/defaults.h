/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifndef __DEFAULTS_H
#define __DEFAULTS_H

#define CL_DEFAULT_CFG CONFDIR"/clamd.conf"
#define CL_DEFAULT_BACKLOG 15
#define CL_DEFAULT_MAXTHREADS 10
#define CL_DEFAULT_SCANTIMEOUT 120
#define CL_DEFAULT_LOGSIZE 1048576
#define CL_DEFAULT_CLAMUKOMAXFILESIZE 5 * 1048576
#define CL_DEFAULT_SELFCHECK 1800
#define CL_DEFAULT_MAXWHILEWAIT 120
#define CL_DEFAULT_MAXPORTSCAN 1000
#define CL_DEFAULT_MAXDIRREC 15
#define CL_DEFAULT_STREAMMAXLEN 10 * 1048576
#define CL_DEFAULT_IDLETIMEOUT 30

#endif
