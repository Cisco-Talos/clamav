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

#ifndef __SHARED_H
#define __SHARED_H

/* some global variables */

struct s_info {
    int signs; /* number of signatures loaded */
    int dirs; /* number of scanned directories */
    int files; /* number of scanned files */
    int ifiles; /* number of infected files */
    int notremoved; /* number of not removed files (if --remove) */
    int notmoved; /* number of not moved files (if --move) */
    int errors; /*  ... of errors */
    long int blocks; /* number of read 16kb blocks */
} claminfo;

short int mprintf_disabled, mprintf_verbose, mprintf_quiet, mprintf_stdout, logverbose, recursion, printinfected, bell;
const char *logfile;

#endif
