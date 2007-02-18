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

#ifndef __SHARED_H
#define __SHARED_H

struct s_info {
    unsigned int sigs; /* number of signatures loaded */
    unsigned int dirs; /* number of scanned directories */
    unsigned int files; /* number of scanned files */
    unsigned int ifiles; /* number of infected files */
    unsigned int notremoved; /* number of not removed files (if --remove) */
    unsigned int notmoved; /* number of not moved files (if --move) */
    unsigned int errors; /*  ... of errors */
    unsigned long int blocks; /* number of read 16kb blocks */
};

extern struct s_info claminfo;
extern short recursion, printinfected, bell;

#endif
