/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __GLOBAL_H
#define __GLOBAL_H

struct s_info {
    unsigned int sigs;      /* number of signatures */
    unsigned int dirs;      /* number of scanned directories */
    unsigned int files;     /* number of scanned files */
    unsigned int ifiles;    /* number of infected files */
    unsigned int errors;    /* number of errors */
    uint64_t bytes_scanned; /* number of *scanned* bytes */
    uint64_t bytes_read;    /* number of *read* bytes */
};

extern struct s_info info;
extern short recursion, bell;
extern short printinfected, printclean;

#endif
