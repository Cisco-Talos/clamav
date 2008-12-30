/*
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Author: Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __OPTPARSER_H
#define __OPTPARSER_H

#define OPT_STRING  1	/* quoted/regular string */
#define OPT_NUMBER  2	/* raw number */
#define OPT_SIZE    3	/* number possibly followed by modifers (M/m or K/k) */
#define OPT_BOOL    4	/* boolean */

/* don't share bits! */
#define OPT_CLAMD	1
#define OPT_FRESHCLAM	2
#define OPT_MILTER	4
#define OPT_CLAMSCAN	8
#define OPT_CLAMDSCAN	16
#define OPT_DEPRECATED	32

struct optstruct {
    char *name;
    char *cmd;
    char *strarg;
    int numarg;
    int enabled;
    int active;
    int multiple;
    int idx;
    struct optstruct *nextarg;
    struct optstruct *next;

    char *filename; /* cmdline */
};

const struct optstruct *optget(const struct optstruct *opts, const char *name);

void optfree(struct optstruct *opts);

struct optstruct *optparse(const char *cfgfile, int argc, char * const *argv, int verbose, int toolmask, struct optstruct *oldopts);

#endif
