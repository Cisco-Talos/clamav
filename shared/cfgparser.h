/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __CFGPARSER_H
#define __CFGPARSER_H

#define LINE_LENGTH 1024

#define OPT_STR 1 /* string argument */
#define OPT_NUM 2 /* numerical argument */
#define OPT_COMPSIZE 3 /* convert kilobytes (k) and megabytes (m) to bytes */
#define OPT_BOOL 4 /* boolean value */
#define OPT_FULLSTR 5 /* string argument, but get a full line */

struct cfgoption {
    const char *name;
    int argtype;
    int numarg;
    const char *strarg;
    short multiple;
};

struct cfgstruct {
    char *optname;
    char *strarg;
    int numarg;
    short enabled;
    short multiple;
    struct cfgstruct *nextarg;
    struct cfgstruct *next;
};


struct cfgstruct *getcfg(const char *cfgfile, int verbose);

struct cfgstruct *cfgopt(const struct cfgstruct *copt, const char *optname);

void freecfg(struct cfgstruct *copt);

#endif
