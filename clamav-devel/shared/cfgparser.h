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

#ifndef __CFGPARSER_H
#define __CFGPARSER_H

#define LINE_LENGTH 1024


#define OPT_STR 1 /* string argument */
#define OPT_NUM 2 /* numerical argument */
#define OPT_COMPSIZE 3 /* convert kilobytes (k) and megabytes (m) to bytes */
#define OPT_NOARG 4 /* no argument */
#define OPT_OPTARG 5 /* argument is optional, it's registered as string */
#define OPT_FULLSTR 6 /* string argument, but get a full line */

struct cfgoption {
    const char *name;
    int argtype;
};

struct cfgstruct {
    char *optname;
    char *strarg;
    int numarg;
    struct cfgstruct *nextarg;
    struct cfgstruct *next;
};


struct cfgstruct *parsecfg(const char *cfgfile, int messages);

struct cfgstruct *regcfg(struct cfgstruct *copt, char *optname, char *strarg, int numarg);

struct cfgstruct *cfgopt(const struct cfgstruct *copt, const char *optname);

void freecfg(struct cfgstruct *copt);

#endif
