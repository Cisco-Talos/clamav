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

#ifndef __OPTIONS_H
#define __OPTIONS_H

struct optnode {
    char optchar;
    char *optarg;
    char *optname;
    struct optnode *next;
};

struct optstruct {
    struct optnode *optlist;
    char *filename;
};

int optc(const struct optstruct *opt, char ch);
int optl(const struct optstruct *opt, const char *optname);
void register_char_option(struct optstruct *opt, char ch, const char *longname);
void register_long_option(struct optstruct *opt, const char *optname);
char *getargc(const struct optstruct *opt, char ch);
char *getfirstargc(const struct optstruct *opt, char ch, struct optnode **optnode);
char *getnextargc(struct optnode **optnode, char ch);
char *getargl(const struct optstruct *opt, const char *optname);
char *getfirstargl(const struct optstruct *opt, const char *optname, struct optnode **optnode);
char *getnextargl(struct optnode **optnode, const char *optname);
void free_opt(struct optstruct *opt);

#endif
