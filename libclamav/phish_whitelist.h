/*
 *  Phishing module: whitelist implementation.
 *
 *  Copyright (C) 2006 Török Edvin <edwintorok@gmail.com>
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
 *
 */

#ifndef _WHITELIST_H
#define _WHITELIST_H

int cli_loadwdb(FILE* fd, unsigned int options);
int build_whitelist(void);
int init_whitelist(void);
void whitelist_done(void);
void whitelist_cleanup(void);
int is_whitelist_ok(void);
int whitelist_match(const char* real_url,const char* display_url,int hostOnly);

#endif
