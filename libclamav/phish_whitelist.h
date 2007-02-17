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

#ifdef CL_EXPERIMENTAL

#ifndef _PHISH_WHITELIST_H
#define _PHISH_WHITELIST_H

int init_whitelist(struct cl_engine* engine);
void whitelist_done(struct cl_engine* engine);
void whitelist_cleanup(const struct cl_engine* engine);
int is_whitelist_ok(const struct cl_engine* engine);
int whitelist_match(const struct cl_engine* engine, const char* real_url,const char* display_url,int hostOnly);

#endif

#endif
