/*
 *  Phishing module: domain list implementation.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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


#ifndef _PHISH_DOMAINCHECK_DB_H
#define _PHISH_DOMAINCHECK_DB_H
#include "clamav.h"

int init_domainlist(struct cl_engine* engine);
void domainlist_done(struct cl_engine* engine);
void domainlist_cleanup(const struct cl_engine* engine);
int is_domainlist_ok(const struct cl_engine* engine);
int domainlist_match(const struct cl_engine *engine, char* real_url,const char* display_url,const struct pre_fixup_info* pre_fixup, int hostOnly);

#endif

