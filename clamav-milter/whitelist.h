/*
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008 Sourcefire, Inc.
 *
 *  Author: aCaB <acab@clamav.net>
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

#ifndef _WHITELIST_H
#define _WHITELIST_H

int whitelist_init(const char *fname);
void whitelist_free(void);
int whitelisted(const char *addr, int from);
int smtpauth_init(const char *r);
int smtpauthed(const char *login);
#endif
