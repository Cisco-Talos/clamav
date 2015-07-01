/*
 *  Copyright (C) 2004 Trog <trog@uncon.org>
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
 
#ifndef __VBA_H
#define __VBA_H

#include "libclamav/uniq.h"
#include "libclamav/others.h"

int sigtool_vba_scandir(const char *dirname, int hex_output, struct uniq *U);
cli_ctx *convenience_ctx(int fd);
void destroy_ctx(int desc, cli_ctx *ctx);

#endif
