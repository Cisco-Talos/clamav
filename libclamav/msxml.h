/*
 *  Extract component parts of MS XML files (e.g. MS Office 2003 XML Documents)
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Kevin Lin
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

#ifndef __MSXML_H
#define __MSXML_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"

int cli_scanmsxml(cli_ctx *ctx);

#endif /* __MSXML_H */
