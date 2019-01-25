/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog
 * 
 *  Summary: Extract component parts of OLE2 files (e.g. MS Office Documents).
 * 
 *  Acknowledgements: Some ideas and algorithms were based upon OpenOffice and libgsf.
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

#ifndef __OLE2_EXTRACT_H
#define __OLE2_EXTRACT_H

#include "others.h"
#include "uniq.h"

int cli_ole2_extract(const char *dirname, cli_ctx *ctx, struct uniq **);

#endif
