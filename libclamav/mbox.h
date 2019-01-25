/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 * 
 *  Acknowledgements: Some ideas came from Stephen White <stephen@earth.li>,
 *                    Michael Dankov <misha@btrc.ru>, Gianluigi Tiesi <sherpya@netfarm.it>,
 *                    Everton da Silva Marques, Thomas Lamy <Thomas.Lamy@in-online.net>,
 *                    James Stevens <James@kyzo.com>
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

#ifndef __MBOX_H
#define __MBOX_H

/* See RFC1521 */
typedef	enum {
	NOMIME, APPLICATION, AUDIO, IMAGE, MESSAGE, MULTIPART, TEXT, VIDEO, MEXTENSION
} mime_type;

typedef enum {
	NOENCODING, QUOTEDPRINTABLE, BASE64, EIGHTBIT, BINARY, UUENCODE, YENCODE, EEXTENSION, BINHEX
} encoding_type;

/* tk: shut up manager.c warning */
#include "clamav.h"

/* classes supported by this system */
typedef enum {
	INVALIDCLASS, BLOBCLASS
} object_type;

#ifdef C_BSD
#define UNIX
#endif

#include "table.h"
#include "blob.h"
#include "line.h"
#include "text.h"
#include "message.h"
#include "uuencode.h"

size_t	strstrip(char *s);	/* remove trailing white space */
int	cli_mbox(const char *dir, cli_ctx *ctx);

#endif /* __MBOX_H */
