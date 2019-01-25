/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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
 *
 * $Log: text.h,v $
 * Revision 1.9  2006/07/01 16:17:35  njh
 * Added destroy flag
 *
 * Revision 1.8  2006/04/09 19:59:28  kojm
 * update GPL headers with new address for FSF
 *
 * Revision 1.7  2004/12/04 16:03:55  nigelhorne
 * Text/plain now handled as no encoding
 *
 * Revision 1.6  2004/08/22 10:34:24  nigelhorne
 * Use fileblob
 *
 * Revision 1.5  2004/08/21 11:57:57  nigelhorne
 * Use line.[ch]
 *
 * Revision 1.4  2004/07/20 14:35:29  nigelhorne
 * Some MYDOOM.I were getting through
 *
 * Revision 1.3  2004/06/22 04:08:02  nigelhorne
 * Optimise empty lines
 *
 */

#ifndef __TEXT_H
#define __TEXT_H

/* The contents could change, ONLY access in text.c */
typedef struct text {
	line_t	*t_line;	/* NULL if the line is empty */
	struct	text	*t_next;
} text;

#include "message.h"

void	textDestroy(text *t_head);
text	*textAddMessage(text *aText, message *aMessage);
text	*textMove(text *t_head, text *t);
blob	*textToBlob(text *t, blob *b, int destroy);
fileblob	*textToFileblob(text *t, fileblob *fb, int destroy);

#endif /* __TEXT_H */
