/*
 *  Copyright (C) 2004 Nigel Horne <njh@bandsman.co.uk>
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
 *
 * $Log: line.c,v $
 * Revision 1.1  2004/08/20 11:58:20  nigelhorne
 * First draft
 *
 */

static	char	const	rcsid[] = "$Id: line.c,v 1.1 2004/08/20 11:58:20 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "line.h"
#include "others.h"

line_t *
lineCreate(const char *data)
{
	line_t *ret = cli_malloc(sizeof(struct line));

	if(ret == NULL)
		return NULL;

	ret->l_data = strdup(data);
	if(ret->l_data == NULL) {
		free(ret);
		return NULL;
	}
	ret->l_refs = 1;

	return ret;
}

line_t *
lineLink(line_t *line)
{
	line->l_refs++;
	return line;
}

line_t *
lineUnlink(line_t *line)
{
	if(--line->l_refs == 0) {
		free(line->l_data);
		free(line);
		return NULL;
	}
	return line;
}

const char *
lineGetData(const line_t *line)
{
	return line ? line->l_data : NULL;
}
