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
 * $Log: line.c,v $
 * Revision 1.11  2007/02/12 20:46:08  njh
 * Various tidy
 *
 * Revision 1.10  2006/04/09 19:59:27  kojm
 * update GPL headers with new address for FSF
 *
 * Revision 1.9  2005/03/10 08:53:33  nigelhorne
 * Tidy
 *
 * Revision 1.8  2005/03/01 11:38:11  nigelhorne
 * Fix typo
 *
 * Revision 1.7  2004/12/08 20:07:23  nigelhorne
 * Fix compilation error on Solaris
 *
 * Revision 1.6  2004/10/14 17:45:55  nigelhorne
 * Try to reclaim some memory if it becomes low when decoding
 *
 * Revision 1.5  2004/09/30 08:58:56  nigelhorne
 * Remove empty lines
 *
 * Revision 1.4  2004/09/21 14:55:26  nigelhorne
 * Handle blank lines in text/plain messages
 *
 * Revision 1.3  2004/08/25 12:30:36  nigelhorne
 * Use memcpy rather than strcpy
 *
 * Revision 1.2  2004/08/21 11:57:57  nigelhorne
 * Use line.[ch]
 *
 * Revision 1.1  2004/08/20 11:58:20  nigelhorne
 * First draft
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "clamav.h"
#include "line.h"
#include "others.h"

line_t *
lineCreate(const char *data)
{
	const size_t size = strlen(data);
	line_t *ret = (line_t *)cli_malloc(size + 2);

    if(ret == NULL) {
        cli_errmsg("lineCreate: Unable to allocate memory for ret\n");
        return (line_t *)NULL;
    }

	ret[0] = (char)1;
	/*strcpy(&ret[1], data);*/
	memcpy(&ret[1], data, size);
	ret[size + 1] = '\0';

	return ret;
}

line_t *
lineLink(line_t *line)
{
	assert(line != NULL);
	if((unsigned char)line[0] == (unsigned char)255) {
		cli_dbgmsg("lineLink: linkcount too large (%s)\n", lineGetData(line));
		return lineCreate(lineGetData(line));
	}
	line[0]++;
	/*printf("%d:\n\t'%s'\n", (int)line[0], &line[1]);*/
	return line;
}

line_t *
lineUnlink(line_t *line)
{
	/*printf("%d:\n\t'%s'\n", (int)line[0], &line[1]);*/

	if(--line[0] == 0) {
		free(line);
		return NULL;
	}
	return line;
}

const char *
lineGetData(const line_t *line)
{
	return line ? &line[1] : NULL;
}
