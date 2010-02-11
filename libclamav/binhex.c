/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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
 * Change History:
 * $Log: binhex.c,v $
 * Revision 1.23  2007/02/12 20:46:08  njh
 * Various tidy
 *
 * Revision 1.22  2006/07/31 09:19:52  njh
 * Use MAP_PRIVATE
 *
 * Revision 1.21  2006/07/01 16:17:35  njh
 * Added destroy flag
 *
 * Revision 1.20  2006/07/01 03:47:50  njh
 * Don't loop if binhex runs out of memory
 *
 * Revision 1.19  2006/05/19 11:02:12  njh
 * Just include mbox.h
 *
 * Revision 1.18  2006/04/09 19:59:27  kojm
 * update GPL headers with new address for FSF
 *
 * Revision 1.17  2005/11/06 14:03:26  nigelhorne
 * Ensure NAME_MAX isn't redefined on BeOS
 *
 * Revision 1.16  2005/05/14 16:13:25  nigelhorne
 * Ensure munmap is the right size
 *
 * Revision 1.15  2005/05/13 19:30:34  nigelhorne
 * Clean cli_realloc call
 *
 * Revision 1.14  2005/03/10 08:51:30  nigelhorne
 * Tidy
 *
 * Revision 1.13  2005/01/19 05:29:41  nigelhorne
 * tidy
 *
 * Revision 1.12  2004/12/27 14:17:14  nigelhorne
 * Fix segfault if write to temporary file fails
 *
 * Revision 1.11  2004/12/17 12:03:38  nigelhorne
 * Tidy up for machines without MMAP
 *
 * Revision 1.10  2004/12/16 15:29:51  nigelhorne
 * Tidy
 *
 * Revision 1.9  2004/11/28 22:06:39  nigelhorne
 * Tidy space only headers code
 *
 * Revision 1.8  2004/11/28 21:05:50  nigelhorne
 * Handle headers with only spaces
 *
 * Revision 1.7  2004/11/23 09:05:26  nigelhorne
 * Fix crash in base64 encoded binhex files
 *
 * Revision 1.6  2004/11/22 15:16:53  nigelhorne
 * Use cli_realloc instead of many cli_mallocs
 *
 * Revision 1.5  2004/11/18 20:11:34  nigelhorne
 * Fix segfault
 *
 * Revision 1.4  2004/11/18 19:30:29  kojm
 * add support for Mac's HQX file format
 *
 * Revision 1.3  2004/11/18 18:24:45  nigelhorne
 * Added binhex.h
 *
 * Revision 1.2  2004/11/18 18:09:06  nigelhorne
 * First draft of binhex.c
 *
 */
static	char	const	rcsid[] = "$Id: binhex.c,v 1.23 2007/02/12 20:46:08 njh Exp $";

#include "clamav.h"

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CL_THREAD_SAFE
#ifndef	_REENTRANT
#define	_REENTRANT	/* for Solaris 2.8 */
#endif
#endif

#include <stdio.h>
#include <memory.h>
#include <sys/stat.h>
#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif

#include "others.h"
#include "mbox.h"
#include "binhex.h"
#include "fmap.h"

int
cli_binhex(const char *dir, fmap_t *map)
{
	char *buf, *start, *line;
	size_t size;
	long bytesleft;
	message *m;
	fileblob *fb;
	text *t_line;

	size = (size_t)map->len;

	if(size == 0)
		return CL_CLEAN;

	m = messageCreate();
	if(m == NULL)
		return CL_EMEM;

	start = buf = fmap_need_off_once(map, 0, size);
	if(!buf) {
		messageDestroy(m);
		return CL_EMAP;
	}

	cli_dbgmsg("mmap'ed binhex file\n");

	bytesleft = (long)size;
	line = NULL;

	while(bytesleft > 0) {
		int length = bytesleft;
		char *ptr, *newline;

		/*printf("%d: ", bytesleft);*/

		for(ptr = buf; bytesleft && (*ptr != '\n') && (*ptr != '\r'); ptr++) {
			--bytesleft;
		}

		length -= bytesleft;
		/*printf("%d: ", length);*/

		newline = cli_realloc(line, (size_t)(length + 1));
		if(newline == NULL)
			break;

		line = newline;

		memcpy(line, buf, length);
		line[length] = '\0';

		/*puts(line);*/

		if(messageAddStr(m, line) < 0)
			break;

		if((bytesleft > 0) && (*ptr == '\r')) {
			ptr++;
			bytesleft--;
		}
		buf = ++ptr;
		bytesleft--;
	}

	if(line)
		free(line);

	if((t_line = binhexBegin(m)) == NULL) {
		messageDestroy(m);
		cli_dbgmsg("No binhex line found\n");
		return CL_EFORMAT;
	}

	while(((t_line = t_line->t_next) != NULL) && (t_line->t_line == NULL));

	if(!t_line) {
		messageDestroy(m);
		cli_dbgmsg("No binhex data to parse\n");
		return CL_EFORMAT;
	}

	/* similar to binhexMessage */
	messageSetEncoding(m, "x-binhex");

	fb = messageToFileblob(m, dir, 1);
	if(fb) {
		cli_dbgmsg("Binhex file decoded to %s\n", fileblobGetFilename(fb));
		fileblobDestroy(fb);
	} else
		cli_errmsg("Couldn't decode binhex file to %s\n", dir);
	messageDestroy(m);

	if(fb)
		return CL_CLEAN;	/* a lie - but it gets things going */
	/* return CL_EIO; */	/* probably CL_EMEM, but we can't tell at this layer */
	/* TK: CL_EMEM is too generic here and should not be reported for parsing errors */
	return CL_EFORMAT;
}
