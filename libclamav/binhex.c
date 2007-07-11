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

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#ifdef CL_THREAD_SAFE
#ifndef	_REENTRANT
#define	_REENTRANT	/* for Solaris 2.8 */
#endif
#endif

#ifdef	HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#include <stdio.h>
#include <memory.h>
#include <sys/stat.h>
#include "others.h"

#include "mbox.h"
#include "binhex.h"

int
cli_binhex(const char *dir, int desc)
{
#ifndef HAVE_MMAP
	cli_warnmsg("File not decoded - binhex decoding needs mmap() (for now)\n");
	return CL_CLEAN;
#else
	struct stat statb;
	char *buf, *start, *line;
	size_t size;
	long bytesleft;
	message *m;
	fileblob *fb;

	if(fstat(desc, &statb) < 0)
		return CL_EOPEN;

	size = (size_t)statb.st_size;

	if(size == 0)
		return CL_CLEAN;

	m = messageCreate();
	if(m == NULL)
		return CL_EMEM;

	start = buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, desc, 0);
	if(buf == MAP_FAILED) {
		messageDestroy(m);
		return CL_EMEM;
	}

	cli_dbgmsg("mmap'ed binhex file\n");

	bytesleft = (long)size;
	line = NULL;

	while(bytesleft > 0) {
		int length = 0;
		char *ptr, *newline;

		/*printf("%d: ", bytesleft);*/

		for(ptr = buf; bytesleft && (*ptr != '\n') && (*ptr != '\r'); ptr++) {
			length++;
			--bytesleft;
		}

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
	munmap(start, size);

	if(line)
		free(line);

	if(binhexBegin(m) == NULL) {
		messageDestroy(m);
		cli_errmsg("No binhex line found\n");
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
	return CL_EIO;	/* probably CL_EMEM, but we can't tell at this layer */
#endif
}
