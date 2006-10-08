/*
 *  Copyright (C) 2006 Nigel Horne <njh@clamav.net>
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
 * Save the JavaScript embedded in an HTML file, then run the script, saving
 * the output in a file that is to be scanned, then remove the script file
 */
static	char	const	rcsid[] = "$Id: js.c,v 1.1 2006/10/08 10:43:17 njh Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	CL_EXPERIMENTAL

#include "clamav.h"
#include "others.h"
#include <memory.h>
#include <string.h>

#if	HAVE_MMAP

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

static	const	char	*cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns);

int
cli_scanjs(const char *dir, int desc)
{
	struct stat statb;
	off_t size;	/* total number of bytes in the file */
	char *buf;	/* start of memory mapped area */
	const char *p;
	long bytesleft;
	int done_header;

	cli_dbgmsg("in cli_scanjs(%s)\n", dir);

	if(fstat(desc, &statb) < 0)
		return CL_EOPEN;

	size = (size_t)statb.st_size;

	if(size == 0)
		return CL_CLEAN;

	if(size <= 17)	/* doesn't even include <script></script> */
		return CL_EFORMAT;

	p = buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, desc, 0);
	if(buf == MAP_FAILED)
		return CL_EMEM;

	cli_dbgmsg("cli_scanjs: scanning %lu bytes\n", size);

	p = buf;
	bytesleft = size;
	done_header = 0;

	while(p < &buf[size]) {
		const char *q = cli_pmemstr(p, bytesleft, "<script", 7);

		if(q != NULL)
			/* TODO: full case independant search */
			q = cli_pmemstr(p, bytesleft, "<SCRIPT", 7);

		if(q == NULL)
			break;

		/* TODO: check language is javascript */

		bytesleft -= (q - p);
		p = q;

		q = cli_pmemstr(p, bytesleft, ">", 1);
		if(q == NULL)
			break;

		bytesleft -= (q - p);
		p = q;

		p++;
		bytesleft--;

		while(bytesleft) {
			if(*p == '<') {
				p++;
				if(--bytesleft == 0)
					break;
				if(*p == '!') {
					while(bytesleft && (*p != '\n')) {
						p++;
						bytesleft--;
					}
					continue;
				}
				if((bytesleft >= 7) && (strncasecmp(p, "/script", 7) == 0)) {
					bytesleft -= 7;
					p = &p[7];
					while(bytesleft && (*p != '>')) {
						p++;
						bytesleft--;
					}
					break;
				}
			}
			/*
			 * if(!done_header) {
			 * 	EMIT
			 *		function main()
			 *		{
			 *	END_EMIT
			 *	done_header = true;
			 * }
			 */
			/*putchar(tolower(*p));*/
			p++;
			bytesleft--;
		}
	}

	if(!done_header)
		cli_dbgmsg("No javascript was detected\n");
	else {
		/*
		 * EMIT
		 *	}
		 *
		 *	main();
		 * END_EMIT
		 * Run NJS on the script file
		 */
	}
	/* unlink the script file */

	munmap(buf, size);
	return CL_CLEAN;
}

/* Copied from pdf.c :-( */
/*
 * like cli_memstr - but returns the location of the match
 * FIXME: need a case insensitive version`
 */
static const char *
cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns)
{
	const char *pt, *hay;
	size_t n;

	if(haystack == needle)
		return haystack;

	if(hs < ns)
		return NULL;

	if(memcmp(haystack, needle, ns) == 0)
		return haystack;

	pt = hay = haystack;
	n = hs;

	while((pt = memchr(hay, needle[0], n)) != NULL) {
		n -= (int) pt - (int) hay;
		if(n < ns)
			break;

		if(memcmp(pt, needle, ns) == 0)
			return pt;

		if(hay == pt) {
			n--;
			hay++;
		} else
			hay = pt;
	}

	return NULL;
}

#else

int
cli_scanjs(const char *dir, int desc)
{
	cli_warnmsg("File not decoded - JS decoding needs mmap() (for now)\n");
	return CL_CLEAN;
}
#endif	/*HAVE_MMAP*/

#endif	/*CL_EXPERIMENTAL*/
