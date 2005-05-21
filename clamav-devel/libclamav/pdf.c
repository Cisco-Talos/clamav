/*
 *  Copyright (C) 2005 Nigel Horne <njh@bandsman.co.uk>
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
 */
static	char	const	rcsid[] = "$Id: pdf.c,v 1.13 2005/05/21 19:48:29 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"

#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "table.h"
#include "mbox.h"
#include "others.h"
#include "blob.h"

#ifndef	MIN
#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif

int
cli_pdf(const char *dir, int desc)
{
#ifndef HAVE_MMAP
	cli_warnmsg("File not decoded - PDF decoding needs mmap() (for now)\n");
	return CL_CLEAN;
#else
	struct stat statb;
	off_t size;
	long bytesleft;
	char *buf;
	const char *p, *q;
	int rc = CL_CLEAN;

	cli_dbgmsg("in cli_pdf()\n");

	if(fstat(desc, &statb) < 0)
		return CL_EOPEN;

	size = (size_t)statb.st_size;

	if(size == 0)
		return CL_CLEAN;

	p = buf = mmap(NULL, size, PROT_READ, MAP_SHARED, desc, 0);
	if(buf == MAP_FAILED)
		return CL_EMEM;

	bytesleft = (long)size;

	cli_dbgmsg("cli_pdf: scanning %lu bytes\n", bytesleft);

	while((q = cli_pmemstr(p, bytesleft, "obj", 3)) != NULL) {
		int length, ascii85decode, flatedecode, fout;
		const char *s, *t, *u, *obj;
		size_t objlen;
		char fullname[NAME_MAX + 1];

		bytesleft -= (q - p) + 3;
		obj = p = &q[3];
		q = cli_pmemstr(p, bytesleft, "endobj", 6);
		if(q == NULL) {
			cli_dbgmsg("No matching endobj");
			break;
		}
		bytesleft -= (q - p) + 6;
		p = &q[6];
		objlen = (size_t)(q - obj);

		t = cli_pmemstr(obj, objlen, "stream\n", 7);
		if(t == NULL) {
			t = cli_pmemstr(obj, objlen, "stream\r", 7);
			if(t == NULL)
				continue;
		}

		length = ascii85decode = flatedecode = 0;
		for(s = obj; s < t; s++)
			if(*s == '/') {
				if(strncmp(++s, "Length ", 7) == 0) {
					s += 7;
					length = atoi(s);
					while(isdigit(*s))
						s++;
				} else if((strncmp(s, "FlateDecode ", 12) == 0) ||
					  (strncmp(s, "FlateDecode\n", 12) == 0)) {
					flatedecode = 1;
					s += 12;
				} else if(strncmp(s, "ASCII85Decode ", 12) == 0) {
					ascii85decode++;
					break;
				}
			
			}

		if(ascii85decode) {
			cli_warnmsg("ASCII85Decode not yet supported\n");
			continue;
		}

		t += 7;
		u = cli_pmemstr(t, objlen - 7, "endstream\n", 10);
		if(u == NULL) {
			const char *v = u;

			u = cli_pmemstr(t, objlen - 7, "endstream\r", 10);
			if(u == NULL) {
				cli_dbgmsg("No endstream");
				break;
			}
			v = u;
			while(strchr("\r\n", *--v))
				--u;

		}
		snprintf(fullname, sizeof(fullname), "%s/pdfXXXXXX", dir);
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS) || defined(C_CYGWIN)
		fout = mkstemp(fullname);
#else
		(void)mktemp(fullname);
		fout = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#endif

		if(fout < 0) {
			cli_errmsg("cli_pdf: can't create temporary file %s: %s\n", fullname, strerror(errno));
			rc = CL_ETMPFILE;
			break;
		}

		if(flatedecode) {
			z_stream stream;
			size_t len = (size_t)(u - t);
			unsigned char output[BUFSIZ];

			cli_dbgmsg("cli_pdf: flatedecode %lu bytes\n", len);

			while(strchr("\r\n", *t)) {
				len--;
				t++;
			}

			stream.zalloc = (alloc_func)Z_NULL;
			stream.zfree = (free_func)Z_NULL;
			stream.opaque = (void *)NULL;
			stream.next_in = (unsigned char *)t;
			stream.avail_in = len;

			if(inflateInit(&stream) != Z_OK) {
				cli_warnmsg("cli_pdf: inflateInit failed");
				close(fout);
				continue;
			}
			stream.next_out = output;
			stream.avail_out = sizeof(output);
			for(;;) {
				int zstat;

				if(stream.avail_out == 0) {
					cli_dbgmsg("write BUFSIZ\n");
					write(fout, output, BUFSIZ);
					stream.next_out = output;
					stream.avail_out = BUFSIZ;
				}
				zstat = inflate(&stream, Z_NO_FLUSH);
				switch(zstat) {
					case Z_OK:
						continue;
					case Z_STREAM_END:
						break;
					default:
						cli_warnmsg("Error %d inflating PDF attachment\n", zstat);
						rc = CL_EZIP;
						break;
				}
				break;
			}

			if(stream.avail_out != sizeof(output)) {
				cli_dbgmsg("flush %lu\n", sizeof(output) - stream.avail_out);
				write(fout, output, sizeof(output) - stream.avail_out);
			}
			inflateEnd(&stream);
		} else
			write(fout, t, (size_t)(u - t));

		close(fout);
		cli_dbgmsg("cli_pdf: extracted to %s\n", fullname);
	}

	munmap(buf, size);

	cli_dbgmsg("cli_pdf: returning %d\n", rc);
	return rc;
#endif
}
