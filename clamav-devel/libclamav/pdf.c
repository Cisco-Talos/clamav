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
static	char	const	rcsid[] = "$Id: pdf.c,v 1.42 2006/03/08 16:04:22 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"

#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#if HAVE_MMAP
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
#include "blob.h"
#include "pdf.h"

#ifndef	MIN
#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif

static	int	flatedecode(const unsigned char *buf, size_t len, int fout, const cli_ctx *ctx);
static	int	ascii85decode(const char *buf, size_t len, unsigned char *output);
static	const	char	*pdf_nextlinestart(const char *ptr, size_t len);
static	const	char	*pdf_nextobject(const char *ptr, size_t len);
static	const	char	*cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns);

/*
 * TODO: handle embedded URLs if (options&CL_SCAN_MAILURL)
 */
int
cli_pdf(const char *dir, int desc, const cli_ctx *ctx)
{
	struct stat statb;
	off_t size;	/* total number of bytes in the file */
	long bytesleft, trailerlength;
	char *buf;	/* start of memory mapped area */
	const char *p, *q, *trailerstart;
	const char *xrefstart;	/* cross reference table */
	/*size_t xreflength;*/
	int rc = CL_CLEAN;

	cli_dbgmsg("in cli_pdf()\n");

	if(fstat(desc, &statb) < 0)
		return CL_EOPEN;

	size = (size_t)statb.st_size;

	if(size == 0)
		return CL_CLEAN;

	if(size <= 7)	/* doesn't even include the file header */
		return CL_EFORMAT;

	p = buf = mmap(NULL, size, PROT_READ, MAP_SHARED, desc, 0);
	if(buf == MAP_FAILED)
		return CL_EMEM;

	cli_dbgmsg("cli_pdf: scanning %lu bytes\n", size);

	/* Lines are terminated by \r, \n or both */

	/* File Header */
	if(memcmp(p, "%PDF-1.", 7) != 0) {
		munmap(buf, size);
		return CL_EFORMAT;
	}

#if	0
	q = pdf_nextlinestart(&p[6], size - 6);
	if(q == NULL) {
		munmap(buf, size);
		return CL_EFORMAT;
	}
	bytesleft = size - (long)(q - p);
	p = q;
#else
	p = &p[6];
	bytesleft = size - 6;
#endif

	/* Find the file trailer */
	for(q = &p[bytesleft - 6]; q > p; --q)
		if(memcmp(q, "%%EOF", 5) == 0)
			break;

	if(q == p) {
		munmap(buf, size);
		return CL_EFORMAT;
	}

	for(trailerstart = &q[-7]; trailerstart > p; --trailerstart)
		if(memcmp(trailerstart, "trailer", 7) == 0)
			break;

	/*
	 * q points to the end of the trailer section
	 */
	trailerlength = (long)(q - trailerstart);
	if(cli_pmemstr(trailerstart, trailerlength, "Encrypt", 7)) {
		/*
		 * This tends to mean that the file is, in effect, read-only
		 */
		munmap(buf, size);
		cli_warnmsg("Encrypted PDF files not yet supported\n");
		return CL_EFORMAT;
	}

	/*
	 * not true, since edits may put data after the trailer
	bytesleft -= trailerlength;
	 */

	/*
	 * FIXME: Handle more than one xref section in the xref table
	 */
	for(xrefstart = trailerstart; xrefstart > p; --xrefstart)
		if(memcmp(xrefstart, "xref", 4) == 0)
			/*
			 * Make sure it's the start of the line, not a startxref
			 * token
			 */
			if((xrefstart[-1] == '\n') || (xrefstart[-1] == '\r'))
				break;

	if(xrefstart == p) {
		munmap(buf, size);
		return CL_EFORMAT;
	}

	/*
	 * not true, since edits may put data after the trailer
	xreflength = (size_t)(trailerstart - xrefstart);
	bytesleft -= xreflength;
	 */

	/*
	 * The body section consists of a sequence of indirect objects
	 */
	while((p < xrefstart) && ((q = pdf_nextobject(p, bytesleft)) != NULL)) {
		int is_ascii85decode, is_flatedecode, fout, len;
		/*int object_number, generation_number;*/
		const char *objstart, *objend, *streamstart, *streamend;
		size_t length, objlen, streamlen;
		char fullname[NAME_MAX + 1];
  
		if(q == xrefstart)
			break;
		if(memcmp(q, "xref", 4) == 0)
			break;
		if(!isdigit(*q)) {
			cli_warnmsg("cli_pdf: Object number missing\n");
			rc = CL_EFORMAT;
			break;
		}
		/*object_number = atoi(q);*/
		bytesleft -= (q - p);
		p = q;

		q = pdf_nextobject(p, bytesleft);
		if((q == NULL) || !isdigit(*q)) {
			cli_warnmsg("cli_pdf: Generation number missing\n");
			rc = CL_EFORMAT;
			break;
		}
		/*generation_number = atoi(q);*/
		bytesleft -= (q - p);
		p = q;

		q = pdf_nextobject(p, bytesleft);
		if((q == NULL) || (memcmp(q, "obj", 3) != 0)) {
			cli_warnmsg("Indirect object missing \"obj\"\n");
			rc = CL_EFORMAT;
			break;
		}

		bytesleft -= (q - p) + 3;
		objstart = p = &q[3];
		objend = cli_pmemstr(p, bytesleft, "endobj", 6);
		if(objend == NULL) {
			cli_dbgmsg("No matching endobj\n");
			break;
		}
		bytesleft -= (objend - p) + 6;
		p = &objend[6];
		objlen = (size_t)(objend - objstart);

		/* Is this object a stream? */
		streamstart = cli_pmemstr(objstart, objlen, "stream", 6);
		if(streamstart == NULL)
			continue;

		length = is_ascii85decode = is_flatedecode = 0;
		/*
		 * TODO: handle F and FFilter?
		 */
		q = objstart;
		while(q < streamstart) {
			if(*q == '/') {	/* name object */
				if(strncmp(++q, "Length ", 7) == 0) {
					q += 7;
					length = atoi(q);
					while(isdigit(*q))
						q++;
					q--;
				} else if(strncmp(q, "FlateDecode", 11) == 0) {
					is_flatedecode = 1;
					q += 12;
				} else if(strncmp(q, "ASCII85Decode", 12) == 0) {
					is_ascii85decode = 1;
					q += 13;
				}
			}
			q = pdf_nextobject(q, (size_t)(streamstart - q));
			if(q == NULL)
				break;
		}

		/* objend points to the end of the object (start of "endobj") */
		streamstart += 6;	/* go past the word "stream" */
		len = (int)(objend - streamstart);
		q = pdf_nextlinestart(streamstart, len);
		if(q == NULL)
			break;
		len -= (int)(q - streamstart);
		streamstart = q;
		streamend = cli_pmemstr(streamstart, len, "endstream\n", 10);
		if(streamend == NULL) {
			streamend = cli_pmemstr(streamstart, len, "endstream\r", 10);
			if(streamend == NULL) {
				cli_dbgmsg("No endstream");
				break;
			}
		}
		streamlen = (int)(streamend - streamstart) + 1;

		if(streamlen == 0) {
			cli_dbgmsg("Empty stream");
			continue;
		}

		/*while(strchr("\r\n", *--streamend))
			;*/
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

		cli_dbgmsg("length %d, streamlen %d\n", length, streamlen);

#if	0
		/* FIXME: this isn't right... */
		if(length)
			/*streamlen = (is_flatedecode) ? length : MIN(length, streamlen);*/
			streamlen = MIN(length, streamlen);
#endif

		if(is_ascii85decode) {
			unsigned char *tmpbuf = cli_malloc(streamlen * 5);
			int ret;

			if(tmpbuf == NULL) {
				close(fout);
				unlink(fullname);
				rc = CL_EMEM;
				continue;
			}

			ret = ascii85decode(streamstart, streamlen, tmpbuf);

			if(ret == -1) {
				free(tmpbuf);
				close(fout);
				unlink(fullname);
				rc = CL_EFORMAT;
				continue;
			}
			if(ret) {
				streamlen = (size_t)ret;
				/* free unused trailing bytes */
				tmpbuf = cli_realloc(tmpbuf, streamlen);
				/*
				 * Note that it will probably be both
				 * ascii85encoded and flateencoded
				 */
				if(is_flatedecode) {
					const int zstat = flatedecode((unsigned char *)tmpbuf, streamlen, fout, ctx);

					if(zstat != Z_OK)
						rc = CL_EZIP;
				} else
					cli_writen(fout, (char *)streamstart, streamlen);
			}
			free(tmpbuf);
		} else if(is_flatedecode) {
			const int zstat = flatedecode((unsigned char *)streamstart, streamlen, fout, ctx);

			if(zstat != Z_OK)
				rc = CL_EZIP;
		} else
			cli_writen(fout, (char *)streamstart, streamlen);

		close(fout);
		cli_dbgmsg("cli_pdf: extracted to %s\n", fullname);
	}

	munmap(buf, size);

	cli_dbgmsg("cli_pdf: returning %d\n", rc);
	return rc;
}

/* flate inflation - returns zlib status, e.g. Z_OK */
static int
flatedecode(const unsigned char *buf, size_t len, int fout, const cli_ctx *ctx)
{
	int zstat;
	off_t nbytes;
	z_stream stream;
	unsigned char output[BUFSIZ];

	cli_dbgmsg("cli_pdf: flatedecode %lu bytes\n", len);

	stream.zalloc = (alloc_func)Z_NULL;
	stream.zfree = (free_func)Z_NULL;
	stream.opaque = (void *)NULL;
	stream.next_in = (unsigned char *)buf;
	stream.avail_in = len;
	stream.next_out = output;
	stream.avail_out = sizeof(output);

	zstat = inflateInit(&stream);
	if(zstat != Z_OK) {
		cli_warnmsg("cli_pdf: inflateInit failed");
		return zstat;
	}
	nbytes = 0;
	for(;;) {
		zstat = inflate(&stream, Z_NO_FLUSH);
		switch(zstat) {
			case Z_OK:
				if(stream.avail_out == 0) {
					nbytes += cli_writen(fout, output, sizeof(output));
					if(ctx->limits &&
					   ctx->limits->maxfilesize &&
					   (nbytes > (off_t) ctx->limits->maxfilesize)) {
						cli_dbgmsg("cli_pdf: flatedecode size exceeded (%lu)\n", nbytes);
						inflateEnd(&stream);
#ifdef	notdef
						*ctx->virname = "PDF.ExceededFileSize";
#endif
						return Z_DATA_ERROR;
					}
					stream.next_out = output;
					stream.avail_out = sizeof(output);
				}
				continue;
			case Z_STREAM_END:
				break;
			default:
				if(stream.msg)
					cli_warnmsg("Error \"%s\" inflating PDF attachment\n", stream.msg);
				else
					cli_warnmsg("Error %d inflating PDF attachment\n", zstat);
				inflateEnd(&stream);
				return zstat;
		}
		break;
	}

	cli_dbgmsg("cli_pdf: flatedecode in=%lu out=%lu ratio %ld (max %d)\n",
		stream.total_in, stream.total_out,
		stream.total_out / stream.total_in,
		ctx->limits ? ctx->limits->maxratio : 0);

	if(ctx->limits &&
	   ctx->limits->maxratio &&
	   ((stream.total_out / stream.total_in) > ctx->limits->maxratio)) {
		cli_dbgmsg("cli_pdf: flatedecode Max ratio reached\n");
		inflateEnd(&stream);
#ifdef	notdef
		*ctx->virname = "Oversized.PDF";
#endif
		return Z_DATA_ERROR;
	}
	if(stream.avail_out != sizeof(output))
		cli_writen(fout, output, sizeof(output) - stream.avail_out);

	return inflateEnd(&stream);
}

/* ascii85 inflation, returns number of bytes in output, -1 for error */
static int
ascii85decode(const char *buf, size_t len, unsigned char *output)
{
	const char *ptr = buf;
	uint32_t sum = 0;
	int quintet = 0;
	int ret = 0;

	cli_dbgmsg("cli_pdf: ascii85decode %lu bytes\n", len);

	while(len > 0) {
		int byte = (len--) ? (int)*ptr++ : EOF;

		if((byte == '~') && (*ptr == '>'))
			byte = EOF;

		if(byte >= '!' && byte <= 'u') {
			sum = sum * 85 + ((uint32_t)byte - '!');
			if(++quintet == 5) {
				*output++ = (unsigned char)(sum >> 24);
				*output++ = (unsigned char)((sum >> 16) & 0xFF);
				*output++ = (unsigned char)((sum >> 8) & 0xFF);
				*output++ = (unsigned char)(sum & 0xFF);
				ret += 4;
				quintet = 0;
				sum = 0;
			}
		} else if(byte == 'z') {
			if(quintet) {
				cli_warnmsg("ascii85decode: unexpected 'z'\n");
				return -1;
			}
			*output++ = '\0';
			*output++ = '\0';
			*output++ = '\0';
			*output++ = '\0';
			ret += 4;
		} else if(byte == EOF) {
			if(quintet) {
				int i;

				if(quintet == 1) {
					cli_warnmsg("ascii85Decode: only 1 byte in last quintet\n");
					return -1;
				}
				sum *= 85 * (5 - quintet);
				if(quintet > 1)
					sum += (0xFFFFFF >> ((quintet - 2) * 8));
				ret += quintet;
				for(i = 0; i < quintet - 1; i++)
					*output++ = (unsigned char)((sum >> (24 - 8 * i)) & 0xFF);
				quintet = 0;
			}
			len = 0;
			break;
		} else if(!isspace(byte)) {
			cli_warnmsg("ascii85Decode: invalid character 0x%x, len %lu\n", byte & 0xFF, len);
			return -1;
		}
	}
	return ret;
}

/*
 * Find the start of the next line
 */
static const char *
pdf_nextlinestart(const char *ptr, size_t len)
{
	while(strchr("\r\n", *ptr) == NULL) {
		if(--len == 0L)
			return NULL;
		ptr++;
	}
	while(strchr("\r\n", *ptr) != NULL) {
		if(--len == 0L)
			return NULL;
		ptr++;
	}
	return ptr;
}

/*
 * Return the start of the next PDF object.
 * This assumes that we're not in a stream.
 */
static const char *
pdf_nextobject(const char *ptr, size_t len)
{
	const char *p;
	int inobject = 1;

	while(len) {
		switch(*ptr) {
			case '\n':
			case '\r':
			case '%':	/* comment */
				p = pdf_nextlinestart(ptr, len);
				if(p == NULL)
					return NULL;
				len -= (size_t)(p - ptr);
				ptr = p;
				inobject = 0;
				break;

			case ' ':
			case '\t':
			case '\v':
			case '\f':
				inobject = 0;
				ptr++;
				len--;
				break;
			default:
				if(!inobject)
					/* TODO: parse and return object type */
					return ptr;
				ptr++;
				len--;
		}
	}
	return NULL;
}

/*
 * like cli_memstr - but returns the location of the match
 * FIXME: need a case insensitive version
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
#else	/*!HAVE_MMAP*/
int
cli_pdf(const char *dir, int desc)
{
	cli_warnmsg("File not decoded - PDF decoding needs mmap() (for now)\n");
	return CL_CLEAN;
}
#endif
