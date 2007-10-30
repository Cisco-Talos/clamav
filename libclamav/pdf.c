/*
 *  Copyright (C) 2005-2007 Nigel Horne <njh@bandsman.co.uk>
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
 * TODO: Embedded fonts
 * TODO: Predictor image handling
 */
static	char	const	rcsid[] = "$Id: pdf.c,v 1.61 2007/02/12 20:46:09 njh Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	HAVE_MMAP
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#ifdef	HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#ifdef	C_WINDOWS
#include <io.h>
#endif

#include "clamav.h"
#include "others.h"
#include "mbox.h"
#include "pdf.h"

#ifdef	CL_DEBUG
/*#define	SAVE_TMP	/* Save the file being worked on in tmp */
#endif

static	int	try_flatedecode(unsigned char *buf, off_t real_len, off_t calculated_len, int fout, const cli_ctx *ctx);
static	int	flatedecode(unsigned char *buf, off_t len, int fout, const cli_ctx *ctx);
static	int	ascii85decode(const char *buf, off_t len, unsigned char *output);
static	const	char	*pdf_nextlinestart(const char *ptr, size_t len);
static	const	char	*pdf_nextobject(const char *ptr, size_t len);
static	const	char	*cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns);

/*
 * TODO: handle embedded URLs if (options&CL_SCAN_MAILURL)
 */
int
cli_pdf(const char *dir, int desc, const cli_ctx *ctx)
{
	off_t size;	/* total number of bytes in the file */
	off_t bytesleft, trailerlength;
	char *buf, *alloced;	/* start of memory mapped area */
	const char *p, *q, *trailerstart;
	const char *xrefstart;	/* cross reference table */
	const struct cl_limits *limits;
	/*size_t xreflength;*/
	table_t *md5table;
	int printed_predictor_message, printed_embedded_font_message, rc;
	unsigned int files;
	struct stat statb;

	cli_dbgmsg("in cli_pdf(%s)\n", dir);

	if(fstat(desc, &statb) < 0)
		return CL_EOPEN;

	size = statb.st_size;

	if(size == 0)
		return CL_CLEAN;

	if(size <= 7)	/* doesn't even include the file header */
		return CL_EFORMAT;

	p = buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, desc, 0);
	if(buf == MAP_FAILED)
		return CL_EMEM;

	alloced = cli_malloc(size);
	if(alloced) {
		/*
		 * FIXME: now I have this, there's no need for the lack of
		 *	support on systems without mmap, e.g. cygwin
		 */
		memcpy(alloced, buf, size);
		munmap(buf, size);
		p = alloced;
	}

	cli_dbgmsg("cli_pdf: scanning %lu bytes\n", (unsigned long)size);

	/* Lines are terminated by \r, \n or both */

	/* File Header */
	if(memcmp(p, "%PDF-1.", 7) != 0) {
		if(alloced)
			free(alloced);
		else
			munmap(buf, size);
		return CL_EFORMAT;
	}

#if	0
	q = pdf_nextlinestart(&p[6], size - 6);
	if(q == NULL) {
		if(alloced)
			free(alloced);
		else
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

	if(q <= p) {
		if(alloced)
			free(alloced);
		else
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
		if(alloced)
			free(alloced);
		else
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
		if(alloced)
			free(alloced);
		else
			munmap(buf, size);
		return CL_EFORMAT;
	}

	printed_predictor_message = printed_embedded_font_message = 0;

	md5table = tableCreate();
	/*
	 * not true, since edits may put data after the trailer
	xreflength = (size_t)(trailerstart - xrefstart);
	bytesleft -= xreflength;
	 */

	rc = CL_CLEAN;
	files = 0;
	limits = ctx->limits;

	/*
	 * The body section consists of a sequence of indirect objects
	 */
	while((p < xrefstart) && (rc == CL_CLEAN) &&
	      ((q = pdf_nextobject(p, bytesleft)) != NULL)) {
		int is_ascii85decode, is_flatedecode, fout, len, has_cr;
		/*int object_number, generation_number;*/
		const char *objstart, *objend, *streamstart, *streamend;
		char *md5digest;
		unsigned long length, objlen, real_streamlen, calculated_streamlen;
		int is_embedded_font, predictor;
		char fullname[NAME_MAX + 1];

		if(q == xrefstart)
			break;
		if(memcmp(q, "xref", 4) == 0)
			break;

		/*object_number = atoi(q);*/
		bytesleft -= (off_t)(q - p);
		p = q;

		if(memcmp(q, "endobj", 6) == 0)
			continue;
		if(!isdigit(*q)) {
			cli_warnmsg("cli_pdf: Object number missing\n");
			rc = CL_EFORMAT;
			break;
		}
		q = pdf_nextobject(p, bytesleft);
		if((q == NULL) || !isdigit(*q)) {
			cli_warnmsg("cli_pdf: Generation number missing\n");
			rc = CL_EFORMAT;
			break;
		}
		/*generation_number = atoi(q);*/
		bytesleft -= (off_t)(q - p);
		p = q;

		q = pdf_nextobject(p, bytesleft);
		if((q == NULL) || (memcmp(q, "obj", 3) != 0)) {
			cli_warnmsg("Indirect object missing \"obj\"\n");
			rc = CL_EFORMAT;
			break;
		}

		bytesleft -= (off_t)((q - p) + 3);
		objstart = p = &q[3];
		objend = cli_pmemstr(p, bytesleft, "endobj", 6);
		if(objend == NULL) {
			cli_dbgmsg("No matching endobj\n");
			break;
		}
		bytesleft -= (off_t)((objend - p) + 6);
		p = &objend[6];
		objlen = (unsigned long)(objend - objstart);

		/* Is this object a stream? */
		streamstart = cli_pmemstr(objstart, objlen, "stream", 6);
		if(streamstart == NULL)
			continue;

		is_embedded_font = length = is_ascii85decode =
			is_flatedecode = 0;
		predictor = 1;

		/*
		 * TODO: handle F and FFilter?
		 */
		q = objstart;
		while(q < streamstart) {
			if(*q == '/') {	/* name object */
				/*cli_dbgmsg("Name object %8.8s\n", q+1, q+1);*/
				if(strncmp(++q, "Length ", 7) == 0) {
					q += 7;
					length = atoi(q);
					while(isdigit(*q))
						q++;
					/*
					 * Note: incremental updates are not
					 *	supported
					 */
					if((bytesleft > 11) && strncmp(q, " 0 R", 4) == 0) {
						const char *r;
						char b[14];

						q += 4;
						cli_dbgmsg("Length is in indirect obj %ld\n",
							length);
						snprintf(b, sizeof(b),
							"\n%ld 0 obj", length);
						length = (unsigned long)strlen(b);
						r = cli_pmemstr(alloced ? alloced : buf,
							size, b, length);
						if(r == NULL) {
							b[0] = '\r';
							r = cli_pmemstr(alloced ? alloced : buf,
								size, b, length);
						}
						if(r) {
							r += length - 1;
							r = pdf_nextobject(r, bytesleft - (r - q));
							if(r) {
								length = atoi(r);
								while(isdigit(*r))
									r++;
								cli_dbgmsg("length in '%s' %ld\n",
									&b[1],
									length);
							}
						} else
							cli_warnmsg("Couldn't find '%s'\n",
								&b[1]);
					}
					q--;
				} else if(strncmp(q, "Length2 ", 8) == 0)
					is_embedded_font = 1;
				else if(strncmp(q, "Predictor ", 10) == 0) {
					q += 10;
					predictor = atoi(q);
					while(isdigit(*q))
						q++;
					q--;
				} else if(strncmp(q, "FlateDecode", 11) == 0) {
					is_flatedecode = 1;
					q += 11;
				} else if(strncmp(q, "ASCII85Decode", 13) == 0) {
					is_ascii85decode = 1;
					q += 13;
				}
			}
			q = pdf_nextobject(q, (size_t)(streamstart - q));
			if(q == NULL)
				break;
		}

		if(is_embedded_font) {
			/*
			 * Need some documentation, the only I can find a
			 * reference to is not free, if some kind soul wishes
			 * to donate a copy, please contact me!
			 * (http://safari.adobepress.com/0321304748)
			 */
			if(!printed_embedded_font_message) {
				cli_dbgmsg("Embedded fonts not yet supported\n");
				printed_embedded_font_message = 1;
			}
			continue;
		}
		if(predictor > 1) {
			/*
			 * Needs some thought
			 */
			if(!printed_predictor_message) {
				cli_dbgmsg("Predictor %d not honoured for embedded image\n",
					predictor);
				printed_predictor_message = 1;
			}
			continue;
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
				cli_dbgmsg("No endstream\n");
				break;
			}
			has_cr = 1;
		} else
			has_cr = 0;
		snprintf(fullname, sizeof(fullname), "%s/pdfXXXXXX", dir);
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS) || defined(C_CYGWIN)
		fout = mkstemp(fullname);
#elif	defined(C_WINDOWS)
		if(_mktemp(fullname) == NULL) {
			/* mktemp only allows 26 files */
			char *name = cli_gentemp(dir);
			if(name == NULL)
				fout = -1;
			else {
				strcpy(fullname, name);
				free(name);
				fout = open(fullname,
					O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
			}
		} else
			fout = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#else
		mktemp(fullname);
		fout = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#endif

		if(fout < 0) {
			cli_errmsg("cli_pdf: can't create temporary file %s: %s\n", fullname, strerror(errno));
			rc = CL_ETMPFILE;
			break;
		}

		/*
		 * Calculate the length ourself, the Length parameter is often
		 * wrong
		 */
		if((*--streamend != '\n') && (*streamend != '\r'))
			streamend++;
		else if(has_cr && (*--streamend != '\r'))
			streamend++;

		if(streamend <= streamstart) {
			close(fout);
			cli_dbgmsg("Empty stream\n");
			unlink(fullname);
			continue;
		}
		calculated_streamlen = (int)(streamend - streamstart);
		real_streamlen = length;

		if(calculated_streamlen != real_streamlen)
			cli_dbgmsg("cli_pdf: Incorrect Length field in file attempting to recover\n");

		cli_dbgmsg("length %ld, calculated_streamlen %ld isFlate %d isASCII85 %d\n",
			length, calculated_streamlen,
			is_flatedecode, is_ascii85decode);

#if	0
		/* FIXME: this isn't right... */
		if(length)
			/*streamlen = (is_flatedecode) ? length : MIN(length, streamlen);*/
			streamlen = MIN(length, streamlen);
#endif

		if(is_ascii85decode) {
			unsigned char *tmpbuf = cli_malloc(calculated_streamlen * 5);
			int ret;

			if(tmpbuf == NULL) {
				close(fout);
				unlink(fullname);
				rc = CL_EMEM;
				continue;
			}

			ret = ascii85decode(streamstart, calculated_streamlen, tmpbuf);

			if(ret == -1) {
				free(tmpbuf);
				close(fout);
				unlink(fullname);
				rc = CL_EFORMAT;
				continue;
			}
			if(ret) {
				unsigned char *t;

				real_streamlen = ret;
				/* free unused trailing bytes */
				t = (unsigned char *)cli_realloc(tmpbuf,
					calculated_streamlen);
				if(t == NULL) {
					free(tmpbuf);
					close(fout);
					unlink(fullname);
					rc = CL_EMEM;
					continue;
				}
				tmpbuf = t;
				/*
				 * Note that it will probably be both
				 * ascii85encoded and flateencoded
				 */
				if(is_flatedecode)
					rc = try_flatedecode((unsigned char *)tmpbuf, real_streamlen, real_streamlen, fout, ctx);
				else
					cli_writen(fout, (const char *)streamstart, real_streamlen);
			}
			free(tmpbuf);
		} else if(is_flatedecode)
			rc = try_flatedecode((unsigned char *)streamstart, real_streamlen, calculated_streamlen, fout, ctx);

		else {
			cli_dbgmsg("cli_pdf: writing %lu bytes from the stream\n",
				(unsigned long)real_streamlen);
			cli_writen(fout, (const char *)streamstart, real_streamlen);
		}

		close(fout);
		md5digest = cli_md5file(fullname);
		if(tableFind(md5table, md5digest) >= 0) {
			cli_dbgmsg("cli_pdf: not scanning duplicate embedded file '%s'\n", fullname);
			unlink(fullname);
		} else
			tableInsert(md5table, md5digest, 1);
		free(md5digest);
		cli_dbgmsg("cli_pdf: extracted file %d to %s\n", ++files,
			fullname);
		if(limits && limits->maxfiles && (files >= limits->maxfiles)) {
			/* Bug 698 */
			cli_dbgmsg("cli_pdf: number of files exceeded %u\n", limits->maxfiles);
			rc = CL_EMAXFILES;
		}
	}

	if(alloced)
		free(alloced);
	else
		munmap(buf, size);

	tableDestroy(md5table);

	cli_dbgmsg("cli_pdf: returning %d\n", rc);
	return rc;
}

/*
 * flate inflation - returns clamAV status, e.g CL_SUCCESS, CL_EZIP
 */
static int
try_flatedecode(unsigned char *buf, off_t real_len, off_t calculated_len, int fout, const cli_ctx *ctx)
{
	int ret = flatedecode(buf, real_len, fout, ctx);

	if(ret == CL_SUCCESS)
		return CL_SUCCESS;

	if(real_len == calculated_len) {
		/*
		 * Nothing more we can do to inflate
		 */
		cli_warnmsg("Bad compression in flate stream\n");
		return (ret == CL_SUCCESS) ? CL_EFORMAT : ret;
	}

	ret = flatedecode(buf, calculated_len, fout, ctx);
	if(ret == CL_SUCCESS)
		return CL_SUCCESS;

	/* i.e. the PDF file is broken :-( */
	cli_warnmsg("cli_pdf: Bad compressed block length in flate stream\n");

	return ret;
}

static int
flatedecode(unsigned char *buf, off_t len, int fout, const cli_ctx *ctx)
{
	int zstat;
	off_t nbytes;
	z_stream stream;
	unsigned char output[BUFSIZ];
#ifdef	SAVE_TMP
	char tmpfilename[16];
	int tmpfd;
#endif

	cli_dbgmsg("cli_pdf: flatedecode %lu bytes\n", (unsigned long)len);

	if(len == 0) {
		cli_warnmsg("cli_pdf: flatedecode len == 0\n");
		return CL_CLEAN;
	}

#ifdef	SAVE_TMP
	/*
	 * Copy the embedded area for debugging, so that if it falls over
	 * we have a copy of the offending data. This is debugging code
	 * that you shouldn't of course install in a live environment. I am
	 * not interested in hearing about security issues with this section
	 * of the parser.
	 */
	strcpy(tmpfilename, "/tmp/pdfXXXXXX");
	tmpfd = mkstemp(tmpfilename);
	if(tmpfd < 0) {
		perror(tmpfilename);
		cli_errmsg("Can't make debugging file\n");
	} else {
		FILE *tmpfp = fdopen(tmpfd, "w");

		if(tmpfp) {
			fwrite(buf, sizeof(char), len, tmpfp);
			fclose(tmpfp);
			cli_dbgmsg("cli_pdf: flatedecode: debugging file is %s\n",
				tmpfilename);
		} else
			cli_errmsg("cli_pdf: can't fdopen debugging file\n");
	}
#endif
	stream.zalloc = (alloc_func)Z_NULL;
	stream.zfree = (free_func)Z_NULL;
	stream.opaque = (void *)NULL;
	stream.next_in = (Bytef *)buf;
	stream.avail_in = len;
	stream.next_out = output;
	stream.avail_out = sizeof(output);

	zstat = inflateInit(&stream);
	if(zstat != Z_OK) {
		cli_warnmsg("cli_pdf: inflateInit failed");
		return CL_EZIP;
	}

	nbytes = 0;

	while(stream.avail_in) {
		zstat = inflate(&stream, Z_NO_FLUSH);	/* zlib */
		switch(zstat) {
			case Z_OK:
				if(stream.avail_out == 0) {

					nbytes += cli_writen(fout, output, sizeof(output));

					if(ctx->limits &&
					   ctx->limits->maxfilesize &&
					   (nbytes > (off_t) ctx->limits->maxfilesize)) {
						cli_dbgmsg("cli_pdf: flatedecode size exceeded (%lu)\n",
							(unsigned long)nbytes);
						inflateEnd(&stream);
						if(BLOCKMAX) {
							*ctx->virname = "PDF.ExceededFileSize";
							return CL_VIRUS;
						}
						return CL_EZIP;
					}
					stream.next_out = output;
					stream.avail_out = sizeof(output);
				}
				continue;
			case Z_STREAM_END:
				break;
			default:
				if(stream.msg)
					cli_dbgmsg("pdf: after writing %lu bytes, got error \"%s\" inflating PDF attachment\n",
						(unsigned long)nbytes,
						stream.msg);
				else
					cli_dbgmsg("pdf: after writing %lu bytes, got error %d inflating PDF attachment\n",
						(unsigned long)nbytes, zstat);
				inflateEnd(&stream);
				return (zstat == Z_OK) ? CL_SUCCESS : CL_EZIP;
		}
		break;
	}

	if(stream.avail_out != sizeof(output))
		if(cli_writen(fout, output, sizeof(output) - stream.avail_out) < 0)
			return CL_EIO;

	/*
	 * On BSD systems total_in and total_out are "long long", so these
	 * numbers could (in theory) get truncated in the debug statement
	 */
	cli_dbgmsg("cli_pdf: flatedecode in=%lu out=%lu ratio %lu (max %u)\n",
		(unsigned long)stream.total_in, (unsigned long)stream.total_out,
		(unsigned long)(stream.total_out / stream.total_in),
		ctx->limits ? ctx->limits->maxratio : 0);

	if(ctx->limits &&
	   ctx->limits->maxratio &&
	   ((stream.total_out / stream.total_in) > ctx->limits->maxratio)) {
		cli_dbgmsg("cli_pdf: flatedecode Max ratio reached\n");
		inflateEnd(&stream);
		if(BLOCKMAX) {
			*ctx->virname = "Oversized.PDF";
			return CL_VIRUS;
		}
		return CL_EZIP;
	}

#ifdef	SAVE_TMP
	unlink(tmpfilename);
#endif
	return inflateEnd(&stream) == Z_OK ? CL_SUCCESS : CL_EZIP;
}

/*
 * ascii85 inflation, returns number of bytes in output, -1 for error
 *
 * See http://www.piclist.com/techref/method/encode.htm (look for base85)
 */
static int
ascii85decode(const char *buf, off_t len, unsigned char *output)
{
	const char *ptr;
	uint32_t sum = 0;
	int quintet = 0;
	int ret = 0;

	if(cli_pmemstr(buf, len, "~>", 2) == NULL)
		cli_warnmsg("ascii85decode: no EOF marker found\n");

	ptr = buf;

	cli_dbgmsg("cli_pdf: ascii85decode %lu bytes\n", (unsigned long)len);

	while(len > 0) {
		int byte = (len--) ? (int)*ptr++ : EOF;

		if((byte == '~') && (*ptr == '>'))
			byte = EOF;

		if(byte >= '!' && byte <= 'u') {
			sum = (sum * 85) + ((uint32_t)byte - '!');
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
			cli_dbgmsg("ascii85decode: quintet %d\n", quintet);
			if(quintet) {
				int i;

				if(quintet == 1) {
					cli_warnmsg("ascii85Decode: only 1 byte in last quintet\n");
					return -1;
				}
				for(i = quintet; i < 5; i++)
					sum *= 85;

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
			cli_warnmsg("ascii85Decode: invalid character 0x%x, len %lu\n",
				byte & 0xFF, (unsigned long)len);
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
			case '[':	/* Start of an array object */
			case '\v':
			case '\f':
			case '<':	/* Start of a dictionary object */
				inobject = 0;
				ptr++;
				len--;
				break;
			case '/':	/* Start of a name object */
				return ptr;
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
		n -= (size_t)(pt - hay);
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

#include "clamav.h"
#include "others.h"
#include "pdf.h"

int
cli_pdf(const char *dir, int desc, const cli_ctx *ctx)
{
	cli_warnmsg("File not decoded - PDF decoding needs mmap() (for now)\n");
	return CL_CLEAN;
}
#endif
