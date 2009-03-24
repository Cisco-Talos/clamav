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

#include <zlib.h>

#ifdef	C_WINDOWS
#include <io.h>
#endif

#include "clamav.h"
#include "others.h"
#include "mbox.h"
#include "pdf.h"
#include "scanners.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifdef	CL_DEBUG
/*#define	SAVE_TMP	
 *Save the file being worked on in tmp */
#endif

static	int	try_flatedecode(unsigned char *buf, off_t real_len, off_t calculated_len, int fout, cli_ctx *ctx);
static	int	flatedecode(unsigned char *buf, off_t len, int fout, cli_ctx *ctx);
static	int	ascii85decode(const char *buf, off_t len, unsigned char *output);
static	const	char	*pdf_nextlinestart(const char *ptr, size_t len);
static	const	char	*pdf_nextobject(const char *ptr, size_t len);
static	const	char	*cli_pmemstr(const char *haystack, size_t hs, const char *needle, size_t ns);

/*
 * TODO: handle embedded URLs if (options&CL_SCAN_MAILURL)
 */
int
cli_pdf(const char *dir, int desc, cli_ctx *ctx, off_t offset)
{
	off_t size;	/* total number of bytes in the file */
	off_t bytesleft, trailerlength;
	char *buf;	/* start of memory mapped area */
	const char *p, *q, *trailerstart;
	const char *xrefstart;	/* cross reference table */
	/*size_t xreflength;*/
	table_t *md5table;
	int printed_predictor_message, printed_embedded_font_message, rc;
	unsigned int files;
	struct stat statb;

	cli_dbgmsg("in cli_pdf(%s)\n", dir);

	if(fstat(desc, &statb) < 0) {
		cli_errmsg("cli_pdf: fstat() failed\n");
		return CL_EOPEN;
	}

	size = statb.st_size - offset;

	if(size <= 7)	/* doesn't even include the file header */
		return CL_CLEAN;

	p = buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, desc, offset);
	if(buf == MAP_FAILED) {
		cli_errmsg("cli_pdf: mmap() failed\n");
		return CL_EMAP;
	}

	cli_dbgmsg("cli_pdf: scanning %lu bytes\n", (unsigned long)size);

	/* Lines are terminated by \r, \n or both */

	/* File Header */
	bytesleft = size - 5;
	for(q = p; bytesleft; bytesleft--, q++) {
	    if(!strncasecmp(q, "%PDF-", 5)) {
		bytesleft = size - (off_t) (q - p);
		p = q;
		break;
	    }
	}

	if(!bytesleft) {
	    munmap(buf, size);
	    cli_dbgmsg("cli_pdf: file header not found\n");
	    return CL_CLEAN;
	}

	/* Find the file trailer */
	for(q = &p[bytesleft - 5]; q > p; --q)
		if(strncasecmp(q, "%%EOF", 5) == 0)
			break;

	if(q <= p) {
		munmap(buf, size);
		cli_dbgmsg("cli_pdf: trailer not found\n");
		return CL_CLEAN;
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
		 * http://www.cs.cmu.edu/~dst/Adobe/Gallery/anon21jul01-pdf-encryption.txt
		 * http://www.adobe.com/devnet/pdf/
		 */
		munmap(buf, size);
		cli_dbgmsg("cli_pdf: Encrypted PDF files not yet supported\n");
		return CL_CLEAN;
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
		cli_dbgmsg("cli_pdf: xref not found\n");
		return CL_CLEAN;
	}

	printed_predictor_message = printed_embedded_font_message = 0;

	md5table = tableCreate();
	/*
	 * not true, since edits may put data after the trailer
	xreflength = (size_t)(trailerstart - xrefstart);
	bytesleft -= xreflength;
	 */

	files = 0;

	rc = CL_CLEAN;

	/*
	 * The body section consists of a sequence of indirect objects
	 */
	while((p < xrefstart) && (cli_checklimits("cli_pdf", ctx, 0, 0, 0)==CL_CLEAN) &&
	      ((q = pdf_nextobject(p, bytesleft)) != NULL)) {
		int is_ascii85decode, is_flatedecode, fout, len, has_cr;
		/*int object_number, generation_number;*/
		const char *objstart, *objend, *streamstart, *streamend;
		unsigned char *md5digest;
		unsigned long length, objlen, real_streamlen, calculated_streamlen;
		int is_embedded_font, predictor;
		char fullname[NAME_MAX + 1];

		rc = CL_CLEAN;
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
			cli_dbgmsg("cli_pdf: Object number missing\n");
			break;
		}
		q = pdf_nextobject(p, bytesleft);
		if((q == NULL) || !isdigit(*q)) {
			cli_dbgmsg("cli_pdf: Generation number missing\n");
			break;
		}
		/*generation_number = atoi(q);*/
		bytesleft -= (off_t)(q - p);
		p = q;

		q = pdf_nextobject(p, bytesleft);
		if((q == NULL) || (memcmp(q, "obj", 3) != 0)) {
			cli_dbgmsg("cli_pdf: Indirect object missing \"obj\"\n");
			break;
		}

		bytesleft -= (off_t)((q - p) + 3);
		objstart = p = &q[3];
		objend = cli_pmemstr(p, bytesleft, "endobj", 6);
		if(objend == NULL) {
			cli_dbgmsg("cli_pdf: No matching endobj\n");
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
						const char *r, *nq;
						int opt_failed = 0;
						size_t len;
						char b[14];

						q += 4;
						cli_dbgmsg("cli_pdf: Length is in indirect obj %lu\n",
							length);
						snprintf(b, sizeof(b),
							"%lu 0 obj", length);
						length = (unsigned long)strlen(b);
						/* optimization: assume objects
						 * are sequential */
						nq = q;
						len = buf + size - q;
						do {
							r = cli_pmemstr(nq, len, b, length);
							if (r > nq) {
								const char x = *(r-1);
								if (x == '\n' || x=='\r') {
									--r;
									break;
								}
							}
							if (r) {
								len -= r+1-nq;
								nq = r + 1;
							} else if (!opt_failed) {
								/* we failed optimized match,
								 * try matching from the beginning
								 */
								len = q - buf;
								r = nq = buf;
								/* prevent
								 * infloop */
								opt_failed = 1;
							}
						} while (r);
						if(r) {
							r += length - 1;
							r = pdf_nextobject(r, bytesleft - (r - q));
							if(r) {
								length = atoi(r);
								while(isdigit(*r))
									r++;
								cli_dbgmsg("cli_pdf: length in '%s' %lu\n",
									&b[1],
									length);
							}
						} else
							cli_dbgmsg("cli_pdf: Couldn't find '%s'\n",
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
				cli_dbgmsg("cli_pdf: Embedded fonts not yet supported\n");
				printed_embedded_font_message = 1;
			}
			continue;
		}
		if(predictor > 1) {
			/*
			 * Needs some thought
			 */
			if(!printed_predictor_message) {
				cli_dbgmsg("cli_pdf: Predictor %d not honoured for embedded image\n",
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
				cli_dbgmsg("cli_pdf: No endstream\n");
				break;
			}
			has_cr = 1;
		} else
			has_cr = 0;
		snprintf(fullname, sizeof(fullname), "%s/pdf%02u", dir, files);
		fout = open(fullname, O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
		if(fout < 0) {
			char err[128];
			cli_errmsg("cli_pdf: can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
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
			cli_dbgmsg("cli_pdf: Empty stream\n");
			if (cli_unlink(fullname)) {
				rc = CL_EUNLINK;
				break;
			}
			continue;
		}
		calculated_streamlen = (int)(streamend - streamstart);
		real_streamlen = length;

		cli_dbgmsg("cli_pdf: length %lu, calculated_streamlen %lu isFlate %d isASCII85 %d\n",
			length, calculated_streamlen,
			is_flatedecode, is_ascii85decode);

		if(calculated_streamlen != real_streamlen) {
			cli_dbgmsg("cli_pdf: Incorrect Length field in file attempting to recover\n");
			if(real_streamlen > calculated_streamlen)
				real_streamlen = calculated_streamlen;
		}
#if	0
		/* FIXME: this isn't right... */
		if(length)
			/*streamlen = (is_flatedecode) ? length : MIN(length, streamlen);*/
			streamlen = MIN(length, streamlen);
#endif

		if(is_ascii85decode) {
			unsigned char *tmpbuf;
			int ret = cli_checklimits("cli_pdf", ctx, calculated_streamlen * 5, calculated_streamlen, real_streamlen);

			if(ret != CL_CLEAN) {
				close(fout);
				if (cli_unlink(fullname)) {
					rc = CL_EUNLINK;
					break;
				}
				continue;
			}

			tmpbuf = cli_malloc(calculated_streamlen * 5);

			if(tmpbuf == NULL) {
				close(fout);
				if (cli_unlink(fullname)) {
					rc = CL_EUNLINK;
					break;
				}
				continue;
			}

			ret = ascii85decode(streamstart, calculated_streamlen, tmpbuf);

			if(ret == -1) {
				free(tmpbuf);
				close(fout);
				if (cli_unlink(fullname)) {
					rc = CL_EUNLINK;
					break;
				}
				continue;
			}
			if(ret) {
				unsigned char *t;

				real_streamlen = ret;
				/* free unused trailing bytes */
				t = (unsigned char *)cli_realloc(tmpbuf,calculated_streamlen);
				if(t == NULL) {
					free(tmpbuf);
					close(fout);
					if (cli_unlink(fullname)) {
						rc = CL_EUNLINK;
						break;
					}
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
				  rc = (unsigned long)cli_writen(fout, (const char *)streamstart, real_streamlen)==real_streamlen ? CL_CLEAN : CL_EWRITE;
			}
			free(tmpbuf);
		} else if(is_flatedecode) {
			rc = try_flatedecode((unsigned char *)streamstart, real_streamlen, calculated_streamlen, fout, ctx);

		} else {
			cli_dbgmsg("cli_pdf: writing %lu bytes from the stream\n",
				(unsigned long)real_streamlen);
			if((rc = cli_checklimits("cli_pdf", ctx, real_streamlen, 0, 0))==CL_CLEAN)
				rc = (unsigned long)cli_writen(fout, (const char *)streamstart, real_streamlen) == real_streamlen ? CL_CLEAN : CL_EWRITE;
		}

		if (rc == CL_CLEAN) {
			cli_dbgmsg("cli_pdf: extracted file %u to %s\n", files, fullname);
			files++;
	
			lseek(fout, 0, SEEK_SET);
			if((md5digest = cli_md5digest(fout))) {
				unsigned int i;
				char md5str[33];

				for(i = 0; i < 16; i++)
					sprintf(md5str + 2*i, "%02x", md5digest[i]);
				md5str[32] = 0;
				free(md5digest);

				if(tableFind(md5table, md5str) >= 0) {
					cli_dbgmsg("cli_pdf: not scanning duplicate embedded file '%s'\n", fullname);
					ctx->scannedfiles++;
					close(fout);
					if (cli_unlink(fullname)) {
						rc = CL_EUNLINK;
						break;
					}
					continue;
				} else
					tableInsert(md5table, md5str, 1);
			}

			lseek(fout, 0, SEEK_SET);
			rc = cli_magic_scandesc(fout, ctx);
		}
		close(fout);
		if(!ctx->engine->keeptmp)
			if (cli_unlink(fullname)) rc = CL_EUNLINK;
		if(rc != CL_CLEAN) break;
	}

	munmap(buf, size);

	tableDestroy(md5table);

	cli_dbgmsg("cli_pdf: returning %d\n", rc);
	return rc;
}

/*
 * flate inflation
 */
static int
try_flatedecode(unsigned char *buf, off_t real_len, off_t calculated_len, int fout, cli_ctx *ctx)
{
	int ret = cli_checklimits("cli_pdf", ctx, real_len, 0, 0);

	if (ret==CL_CLEAN && flatedecode(buf, real_len, fout, ctx) == CL_SUCCESS)
		return CL_CLEAN;

	if(real_len == calculated_len) {
		/*
		 * Nothing more we can do to inflate
		 */
		cli_dbgmsg("cli_pdf: Bad compression in flate stream\n");
		return CL_CLEAN;
	}

	if(cli_checklimits("cli_pdf", ctx, calculated_len, 0, 0)!=CL_CLEAN)
		return CL_CLEAN;

	ret = flatedecode(buf, calculated_len, fout, ctx);
	if(ret == CL_CLEAN)
		return CL_CLEAN;

	/* i.e. the PDF file is broken :-( */
	cli_dbgmsg("cli_pdf: Bad compressed block length in flate stream\n");

	return ret;
}

static int
flatedecode(unsigned char *buf, off_t len, int fout, cli_ctx *ctx)
{
	int zstat, ret;
	off_t nbytes;
	z_stream stream;
	unsigned char output[BUFSIZ];
#ifdef	SAVE_TMP
	char tmpfilename[16];
	int tmpfd;
#endif

	cli_dbgmsg("cli_pdf: flatedecode %lu bytes\n", (unsigned long)len);

	if(len == 0) {
		cli_dbgmsg("cli_pdf: flatedecode len == 0\n");
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
		cli_errmsg("cli_pdf: Can't make debugging file\n");
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
		cli_warnmsg("cli_pdf: inflateInit failed\n");
		return CL_EMEM;
	}

	nbytes = 0;

	while(stream.avail_in) {
		zstat = inflate(&stream, Z_NO_FLUSH);	/* zlib */
		switch(zstat) {
			case Z_OK:
				if(stream.avail_out == 0) {
				  	int written;
					if ((written=cli_writen(fout, output, sizeof(output)))!=sizeof(output)) {
						cli_errmsg("cli_pdf: failed to write output file\n");
						inflateEnd(&stream);
						return CL_EWRITE;
					}
					nbytes += written;

					if((ret=cli_checklimits("cli_pdf", ctx, nbytes, 0, 0))!=CL_CLEAN) {
						inflateEnd(&stream);
						return ret;
					}
					stream.next_out = output;
					stream.avail_out = sizeof(output);
				}
				continue;
			case Z_STREAM_END:
				break;
			default:
				if(stream.msg)
					cli_dbgmsg("cli_pdf: after writing %lu bytes, got error \"%s\" inflating PDF attachment\n",
						(unsigned long)nbytes,
						stream.msg);
				else
					cli_dbgmsg("cli_pdf: after writing %lu bytes, got error %d inflating PDF attachment\n",
						(unsigned long)nbytes, zstat);
				inflateEnd(&stream);
				return CL_CLEAN;
		}
		break;
	}

	if(stream.avail_out != sizeof(output)) {
		if(cli_writen(fout, output, sizeof(output) - stream.avail_out) < 0) {
			cli_errmsg("cli_pdf: failed to write output file\n");
			inflateEnd(&stream);
			return CL_EWRITE;
		}
	}
			
#ifdef	SAVE_TMP
	if (cli_unlink(tmpfilename)) {
		inflateEnd(&stream);
		return CL_EUNLINK;
	}
#endif
	inflateEnd(&stream);
	return CL_CLEAN;
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
		cli_dbgmsg("cli_pdf: ascii85decode: no EOF marker found\n");

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
				cli_dbgmsg("ascii85decode: unexpected 'z'\n");
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
					cli_dbgmsg("ascii85Decode: only 1 byte in last quintet\n");
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
			cli_dbgmsg("ascii85Decode: invalid character 0x%x, len %lu\n",
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
cli_pdf(const char *dir, int desc, cli_ctx *ctx, off_t offset)
{
	cli_dbgmsg("File not decoded - PDF decoding needs mmap() (for now)\n");
	return CL_CLEAN;
}
#endif
