/*
 *  Copyright (C) 2007-2008, 2010 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne, Török Edvin
 *
 *  Also based on Matt Olney's pdf parser in snort-nrt.
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
#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "pdf.h"
#include "scanners.h"
#include "fmap.h"
#include "str.h"

#ifdef	CL_DEBUG
/*#define	SAVE_TMP	
 *Save the file being worked on in tmp */
#endif

static	int	asciihexdecode(const char *buf, off_t len, char *output);
static	int	ascii85decode(const char *buf, off_t len, unsigned char *output);
static	const	char	*pdf_nextlinestart(const char *ptr, size_t len);
static	const	char	*pdf_nextobject(const char *ptr, size_t len);

#if 1
enum pdf_flag {
    BAD_PDF_VERSION=0,
    BAD_PDF_HEADERPOS,
    BAD_PDF_TRAILER,
    BAD_PDF_TOOMANYOBJS,
    BAD_STREAM_FILTERS,
    BAD_FLATE,
    BAD_ASCIIDECODE,
    UNTERMINATED_OBJ_DICT,
    ESCAPED_COMMON_PDFNAME,
    HEX_JAVASCRIPT
};

static int xrefCheck(const char *xref, const char *eof)
{
    const char *q;
    while (xref < eof && (*xref == ' ' || *xref == '\n' || *xref == '\r'))
	xref++;
    if (xref + 4 >= eof)
	return -1;
    if (!memcmp(xref, "xref", 4)) {
	cli_dbgmsg("cli_pdf: found xref\n");
	return 0;
    }
    /* could be xref stream */
    for (q=xref; q+5 < eof; q++) {
	if (!memcmp(q,"/XRef",4)) {
	    cli_dbgmsg("cli_pdf: found /XRef\n");
	    return 0;
	}
    }
    return -1;
}

enum objflags {
    OBJ_STREAM=0,
    OBJ_DICT,
    OBJ_EMBEDDED_FILE,
    OBJ_FILTER_AH,
    OBJ_FILTER_A85,
    OBJ_FILTER_FLATE,
    OBJ_FILTER_LZW,
    OBJ_FILTER_RL,
    OBJ_FILTER_FAX,
    OBJ_FILTER_JBIG2,
    OBJ_FILTER_DCT,
    OBJ_FILTER_JPX,
    OBJ_FILTER_CRYPT,
    OBJ_JAVASCRIPT
};

struct pdf_obj {
    uint32_t start;
    uint32_t id;
    uint32_t flags;
};
struct pdf_struct {
    struct pdf_obj *objs;
    unsigned nobjs;
    const char *map;
    off_t size;
    off_t offset;
    unsigned flags;
    cli_ctx *ctx;
    const char *dir;
    unsigned files;
};

static const char *findNextNonWSBack(const char *q, const char *start)
{
    while (q > start &&
	   (*q == 0 || *q == 9 || *q == 0xa || *q == 0xc || *q == 0xd || *q == 0x20))
    {
	q--;
    }
    return q;
}

static int find_stream_bounds(const char *start, off_t bytesleft, off_t bytesleft2, off_t *stream, off_t *endstream)
{
    const char *q2, *q;
    if ((q2 = cli_memstr(start, bytesleft, "stream", 6))) {
	q2 += 6;
	if (q2[0] == '\xd' && q2[1] == '\xa')
	    q2 += 2;
	if (q2[0] == '\xa')
	    q2++;
	*stream = q2 - start;
	bytesleft2 -= q2 - start;
	q = q2;
	q2 = cli_memstr(q, bytesleft2, "endstream", 9);
	if (!q2)
	    return 0;/* no more objs */
	*endstream = q2 - start;
	return 1;
    }
    return 0;
}

static int pdf_findobj(struct pdf_struct *pdf)
{
    const char *start, *q, *q2, *q3, *eof;
    struct pdf_obj *obj;
    off_t bytesleft;
    unsigned genid, objid;

    pdf->nobjs++;
    pdf->objs = cli_realloc2(pdf->objs, sizeof(*pdf->objs)*pdf->nobjs);
    if (!pdf->objs) {
	cli_warnmsg("cli_pdf: out of memory parsing objects (%u)\n", pdf->nobjs);
	return -1;
    }
    obj = &pdf->objs[pdf->nobjs-1];
    memset(obj, 0, sizeof(*obj));
    start = pdf->map+pdf->offset;
    bytesleft = pdf->size - pdf->offset;
    q2 = cli_memstr(start, bytesleft, " obj", 4);
    if (!q2)
	return 0;/* no more objs */
    bytesleft -= q2 - start;
    q = findNextNonWSBack(q2-1, start);
    while (q > start && isdigit(*q)) { q--; }
    genid = atoi(q);
    q = findNextNonWSBack(q-1,start);
    while (q > start && isdigit(*q)) { q--; }
    objid = atoi(q);
    obj->id = (objid << 8) | (genid&0xff);
    obj->start = q2+4 - pdf->map;
    obj->flags = 0;
    bytesleft -= 4;
    eof = pdf->map + pdf->size;
    q = pdf->map + obj->start;
    while (q < eof && bytesleft > 0) {
	off_t p_stream, p_endstream;
	q2 = pdf_nextobject(q, bytesleft);
	if (!q2)
	    return 0;/* no more objs */
	bytesleft -= q2 - q;
	if (find_stream_bounds(q-1, q2-q, bytesleft + (q2-q), &p_stream, &p_endstream)) {
	    obj->flags |= 1 << OBJ_STREAM;
	    q2 = q-1 + p_endstream + 6;
	    bytesleft -= q2 - q + 1;
	} else if ((q3 = cli_memstr(q-1, q2-q+1, "endobj", 6))) {
	    q2 = q3 + 6;
	    pdf->offset = q2 - pdf->map;
	    return 1; /* obj found and offset positioned */
	} else {
	    q2++;
	}
	q = q2;
    }
    return 0;/* no more objs */
}

static int filter_writen(struct pdf_struct *pdf, struct pdf_obj *obj,
			 int fout, const char *buf, off_t len, off_t *sum)
{
    if (cli_checklimits("pdf", pdf->ctx, *sum, 0, 0))
	return len; /* pretend it was a successful write to suppress CL_EWRITE */
    *sum += len;
    return cli_writen(fout, buf, len);
}

static int filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj,
			      const char *buf, off_t len, int fout, off_t *sum)
{
    int zstat;
    z_stream stream;
    off_t nbytes;
    char output[BUFSIZ];

    if (len == 0)
	return CL_CLEAN;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)buf;
    stream.avail_in = len;
    stream.next_out = (Bytef *)output;
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
		    if ((written=filter_writen(pdf, obj, fout, output, sizeof(output), sum))!=sizeof(output)) {
			cli_errmsg("cli_pdf: failed to write output file\n");
			inflateEnd(&stream);
			return CL_EWRITE;
		    }
		    nbytes += written;
		    stream.next_out = (Bytef *)output;
		    stream.avail_out = sizeof(output);
		}
		continue;
	    case Z_STREAM_END:
		break;
	    default:
		if(stream.msg)
		    cli_dbgmsg("cli_pdf: after writing %lu bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
			       (unsigned long)nbytes,
			       stream.msg, obj->id>>8, obj->id&0xff);
		else
		    cli_dbgmsg("cli_pdf: after writing %lu bytes, got error %d inflating PDF stream in %u %u obj\n",
			       (unsigned long)nbytes, zstat, obj->id>>8, obj->id&0xff);
		pdf->flags |= 1 << BAD_FLATE;
		inflateEnd(&stream);
		return CL_CLEAN;
	}
	break;
    }

    if(stream.avail_out != sizeof(output)) {
	if(filter_writen(pdf, obj, fout, output, sizeof(output) - stream.avail_out, sum) < 0) {
	    cli_errmsg("cli_pdf: failed to write output file\n");
	    inflateEnd(&stream);
	    return CL_EWRITE;
	}
    }

    inflateEnd(&stream);
    return CL_CLEAN;
}

static struct pdf_obj *find_obj(struct pdf_struct *pdf,
				struct pdf_obj *obj, uint32_t objid)
{
    unsigned j;
    unsigned i;

    /* search starting at previous obj (if exists) */
    if (obj != pdf->objs)
	i = obj - pdf->objs;
    else
	i = 0;
    for (j=i;j<pdf->nobjs;j++) {
	obj = &pdf->objs[j];
	if (obj->id == objid)
	    return obj;
    }
    /* restart search from beginning if not found */
    for (j=0;j<i;j++) {
	obj = &pdf->objs[j];
	if (obj->id == objid)
	    return obj;
    }
    return NULL;
}

static int find_length(struct pdf_struct *pdf,
		       struct pdf_obj *obj,
		       const char *start, off_t len)
{
    int length;
    const char *q;
    q = cli_memstr(start, len, "/Length", 7);
    if (!q)
	return 0;
    q++;
    len -= q - start;
    start = pdf_nextobject(q, len);
    if (!start)
	return 0;
    /* len -= start - q; */
    q = start;
    length = atoi(q);
    while (isdigit(*q)) q++;
    if (*q == ' ') {
	int genid;
	q++;
	genid = atoi(q);
	while(isdigit(*q)) q++;
	if (q[0] == ' ' && q[1] == 'R') {
	    cli_dbgmsg("cli_pdf: length is in indirect object %u %u\n", length, genid);
	    obj = find_obj(pdf, obj, (length << 8) | (genid&0xff));
	    if (!obj) {
		cli_dbgmsg("cli_pdf: indirect object not found\n");
		return 0;
	    }
	    q = pdf_nextobject(pdf->map+obj->start, pdf->size - obj->start);
	    length = atoi(q);
	}
    }
    /* limit length */
    if (start - pdf->map + length+5 > pdf->size) {
	length = pdf->size - (start - pdf->map)-5;
    }
    return length;
}

#define DUMP_MASK ((1 << OBJ_FILTER_FLATE) | (1 << OBJ_FILTER_AH) | (1 << OBJ_FILTER_A85) | (1 << OBJ_EMBEDDED_FILE) | (1 << OBJ_JAVASCRIPT))

static int obj_size(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    unsigned i = obj - pdf->objs;
    i++;
    if (i < pdf->nobjs) {
	int s = pdf->objs[i].start - obj->start - 4;
	if (s > 0)
	    return s;
    }
    return pdf->size - obj->start;
}

static int pdf_extract_obj(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    char fullname[NAME_MAX + 1];
    int fout;
    off_t sum = 0;
    int rc = CL_SUCCESS;
    char *ascii_decoded = NULL;

    if (!(obj->flags & DUMP_MASK)) {
	/* don't dump all streams */
	return CL_CLEAN;
    }
    snprintf(fullname, sizeof(fullname), "%s"PATHSEP"pdf%02u", pdf->dir, pdf->files++);
    fout = open(fullname,O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
    if (fout < 0) {
	char err[128];
	cli_errmsg("cli_pdf: can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
	free(ascii_decoded);
	return CL_ETMPFILE;
    }

    do {
    if (obj->flags & (1 << OBJ_STREAM)) {
	const char *start = pdf->map + obj->start;
	off_t p_stream = 0, p_endstream = 0;
	off_t length;
	find_stream_bounds(start, pdf->size - obj->start,
			   pdf->size - obj->start,
			   &p_stream, &p_endstream);
	if (p_stream && p_endstream) {
	    int rc2;
	    const char *flate_in;
	    long ascii_decoded_size = 0;
	    size_t size = p_endstream - p_stream;

	    length = find_length(pdf, obj, start, p_stream);
	    if (!(obj->flags & (1 << OBJ_FILTER_FLATE)) && !length) {
		const char *q = start + p_endstream;
		length = size;
		q--;
		if (*q == '\n') {
		    q--;
		    length--;
		    if (*q == '\r')
			length--;
		} else if (*q == '\r') {
		    length--;
		}
		cli_dbgmsg("cli_pdf: calculated length %ld\n", length);
	    }
	    if (!length)
		length = size;

	    if (obj->flags & (1 << OBJ_FILTER_AH)) {
		ascii_decoded = cli_malloc(length/2 + 1);
		if (!ascii_decoded) {
		    cli_errmsg("Cannot allocate memory for asciidecode\n");
		    rc = CL_EMEM;
		    break;
		}
		ascii_decoded_size = asciihexdecode(start + p_stream,
						    length,
						    ascii_decoded);
	    } else if (obj->flags & (1 << OBJ_FILTER_A85)) {
		ascii_decoded = cli_malloc(length*5);
		if (!ascii_decoded) {
		    cli_errmsg("Cannot allocate memory for asciidecode\n");
		    rc = CL_EMEM;
		    break;
		}
		ascii_decoded_size = ascii85decode(start+p_stream,
						   length,
						   (unsigned char*)ascii_decoded);
	    }
	    if (ascii_decoded_size < 0) {
		pdf->flags |= 1 << BAD_ASCIIDECODE;
		cli_dbgmsg("cli_pdf: failed to asciidecode in %u %u obj\n", obj->id>>8,obj->id&0xff);
		rc = CL_CLEAN;
		break;
	    }
	    /* either direct or ascii-decoded input */
	    if (!ascii_decoded)
		ascii_decoded_size = length;
	    flate_in = ascii_decoded ? ascii_decoded : start+p_stream;

	    if (obj->flags & (1 << OBJ_FILTER_FLATE)) {
		rc = filter_flatedecode(pdf, obj, flate_in, ascii_decoded_size, fout, &sum);
	    } else {
		if (filter_writen(pdf, obj, fout, flate_in, ascii_decoded_size, &sum) != ascii_decoded_size)
		    rc = CL_EWRITE;
	    }
	    cli_updatelimits(pdf->ctx, sum);
	    /* TODO: invoke bytecode on this pdf obj with metainformation associated
	     * */
	    cli_dbgmsg("cli_pdf: extracted %ld bytes %u %u obj to %s\n", sum, obj->id>>8, obj->id&0xff, fullname);
	    lseek(fout, 0, SEEK_SET);
	    rc2 = cli_magic_scandesc(fout, pdf->ctx);
	    if (rc2 == CL_VIRUS || rc == CL_SUCCESS)
		rc = rc2;
	}
    } else if (obj->flags & (1 << OBJ_JAVASCRIPT)) {
	const char *q2;
	const char *q = pdf->map+obj->start;
	/* TODO: get obj-endobj size */
	off_t bytesleft = obj_size(pdf, obj);
	if (bytesleft < 0)
	    break;

	q2 = cli_memstr(q, bytesleft, "/JavaScript", 11);
	if (!q2)
	    break;
	q2++;
	bytesleft -= q2 - q;
	q = pdf_nextobject(q2, bytesleft);
	if (!q)
	    break;
	bytesleft -= q - q2;
	if (*q == '(') {
	    if (filter_writen(pdf, obj, fout, q+1, bytesleft-1, &sum) != (bytesleft-1)) {
		rc = CL_EWRITE;
		break;
	    }
	} else if (*q == '<') {
	    char *decoded;
	    q2 = memchr(q+1, '>', bytesleft);
	    if (!q2) q2 = q + bytesleft;
	    decoded = cli_malloc(q2 - q);
	    if (!decoded) {
		rc = CL_EMEM;
		break;
	    }
	    cli_hex2str_to(q2, decoded, q2-q-1);
	    decoded[q2-q-1] = '\0';
	    cli_dbgmsg("cli_pdf: found hexadecimal encoded javascript in %u %u obj\n",
		       obj->id>>8, obj->id&0xff);
	    pdf->flags |= 1 << HEX_JAVASCRIPT;
	    filter_writen(pdf, obj, fout, decoded, q2-q-1, &sum);
	    free(decoded);
	}
    }
    } while (0);
    close(fout);
    free(ascii_decoded);
    if (!pdf->ctx->engine->keeptmp)
	if (cli_unlink(fullname) && rc != CL_VIRUS)
	    rc = CL_EUNLINK;
    return rc;
}

static void pdfobj_flag(struct pdf_struct *pdf, struct pdf_obj *obj, enum pdf_flag flag)
{
    const char *s;
    pdf->flags |= 1 << flag;
    if (!cli_debug_flag)
	return;
    switch (flag) {
	case UNTERMINATED_OBJ_DICT:
	    s = "dictionary not terminated";
	    break;
	case ESCAPED_COMMON_PDFNAME:
	    /* like /JavaScript */
	    s = "escaped common pdfname";
	    break;
	case BAD_STREAM_FILTERS:
	    s = "duplicate stream filters";
	    break;
	default:
	case BAD_PDF_VERSION:
	case BAD_PDF_HEADERPOS:
	case BAD_PDF_TRAILER:
	case BAD_PDF_TOOMANYOBJS:
	    return;
    }
    cli_dbgmsg("cli_pdf: %s in object %u %u\n", s, obj->id>>8, obj->id&0xff);
}

enum objstate {
    STATE_NONE,
    STATE_S,
    STATE_FILTER,
    STATE_JAVASCRIPT,
    STATE_ANY /* for actions table below */
};

struct pdfname_action {
    const char *pdfname;
    enum objflags set_objflag;/* OBJ_DICT is noop */
    enum objstate from_state;/* STATE_NONE is noop */
    enum objstate to_state;
};

static struct pdfname_action pdfname_actions[] = {
    {"ASCIIHexDecode", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER},
    {"ASCII85Decode", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER},
    {"EmbeddedFile", OBJ_EMBEDDED_FILE, STATE_NONE, STATE_NONE},
    {"FlateDecode", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER},
    {"LZWDecode", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER},
    {"RunLengthDecode", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER},
    {"CCITTFaxDecode", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER},
    {"JBIG2Decode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER},
    {"DCTDecode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER},
    {"JPXDecode", OBJ_FILTER_JPX, STATE_FILTER, STATE_FILTER},
    {"Crypt",  OBJ_FILTER_CRYPT, STATE_FILTER, STATE_NONE},
    {"Filter", OBJ_DICT, STATE_ANY, STATE_FILTER},
    {"JavaScript", OBJ_JAVASCRIPT, STATE_S, STATE_JAVASCRIPT},
    {"Length", OBJ_DICT, STATE_FILTER, STATE_NONE},
    {"S", OBJ_DICT, STATE_NONE, STATE_S},
    {"Type", OBJ_DICT, STATE_NONE, STATE_NONE}
};

static void handle_pdfname(struct pdf_struct *pdf, struct pdf_obj *obj,
			   const char *pdfname, int escapes,
			   enum objstate *state)
{
    struct pdfname_action *act = NULL;
    unsigned j;
    for (j=0;j<sizeof(pdfname_actions)/sizeof(pdfname_actions[0]);j++) {
	if (!strcmp(pdfname, pdfname_actions[j].pdfname)) {
	    act = &pdfname_actions[j];
	    break;
	}
    }
    if (!act)
	return;
    if (escapes) {
	/* if a commonly used PDF name is escaped that is certainly
	   suspicious. */
	cli_dbgmsg("cli_pdf: pdfname %s is escaped\n", pdfname);
	pdfobj_flag(pdf, obj, ESCAPED_COMMON_PDFNAME);
    }
    if (act->from_state == *state ||
	act->from_state == STATE_ANY) {
	*state = act->to_state;

	if (*state == STATE_FILTER &&
	    act->set_objflag !=OBJ_DICT &&
	    (obj->flags & (1 << act->set_objflag))) {
	    pdfobj_flag(pdf, obj, BAD_STREAM_FILTERS);
	}
	obj->flags |= 1 << act->set_objflag;
    } else {
	/* auto-reset states */
	switch (*state) {
	    case STATE_S:
		*state = STATE_NONE;
		break;
	    default:
		break;
	}
    }
}

static void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    /* enough to hold common pdf names, we don't need all the names */
    char pdfname[64];
    const char *q2, *q3;
    const char *q = obj->start + pdf->map;
    const char *dict, *start;
    off_t dict_length;
    off_t bytesleft = pdf->offset - obj->start;
    unsigned i;
    enum objstate objstate = STATE_NONE;

    if (bytesleft < 0)
	return;
    start = q;
    /* find start of dictionary */
    do {
	q2 = pdf_nextobject(q, bytesleft);
	bytesleft -= q2 -q;
	if (!q2 || bytesleft < 0) {
	    return;
	}
	q3 = memchr(q-1, '<', q2-q+1);
	q2++;
	bytesleft--;
	q = q2;
    } while (!q3 || q3[1] != '<');
    dict = q3+2;
    q = dict;
    bytesleft = pdf->offset - obj->start - (q3 - start);
    /* find end of dictionary */
    do {
	q2 = pdf_nextobject(q, bytesleft);
	bytesleft -= q2 -q;
	if (!q2 || bytesleft < 0) {
	    return;
	}
	q3 = memchr(q-1, '>', q2-q+1);
	q2++;
	bytesleft--;
	q = q2;
    } while (!q3 || q3[1] != '>');
    obj->flags |= 1 << OBJ_DICT;
    dict_length = q3 - dict;

    /*  process pdf names */
    for (q = dict;dict_length;) {
	int escapes = 0;
	q2 = memchr(q, '/', dict_length);
	if (!q2)
	    break;
	dict_length -= q2 - q;
	q = q2;
	/* normalize PDF names */
	for (i = 0;dict_length && (i < sizeof(pdfname)-1); i++) {
	    q++;
	    dict_length--;
	    if (*q == '#') {
		cli_hex2str_to(q+1, pdfname+i, 2);
		q += 2;
		dict_length -= 2;
		escapes = 1;
		continue;
	    }
	    if (*q == ' ' || *q == '\r' || *q == '\n' || *q == '/')
		break;
	    pdfname[i] = *q;
	}
	pdfname[i] = '\0';

	handle_pdfname(pdf, obj, pdfname, escapes, &objstate);
	if (objstate == STATE_JAVASCRIPT) {
	    q2 = pdf_nextobject(q, dict_length);
	    if (q2 && isdigit(*q2)) {
		uint32_t objid = atoi(q2) << 8;
		while (isdigit(*q2)) q2++;
		q2 = pdf_nextobject(q2, dict_length);
		if (q2 && isdigit(*q2)) {
		    objid |= atoi(q2) & 0xff;
		    q2 = pdf_nextobject(q2, dict_length);
		    if (*q2 == 'R') {
			struct pdf_obj *obj2;
			cli_dbgmsg("cli_pdf: found javascript stored in indirect object %u %u",
				   objid >> 8, objid&0xff);
			obj2 = find_obj(pdf, obj, objid);
			obj2->flags |= OBJ_JAVASCRIPT;
		    }
		}
	    }
	    objstate = STATE_NONE;
	}
    }
    cli_dbgmsg("cli_pdf: %u %u obj flags: %02x\n", obj->id>>8, obj->id&0xff, obj->flags);
}

int cli_pdf(const char *dir, cli_ctx *ctx, off_t offset)
{
    struct pdf_struct pdf;
    fmap_t *map = *ctx->fmap;
    size_t size = map->len - offset;
    off_t versize = size > 1032 ? 1032 : size;
    off_t map_off, bytesleft;
    long xref;
    const char *pdfver, *start, *eofmap, *q, *eof;
    int rc;
    unsigned i;

    cli_dbgmsg("in cli_pdf(%s)\n", dir);
    memset(&pdf, 0, sizeof(pdf));
    pdf.ctx = ctx;
    pdf.dir = dir;

    pdfver = start = fmap_need_off_once(map, offset, versize);

    /* Check PDF version */
    if (!pdfver) {
	cli_errmsg("cli_pdf: mmap() failed (1)\n");
	return CL_EMAP;
    }
    /* offset is 0 when coming from filetype2 */
    pdfver = cli_memstr(pdfver, versize, "%PDF-", 5);
    if (!pdfver) {
	cli_dbgmsg("cli_pdf: no PDF- header found\n");
	return CL_SUCCESS;
    }
    /* Check for PDF-1.[0-9]. Although 1.7 is highest now, allow for future
     * versions */
    if (pdfver[5] != '1' || pdfver[6] != '.' ||
	pdfver[7] < '1' || pdfver[7] > '9') {
	pdf.flags |= 1 << BAD_PDF_VERSION;
	cli_dbgmsg("cli_pdf: bad pdf version: %.8s\n", pdfver);
    }
    if (pdfver != start || offset) {
	pdf.flags |= 1 << BAD_PDF_HEADERPOS;
	cli_dbgmsg("cli_pdf: PDF header is not at position 0: %ld\n",pdfver-start+offset);
    }
    offset += pdfver - start;

    /* find trailer and xref, don't fail if not found */
    map_off = map->len - 2048;
    if (map_off < 0)
	map_off = 0;
    bytesleft = map->len - map_off;
    eofmap = fmap_need_off_once(map, map_off, bytesleft);
    if (!eofmap) {
	cli_errmsg("cli_pdf: mmap() failed (2)\n");
	return CL_EMAP;
    }
    eof = eofmap + bytesleft;
    for (q=&eofmap[bytesleft-5]; q > eofmap; q--) {
	if (memcmp(q, "%%EOF", 5) == 0)
	    break;
    }
    if (q <= eofmap) {
	pdf.flags |= 1 << BAD_PDF_TRAILER;
	cli_dbgmsg("cli_pdf: %%%%EOF not found\n");
    } else {
	size = q - eofmap + map_off;
	for (;q > eofmap;q--) {
	    if (memcmp(q, "startxref", 9) == 0)
		break;
	}
	if (q <= eofmap) {
	    pdf.flags |= 1 << BAD_PDF_TRAILER;
	    cli_dbgmsg("cli_pdf: startxref not found\n");
	}
	q += 9;
	while (q < eof && (*q == ' ' || *q == '\n' || *q == '\r')) { q++; }
	xref = atol(q);
	bytesleft = map->len - offset - xref;
	if (bytesleft > 4096)
	    bytesleft = 4096;
	q = fmap_need_off_once(map, offset + xref, bytesleft);
	if (!q || xrefCheck(q, q+bytesleft) == -1) {
	    cli_dbgmsg("cli_pdf: did not find valid xref\n");
	    pdf.flags |= 1 << BAD_PDF_TRAILER;
	}
    }
    size -= offset;

    pdf.size = size;
    pdf.map = fmap_need_off_once(map, offset, size);
    if (!pdf.map) {
	cli_errmsg("cli_pdf: mmap() failed (3)\n");
	return CL_EMAP;
    }
    /* parse PDF and find obj offsets */
    while ((rc = pdf_findobj(&pdf)) > 0) {
	struct pdf_obj *obj = &pdf.objs[pdf.nobjs-1];
	cli_dbgmsg("found %d %d obj @%ld\n", obj->id >> 8, obj->id&0xff, obj->start + offset);
	pdf_parseobj(&pdf, obj);
    }
    if (rc == -1)
	pdf.flags |= 1 << BAD_PDF_TOOMANYOBJS;

    /* extract PDF objs */
    for (i=0;i<pdf.nobjs;i++) {
	struct pdf_obj *obj = &pdf.objs[i];
	rc = pdf_extract_obj(&pdf, obj);
	if (rc != CL_SUCCESS)
	    break;
    }

    if (pdf.flags) {
	cli_dbgmsg("cli_pdf: flags 0x%02x\n", pdf.flags);
	if (pdf.flags & (1 << ESCAPED_COMMON_PDFNAME)) {
	    /* for example /Fl#61te#44#65#63#6f#64#65 instead of /FlateDecode */
	    *ctx->virname = "Heuristics.PDF.ObfuscatedNameObject";
	    rc = CL_VIRUS;
	}
    }
    cli_dbgmsg("cli_pdf: returning %d\n", rc);
    free(pdf.objs);
    return rc;
}

#else
static	int	try_flatedecode(unsigned char *buf, off_t real_len, off_t calculated_len, int fout, cli_ctx *ctx);
static	int	flatedecode(unsigned char *buf, off_t len, int fout, cli_ctx *ctx);
int
cli_pdf(const char *dir, cli_ctx *ctx, off_t offset)
{
	off_t size;	/* total number of bytes in the file */
	off_t bytesleft, trailerlength;
	char *buf;	/* start of memory mapped area */
	const char *p, *q, *trailerstart;
	const char *xrefstart;	/* cross reference table */
	/*size_t xreflength;*/
	int printed_predictor_message, printed_embedded_font_message, rc;
	unsigned int files;
	fmap_t *map = *ctx->fmap;
	int opt_failed = 0;

	cli_dbgmsg("in cli_pdf(%s)\n", dir);
	size = map->len - offset;

	if(size <= 7)	/* doesn't even include the file header */
		return CL_CLEAN;

	p = buf = fmap_need_off_once(map, 0, size); /* FIXME: really port to fmap */
	if(!buf) {
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
	    cli_dbgmsg("cli_pdf: file header not found\n");
	    return CL_CLEAN;
	}

	/* Find the file trailer */
	for(q = &p[bytesleft - 5]; q > p; --q)
		if(strncasecmp(q, "%%EOF", 5) == 0)
			break;

	if(q <= p) {
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
	if(cli_memstr(trailerstart, trailerlength, "Encrypt", 7)) {
		/*
		 * This tends to mean that the file is, in effect, read-only
		 * http://www.cs.cmu.edu/~dst/Adobe/Gallery/anon21jul01-pdf-encryption.txt
		 * http://www.adobe.com/devnet/pdf/
		 */
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
		cli_dbgmsg("cli_pdf: xref not found\n");
		return CL_CLEAN;
	}

	printed_predictor_message = printed_embedded_font_message = 0;

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
		objend = cli_memstr(p, bytesleft, "endobj", 6);
		if(objend == NULL) {
			cli_dbgmsg("cli_pdf: No matching endobj\n");
			break;
		}
		bytesleft -= (off_t)((objend - p) + 6);
		p = &objend[6];
		objlen = (unsigned long)(objend - objstart);

		/* Is this object a stream? */
		streamstart = cli_memstr(objstart, objlen, "stream", 6);
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
						char b[14];

						q += 4;
						cli_dbgmsg("cli_pdf: Length is in indirect obj %lu\n",
							length);
						snprintf(b, sizeof(b),
							"%lu 0 obj", length);
						length = (unsigned long)strlen(b);
						/* optimization: assume objects
						 * are sequential */
						if(!opt_failed) {
						    nq = q;
						    len = buf + size - q;
						} else {
						    nq = buf;
						    len = q - buf;
						}
						do {
							r = cli_memstr(nq, len, b, length);
							if (r > nq) {
								const char x = *(r-1);
								if (x == '\n' || x=='\r') {
									--r;
									break;
								}
							}
							if (r) {
								len -= r + length - nq;
								nq = r + length;
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
		streamend = cli_memstr(streamstart, len, "endstream\n", 10);
		if(streamend == NULL) {
			streamend = cli_memstr(streamstart, len, "endstream\r", 10);
			if(streamend == NULL) {
				cli_dbgmsg("cli_pdf: No endstream\n");
				break;
			}
			has_cr = 1;
		} else
			has_cr = 0;
		snprintf(fullname, sizeof(fullname), "%s"PATHSEP"pdf%02u", dir, files);
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
				unsigned size;

				real_streamlen = ret;
				/* free unused trailing bytes */
				size = real_streamlen > calculated_streamlen ? real_streamlen : calculated_streamlen;
				t = (unsigned char *)cli_realloc(tmpbuf,size);
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
			rc = cli_magic_scandesc(fout, ctx);
		}
		close(fout);
		if(!ctx->engine->keeptmp)
			if (cli_unlink(fullname)) rc = CL_EUNLINK;
		if(rc != CL_CLEAN) break;
	}


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
#endif

static int asciihexdecode(const char *buf, off_t len, char *output)
{
    unsigned i,j;
    for (i=0,j=0;i<len;i++) {
	if (buf[i] == ' ')
	    continue;
	if (buf[i] == '>')
	    break;
	cli_hex2str_to(buf+i, output+j++, 2);
	i++;
    }
    return j;
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

	if(cli_memstr(buf, len, "~>", 2) == NULL)
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
			}
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
