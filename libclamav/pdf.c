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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "clamav.h"
#include "others.h"
#include "pdf.h"
#include "scanners.h"
#include "fmap.h"
#include "str.h"
#include "bytecode.h"
#include "bytecode_api.h"
#include "arc4.h"
#include "rijndael.h"
#include "textnorm.h"


#ifdef	CL_DEBUG
/*#define	SAVE_TMP	
 *Save the file being worked on in tmp */
#endif

static	int	asciihexdecode(const char *buf, off_t len, char *output);
static	int	ascii85decode(const char *buf, off_t len, unsigned char *output);
static	const	char	*pdf_nextlinestart(const char *ptr, size_t len);
static	const	char	*pdf_nextobject(const char *ptr, size_t len);

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

enum enc_method {
    ENC_UNKNOWN,
    ENC_NONE,
    ENC_IDENTITY,
    ENC_V2,
    ENC_AESV2,
    ENC_AESV3
};

struct pdf_struct {
    struct pdf_obj *objs;
    unsigned nobjs;
    unsigned flags;
    unsigned enc_method_stream;
    unsigned enc_method_string;
    unsigned enc_method_embeddedfile;
    const char *CF;
    long CF_n;
    const char *map;
    off_t size;
    off_t offset;
    off_t startoff;
    cli_ctx *ctx;
    const char *dir;
    unsigned files;
    uint32_t enc_objid;
    char *fileID;
    unsigned fileIDlen;
    char *key;
    unsigned keylen;
};

/* define this to be noisy about things that we can't parse properly */
/*#define NOISY*/

#ifdef NOISY
#define noisy_msg(pdf, ...) cli_infomsg(pdf->ctx, __VA_ARGS__)
#define noisy_warnmsg cli_warnmsg
#else
#define noisy_msg (void)
#define noisy_warnmsg (void)
#endif

static const char *findNextNonWSBack(const char *q, const char *start)
{
    while (q > start &&
	   (*q == 0 || *q == 9 || *q == 0xa || *q == 0xc || *q == 0xd || *q == 0x20))
    {
	q--;
    }
    return q;
}

static int find_stream_bounds(const char *start, off_t bytesleft, off_t bytesleft2, off_t *stream, off_t *endstream,
			      int newline_hack)
{
    const char *q2, *q;
    if ((q2 = cli_memstr(start, bytesleft, "stream", 6))) {
	q2 += 6;
	bytesleft -= q2 - start;
	if (bytesleft < 0)
	    return 0;
	if (bytesleft >= 2 && q2[0] == '\xd' && q2[1] == '\xa') {
	    q2 += 2;
	    if (newline_hack && (bytesleft > 2) && q2[0] == '\xa')
		q2++;
	} else if (bytesleft && q2[0] == '\xa')
	    q2++;
	*stream = q2 - start;
	bytesleft2 -= q2 - start;
	if (bytesleft2 <= 0)
	    return 0;
	q = q2;
	q2 = cli_memstr(q, bytesleft2, "endstream", 9);
	if (!q2)
	    q2 = q + bytesleft2-9; /* till EOF */
	*endstream = q2 - start;
	if (*endstream < *stream)
	    *endstream = *stream;
	return 1;
    }
    return 0;
}

/* Expected returns: 1 if success, 0 if no more objects, -1 if error */
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
    while (bytesleft > 0) {
	q2 = cli_memstr(start, bytesleft, "obj", 3);
	if (!q2)
	    return 0;/* no more objs */
	q2--;
	bytesleft -= q2 - start;
	if (*q2 != 0 && *q2 != 9 && *q2 != 0xa && *q2 != 0xc && *q2 != 0xd && *q2 != 0x20) {
	    start = q2+4;
	    bytesleft -= 4;
	    continue;
	}
	break;
    }
    if (bytesleft <= 0)
	return 0;

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
	    q2 = pdf->map + pdf->size;
	bytesleft -= q2 - q;
	if (find_stream_bounds(q-1, q2-q, bytesleft + (q2-q), &p_stream, &p_endstream, 1)) {
	    obj->flags |= 1 << OBJ_STREAM;
	    q2 = q-1 + p_endstream + 9;
	    bytesleft -= q2 - q + 1;
	    if (bytesleft < 0) {
		obj->flags |= 1 << OBJ_TRUNCATED;
		pdf->offset = pdf->size;
		return 1;/* truncated */
	    }
	} else if ((q3 = cli_memstr(q-1, q2-q+1, "endobj", 6))) {
	    q2 = q3 + 6;
	    pdf->offset = q2 - pdf->map;
	    return 1; /* obj found and offset positioned */
	} else {
	    q2++;
	    bytesleft--;
	}
	q = q2;
    }
    obj->flags |= 1 << OBJ_TRUNCATED;
    pdf->offset = pdf->size;
    return 1;/* truncated */
}

static int filter_writen(struct pdf_struct *pdf, struct pdf_obj *obj,
			 int fout, const char *buf, off_t len, off_t *sum)
{
    if (cli_checklimits("pdf", pdf->ctx, *sum, 0, 0))
	return len; /* pretend it was a successful write to suppress CL_EWRITE */
    *sum += len;
    return cli_writen(fout, buf, len);
}

static void pdfobj_flag(struct pdf_struct *pdf, struct pdf_obj *obj, enum pdf_flag flag)
{
    const char *s= "";
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
	case BAD_PDF_VERSION:
	    s = "bad pdf version";
	    break;
	case BAD_PDF_HEADERPOS:
	    s = "bad pdf header position";
	    break;
	case BAD_PDF_TRAILER:
	    s = "bad pdf trailer";
	    break;
	case BAD_PDF_TOOMANYOBJS:
	    s = "too many pdf objs";
	    break;
	case BAD_FLATE:
	    s = "bad deflate stream";
	    break;
	case BAD_FLATESTART:
	    s = "bad deflate stream start";
	    break;
	case BAD_STREAMSTART:
	    s = "bad stream start";
	    break;
	case UNKNOWN_FILTER:
	    s = "unknown filter used";
	    break;
	case BAD_ASCIIDECODE:
	    s = "bad ASCII decode";
	    break;
	case HEX_JAVASCRIPT:
	    s = "hex javascript";
	    break;
	case BAD_INDOBJ:
	    s = "referencing nonexistent obj";
	    break;
	case HAS_OPENACTION:
	    s = "has /OpenAction";
	    break;
	case HAS_LAUNCHACTION:
	    s = "has /LaunchAction";
	    break;
	case BAD_STREAMLEN:
	    s = "bad /Length, too small";
	    break;
	case ENCRYPTED_PDF:
	    s = "PDF is encrypted";
	    break;
	case LINEARIZED_PDF:
	    s = "linearized PDF";
	    break;
	case MANY_FILTERS:
	    s = "more than 2 filters per obj";
	    break;
	case DECRYPTABLE_PDF:
	    s = "decryptable PDF";
	    break;
    }
    cli_dbgmsg("cli_pdf: %s flagged in object %u %u\n", s, obj->id>>8, obj->id&0xff);
}

static int filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj,
			      const char *buf, off_t len, int fout, off_t *sum)
{
    int skipped = 0;
    int zstat;
    z_stream stream;
    off_t nbytes;
    char output[BUFSIZ];

    if (len == 0)
	return CL_CLEAN;

    if (*buf == '\r') {
	buf++;
	len--;
	pdfobj_flag(pdf, obj, BAD_STREAMSTART);
	/* PDF spec says stream is followed by \r\n or \n, but not \r alone.
	 * Sample 0015315109, it has \r followed by zlib header.
	 * Flag pdf as suspicious, and attempt to extract by skipping the \r.
	 */
	if (!len)
	    return CL_CLEAN;
    }

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
	int written;
	zstat = inflate(&stream, Z_NO_FLUSH);	/* zlib */
	switch(zstat) {
	    case Z_OK:
		if(stream.avail_out == 0) {
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
	    default:
		written = sizeof(output) - stream.avail_out;
		if (!written && !nbytes && !skipped) {
		    /* skip till EOL, and try inflating from there, sometimes
		     * PDFs contain extra whitespace */
		    const char *q = pdf_nextlinestart(buf, len);
		    if (q) {
			skipped = 1;
			inflateEnd(&stream);
			len -= q - buf;
			buf = q;
			stream.next_in = (Bytef *)buf;
			stream.avail_in = len;
			stream.next_out = (Bytef *)output;
			stream.avail_out = sizeof(output);
			zstat = inflateInit(&stream);
			if(zstat != Z_OK) {
			    cli_warnmsg("cli_pdf: inflateInit failed\n");
			    return CL_EMEM;
			}
			pdfobj_flag(pdf, obj, BAD_FLATESTART);
			continue;
		    }
		}

		if (filter_writen(pdf, obj, fout, output, written, sum)!=written) {
		    cli_errmsg("cli_pdf: failed to write output file\n");
		    inflateEnd(&stream);
		    return CL_EWRITE;
		}
		nbytes += written;
		stream.next_out = (Bytef *)output;
		stream.avail_out = sizeof(output);
		if (zstat == Z_STREAM_END)
		    break;

		if(stream.msg)
		    cli_dbgmsg("cli_pdf: after writing %lu bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
			       (unsigned long)nbytes,
			       stream.msg, obj->id>>8, obj->id&0xff);
		else
		    cli_dbgmsg("cli_pdf: after writing %lu bytes, got error %d inflating PDF stream in %u %u obj\n",
			       (unsigned long)nbytes, zstat, obj->id>>8, obj->id&0xff);
		if(stream.msg)
		    noisy_warnmsg("cli_pdf: after writing %lu bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
			       (unsigned long)nbytes,
			       stream.msg, obj->id>>8, obj->id&0xff);
		else
		    noisy_warnmsg("cli_pdf: after writing %lu bytes, got error %d inflating PDF stream in %u %u obj\n",
			       (unsigned long)nbytes, zstat, obj->id>>8, obj->id&0xff);
		/* mark stream as bad only if not encrypted */
		inflateEnd(&stream);
		if (!nbytes) {
		    pdfobj_flag(pdf, obj, BAD_FLATESTART);
                    cli_dbgmsg("filter_flatedecode: No bytes, returning CL_EFORMAT for this stream.\n");
                    return CL_EFORMAT;
		} else {
		    pdfobj_flag(pdf, obj, BAD_FLATE);
		}
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
	    if (!q) {
		cli_dbgmsg("cli_pdf: next object not found\n");
		return 0;
	    }
	    length = atoi(q);
	}
    }
    /* limit length */
    if (start - pdf->map + length+5 > pdf->size) {
	length = pdf->size - (start - pdf->map)-5;
    }
    return length;
}

#define DUMP_MASK ((1 << OBJ_CONTENTS) | (1 << OBJ_FILTER_FLATE) | (1 << OBJ_FILTER_DCT) | (1 << OBJ_FILTER_AH) | (1 << OBJ_FILTER_A85) | (1 << OBJ_EMBEDDED_FILE) | (1 << OBJ_JAVASCRIPT) | (1 << OBJ_OPENACTION) | (1 << OBJ_LAUNCHACTION))

static int obj_size(struct pdf_struct *pdf, struct pdf_obj *obj, int binary)
{
    unsigned i = obj - pdf->objs;
    i++;
    if (i < pdf->nobjs) {
	int s = pdf->objs[i].start - obj->start - 4;
	if (s > 0) {
	    if (!binary) {
		const char *p = pdf->map + obj->start;
		const char *q = p + s;
		while (q > p && (isspace(*q) || isdigit(*q)))
		       q--;
		if (q > p+5 && !memcmp(q-5,"endobj",6))
		    q -= 6;
		q = findNextNonWSBack(q, p);
		q++;
		return q - p;
	    }
	    return s;
	}
    }
    if (binary)
	return pdf->size - obj->start;
    return pdf->offset - obj->start - 6;
}

static int run_pdf_hooks(struct pdf_struct *pdf, enum pdf_phase phase, int fd,
			 int dumpid)
{
    int ret;
    struct cli_bc_ctx *bc_ctx;
    cli_ctx *ctx = pdf->ctx;
    fmap_t *map;

    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
	cli_errmsg("cli_pdf: can't allocate memory for bc_ctx");
	return CL_EMEM;
    }

    map = *ctx->fmap;
    if (fd != -1) {
	map = fmap(fd, 0, 0);
	if (!map) {
	    cli_warnmsg("can't mmap pdf extracted obj\n");
	    map = *ctx->fmap;
	    fd = -1;
	}
    }
    cli_bytecode_context_setpdf(bc_ctx, phase, pdf->nobjs, pdf->objs,
				&pdf->flags, pdf->size, pdf->startoff);
    cli_bytecode_context_setctx(bc_ctx, ctx);
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PDF, map);
    cli_bytecode_context_destroy(bc_ctx);
    if (fd != -1) {
	funmap(map);
    }
    return ret;
}

static void dbg_printhex(const char *msg, const char *hex, unsigned len);
static void aes_decrypt(const unsigned char *in, off_t *length, unsigned char *q, char *key, unsigned key_n, int has_iv)
{
    unsigned long rk[RKLENGTH(256)];
    unsigned char iv[16];
    unsigned len = *length;
    unsigned char pad, i;
    int nrounds;

    cli_dbgmsg("cli_pdf: aes_decrypt: key length: %d, data length: %d\n", key_n, (int)*length);
    if (key_n > 32) {
	cli_dbgmsg("cli_pdf: aes_decrypt: key length is %d!\n", key_n*8);
	return;
    }
    if (len < 32) {
	cli_dbgmsg("cli_pdf: aes_decrypt: len is <32: %d\n", len);
	noisy_warnmsg("cli_pdf: aes_decrypt: len is <32: %d\n", len);
	return;
    }
    if (has_iv) {
	memcpy(iv, in, 16);
	in += 16;
	len -= 16;
    } else
	memset(iv, 0, sizeof(iv));

    cli_dbgmsg("aes_decrypt: Calling rijndaelSetupDecrypt\n");
    nrounds = rijndaelSetupDecrypt(rk, key, key_n*8);
    cli_dbgmsg("aes_decrypt: Beginning rijndaelDecrypt\n");
    while (len >= 16) {
	unsigned i;
	rijndaelDecrypt(rk, nrounds, in, q);
	for (i=0;i<16;i++)
	    q[i] ^= iv[i];
	memcpy(iv, in, 16);
	q += 16;
	in += 16;
	len -= 16;
    }
    if (has_iv) {
	len += 16;
	pad = q[-1];
	if (pad > 0x10) {
	    cli_dbgmsg("cli_pdf: aes_decrypt: bad pad: %x (extra len: %d)\n", pad, len-16);
	    noisy_warnmsg("cli_pdf: aes_decrypt: bad pad: %x (extra len: %d)\n", pad, len-16);
	    *length -= len;
	    return;
	}
	q -= pad;
	for (i=1;i<pad;i++) {
	    if (q[i] != pad) {
		cli_dbgmsg("cli_pdf: aes_decrypt: bad pad: %x != %x\n",q[i],pad);
		noisy_warnmsg("cli_pdf: aes_decrypt: bad pad: %x != %x\n",q[i],pad);
		*length -= len;
		return;
	    }
	}
	len += pad;
    }
    *length -= len;
    cli_dbgmsg("cli_pdf: aes_decrypt: length is %d\n", (int)*length);
}


static char *decrypt_any(struct pdf_struct *pdf, uint32_t id, const char *in, off_t *length,
			 enum enc_method enc_method)
{
    unsigned char *key, *q, result[16];
    unsigned n;
    struct arc4_state arc4;

    if (!length || !*length || !in) {
	noisy_warnmsg("decrypt failed for obj %u %u\n", id>>8, id&0xff);
	return NULL;
    }
    n = pdf->keylen + 5;
    if (enc_method == ENC_AESV2)
	n += 4;
    key = cli_malloc(n);
    if (!key) {
	noisy_warnmsg("decrypt_any: malloc failed\n");
	return NULL;
    }

    memcpy(key, pdf->key, pdf->keylen);
    q = key + pdf->keylen;
    *q++ = id >> 8;
    *q++ = id >> 16;
    *q++ = id >> 24;
    *q++ = id;
    *q++ = 0;
    if (enc_method == ENC_AESV2)
	memcpy(q, "sAlT", 4);
    cl_hash_data("md5", key, n, result, NULL);
    free(key);

    n = pdf->keylen + 5;
    if (n > 16)
	n = 16;

    q = cli_malloc(*length);
    if (!q) {
	noisy_warnmsg("decrypt_any: malloc failed\n");
	return NULL;
    }

    switch (enc_method) {
	case ENC_V2:
	    cli_dbgmsg("cli_pdf: enc is v2\n");
	    memcpy(q, in, *length);
	    arc4_init(&arc4, result, n);
	    arc4_apply(&arc4, q, *length);
	    noisy_msg(pdf, "decrypted ARC4 data\n");
	    break;
	case ENC_AESV2:
	    cli_dbgmsg("cli_pdf: enc is aesv2\n");
	    aes_decrypt(in, length, q, result, n, 1);
	    noisy_msg(pdf, "decrypted AES(v2) data\n");
	    break;
	case ENC_AESV3:
	    cli_dbgmsg("cli_pdf: enc is aesv3\n");
	    if (pdf->keylen == 0) {
	        cli_dbgmsg("cli_pdf: no key\n");
	        return NULL;
	    }
	    aes_decrypt(in, length, q, pdf->key, pdf->keylen, 1);
	    noisy_msg(pdf, "decrypted AES(v3) data\n");
	    break;
	case ENC_IDENTITY:
	    cli_dbgmsg("cli_pdf: enc is identity\n");
	    memcpy(q, in, *length);
	    noisy_msg(pdf, "identity encryption\n");
	    break;
	case ENC_NONE:
	    cli_dbgmsg("cli_pdf: enc is none\n");
	    noisy_msg(pdf, "encryption is none\n");
	    free(q);
	    return NULL;
	case ENC_UNKNOWN:
	    cli_dbgmsg("cli_pdf: enc is unknown\n");
	    free(q);
	    noisy_warnmsg("decrypt_any: unknown encryption method for obj %u %u\n",
		       id>>8,id&0xff);
	    return NULL;
    }
    return q;
}

static enum enc_method get_enc_method(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    if (obj->flags & (1 << OBJ_EMBEDDED_FILE))
	return pdf->enc_method_embeddedfile;
    if (obj->flags & (1 << OBJ_STREAM))
	return pdf->enc_method_stream;
    return pdf->enc_method_string;
}

enum cstate {
    CSTATE_NONE,
    CSTATE_TJ,
    CSTATE_TJ_PAROPEN
};

static void process(struct text_norm_state *s, enum cstate *st, const char *buf, int length, int fout)
{
    do {
	switch (*st) {
	    case CSTATE_NONE:
		if (*buf == '[') *st = CSTATE_TJ;
		else {
		    const char *nl = memchr(buf, '\n', length);
		    if (!nl)
			return;
		    length -= nl - buf;
		    buf = nl;
		}
		break;
	    case CSTATE_TJ:
		if (*buf == '(') *st = CSTATE_TJ_PAROPEN;
		break;
	    case CSTATE_TJ_PAROPEN:
		if (*buf == ')') *st = CSTATE_TJ;
		else {
		    if (text_normalize_buffer(s, buf, 1) != 1) {
			cli_writen(fout, s->out, s->out_pos);
			text_normalize_reset(s);
		    }
		}
		break;
	}
	buf++;
	length--;
    } while (length > 0);
}

static int pdf_scan_contents(int fd, struct pdf_struct *pdf)
{
    struct text_norm_state s;
    char fullname[1024];
    char outbuff[BUFSIZ];
    char inbuf[BUFSIZ];
    int fout, n, rc;
    enum cstate st = CSTATE_NONE;

    snprintf(fullname, sizeof(fullname), "%s"PATHSEP"pdf%02u_c", pdf->dir, (pdf->files-1));
    fout = open(fullname,O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
    if (fout < 0) {
	char err[128];
	cli_errmsg("cli_pdf: can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
	return CL_ETMPFILE;
    }

    text_normalize_init(&s, outbuff, sizeof(outbuff));
    while (1) {
	n = cli_readn(fd, inbuf, sizeof(inbuf));
	if (n <= 0)
	    break;
	process(&s, &st, inbuf, n, fout);
    }
    cli_writen(fout, s.out, s.out_pos);

    lseek(fout, 0, SEEK_SET);
    rc = cli_magic_scandesc(fout, pdf->ctx);
    close(fout);
    if (!pdf->ctx->engine->keeptmp)
	if (cli_unlink(fullname) && rc != CL_VIRUS)
	    rc = CL_EUNLINK;
    return rc;
}

static const char *pdf_getdict(const char *q0, int* len, const char *key);
static char *pdf_readval(const char *q, int len, const char *key);
static enum enc_method parse_enc_method(const char *dict, unsigned len, const char *key, enum enc_method def);
static char *pdf_readstring(const char *q0, int len, const char *key, unsigned *slen, const char **qend, int noescape);

static int pdf_extract_obj(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    char fullname[NAME_MAX + 1];
    int fout;
    off_t sum = 0;
    int rc = CL_SUCCESS;
    char *ascii_decoded = NULL;
    char *decrypted = NULL;
    int dump = 1;

    cli_dbgmsg("pdf_extract_obj: obj %u %u\n", obj->id>>8, obj->id&0xff);

    /* TODO: call bytecode hook here, allow override dumpability */
    if ((!(obj->flags & (1 << OBJ_STREAM)) ||
	(obj->flags & (1 << OBJ_HASFILTERS)))
	&& !(obj->flags & DUMP_MASK)) {
	/* don't dump all streams */
	dump = 0;
    }
    if ((obj->flags & (1 << OBJ_IMAGE)) &&
	!(obj->flags & (1 << OBJ_FILTER_DCT))) {
	/* don't dump / scan non-JPG images */
	dump = 0;
    }
    if (obj->flags & (1 << OBJ_FORCEDUMP)) {
	/* bytecode can force dump by setting this flag */
	dump = 1;
    }
    if (!dump)
	return CL_CLEAN;
    cli_dbgmsg("cli_pdf: dumping obj %u %u\n", obj->id>>8, obj->id&0xff);
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
        const char *flate_orig;
	off_t p_stream = 0, p_endstream = 0;
	off_t length, flate_orig_length;
	find_stream_bounds(start, pdf->size - obj->start,
			   pdf->size - obj->start,
			   &p_stream, &p_endstream,
			   pdf->enc_method_stream <= ENC_IDENTITY &&
			   pdf->enc_method_embeddedfile <= ENC_IDENTITY);
	if (p_stream && p_endstream) {
	    const char *flate_in;
	    long ascii_decoded_size = 0;
	    size_t size = p_endstream - p_stream;
	    off_t orig_length;

	    length = find_length(pdf, obj, start, p_stream);
	    if (length < 0)
		length = 0;
	    orig_length = length;
	    if (length > pdf->size || obj->start + p_stream + length > pdf->size) {
		cli_dbgmsg("cli_pdf: length out of file: %ld + %ld > %ld\n",
			   p_stream, length, pdf->size);
		noisy_warnmsg("length out of file, truncated: %ld + %ld > %ld\n",
			   p_stream, length, pdf->size);
		length = pdf->size - (obj->start + p_stream);
	    }
	    if (!(obj->flags & (1 << OBJ_FILTER_FLATE)) && length <= 0) {
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
		if (length < 0)
		    length = 0;
		cli_dbgmsg("cli_pdf: calculated length %ld\n", length);
	    } else {
		if (size > length+2) {
		    cli_dbgmsg("cli_pdf: calculated length %ld < %ld\n",
			       length, size);
		    length = size;
		}
	    }
	    if (orig_length && size > orig_length + 20) {
		cli_dbgmsg("cli_pdf: orig length: %ld, length: %ld, size: %ld\n",
			   orig_length, length, size);
		pdfobj_flag(pdf, obj, BAD_STREAMLEN);
	    }
	    if (!length) {
		length = size;
		if (!length) {
		    cli_dbgmsg("pdf_extract_obj: length and size both 0\n");
		    break; /* Empty stream, nothing to scan */
		}
	    }

	    flate_orig = flate_in = start + p_stream;
            flate_orig_length = length;
	    if (pdf->flags & (1 << DECRYPTABLE_PDF)) {
		enum enc_method enc = get_enc_method(pdf, obj);
		if (obj->flags & (1 << OBJ_FILTER_CRYPT)) {
		    int len = p_stream;
		    const char *q = pdf_getdict(start, &len, "/DecodeParams");
		    enc = ENC_IDENTITY;
		    if (q && pdf->CF) {
			char *name = pdf_readval(q, len, "/Name");
			cli_dbgmsg("cli_pdf: Crypt filter %s\n", name);
			if (name && strcmp(name, "/Identity"))
			    enc = parse_enc_method(pdf->CF, pdf->CF_n, name, enc); 
			free(name);
		    }
		}
		if (cli_memstr(start, p_stream, "/XRef", 5))
		    cli_dbgmsg("cli_pdf: cross reference stream, skipping\n");
		else {
		    decrypted = decrypt_any(pdf, obj->id, flate_in, &length,
					    enc);
		    if (decrypted)
			flate_in = decrypted;
		}
	    }

	    if (obj->flags & (1 << OBJ_FILTER_AH)) {
		ascii_decoded = cli_malloc(length/2 + 1);
		if (!ascii_decoded) {
		    cli_errmsg("Cannot allocate memory for ascii_decoded\n");
		    rc = CL_EMEM;
		    break;
		}
		ascii_decoded_size = asciihexdecode(flate_in,
						    length,
						    ascii_decoded);
	    } else if (obj->flags & (1 << OBJ_FILTER_A85)) {
		ascii_decoded = cli_malloc(length*5);
		if (!ascii_decoded) {
		    cli_errmsg("Cannot allocate memory for ascii_decoded\n");
		    rc = CL_EMEM;
		    break;
		}
		ascii_decoded_size = ascii85decode(flate_in,
						   length,
						   (unsigned char*)ascii_decoded);
	    }
	    if (ascii_decoded_size < 0) {
		/* don't flag for images or truncated objs*/
		if (!(obj->flags &
		      ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
		    pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);
		cli_dbgmsg("cli_pdf: failed to asciidecode in %u %u obj\n", obj->id>>8,obj->id&0xff);
		free(ascii_decoded);
		ascii_decoded = NULL;
		/* attempt to directly flatedecode it */
	    }
	    /* either direct or ascii-decoded input */
	    if (!ascii_decoded)
		ascii_decoded_size = length;
	    else
		flate_in = ascii_decoded;

	    if (obj->flags & (1 << OBJ_FILTER_FLATE)) {
		cli_dbgmsg("cli_pdf: deflate len %ld (orig %ld)\n", ascii_decoded_size, (long)orig_length);
		rc = filter_flatedecode(pdf, obj, flate_in, ascii_decoded_size, fout, &sum);
                if (rc == CL_EFORMAT) {
                    if (decrypted) {
                        flate_in = flate_orig;
                        ascii_decoded_size = flate_orig_length;
                    }
		    cli_dbgmsg("cli_pdf: dumping raw stream (probably encrypted)\n");
		    noisy_warnmsg("cli_pdf: dumping raw stream, probably encrypted and we failed to decrypt'n");
		    if (filter_writen(pdf, obj, fout, flate_in, ascii_decoded_size, &sum) != ascii_decoded_size) {
			cli_errmsg("cli_pdf: failed to write output file\n");
			return CL_EWRITE;
		    }
                }
	    } else {
		if (filter_writen(pdf, obj, fout, flate_in, ascii_decoded_size, &sum) != ascii_decoded_size)
		    rc = CL_EWRITE;
	    }
	} else
	    noisy_warnmsg("cannot find stream bounds for obj %u %u\n", obj->id>>8, obj->id&0xff);

    } else if (obj->flags & (1 << OBJ_JAVASCRIPT)) {
	const char *q2;
	const char *q = pdf->map+obj->start;
	/* TODO: get obj-endobj size */
	off_t bytesleft = obj_size(pdf, obj, 0);
	if (bytesleft < 0)
	    break;

      do {
        char *js = NULL;
        off_t js_len = 0;
        const char *q3;

	q2 = cli_memstr(q, bytesleft, "/JavaScript", 11);
	if (!q2)
	    break;
	bytesleft -= q2 - q + 11;
        q = q2 + 11;

        js = pdf_readstring(q, bytesleft,  "/JS", NULL, &q2, !(pdf->flags & (1<<DECRYPTABLE_PDF)));
        bytesleft -= q2 - q;
        q = q2;

        if (js) {
            const char *out = js;
            js_len = strlen(js);
            if (pdf->flags & (1 << DECRYPTABLE_PDF)) {
                cli_dbgmsg("cli_pdf: encrypted string\n");
		decrypted = decrypt_any(pdf, obj->id, js, &js_len,
					pdf->enc_method_string);
		if (decrypted) {
		    noisy_msg(pdf, "decrypted Javascript string from obj %u %u\n", obj->id>>8,obj->id&0xff);
		    out = decrypted;
		}
	    }

	    if (filter_writen(pdf, obj, fout, out, js_len, &sum) != js_len) {
		rc = CL_EWRITE;
                free(js);
		break;
	    }
            free(js);
	    cli_dbgmsg("bytesleft: %d\n", (int)bytesleft);

            if (bytesleft > 0) {
                q2 = pdf_nextobject(q, bytesleft);
                if (!q2) q2 = q + bytesleft - 1;
                /* non-conforming PDFs that don't escape ) properly */
                q3 = memchr(q, ')', bytesleft);
                if (q3 && q3 < q2) q2 = q3;
                while (q2 > q && q2[-1] == ' ') q2--;
                if (q2 > q) {
                    q--;
                    filter_writen(pdf, obj, fout, q, q2 - q, &sum);
                    q++;
                }
            }
        }

      } while (bytesleft > 0);
    } else {
	off_t bytesleft = obj_size(pdf, obj, 0);
	if (bytesleft < 0) {
	    rc = CL_EFORMAT;
	}
	else if (filter_writen(pdf, obj, fout , pdf->map + obj->start, bytesleft,&sum) != bytesleft)
	    rc = CL_EWRITE;
    }
    } while (0);
    cli_dbgmsg("cli_pdf: extracted %ld bytes %u %u obj to %s\n", sum, obj->id>>8, obj->id&0xff, fullname);
    if (sum) {
	int rc2;
	cli_updatelimits(pdf->ctx, sum);
	/* TODO: invoke bytecode on this pdf obj with metainformation associated
	 * */
	lseek(fout, 0, SEEK_SET);
	rc2 = cli_magic_scandesc(fout, pdf->ctx);
	if (rc2 == CL_VIRUS || rc == CL_SUCCESS)
	    rc = rc2;
	if ((rc == CL_CLEAN) || ((rc == CL_VIRUS) && (pdf->ctx->options & CL_SCAN_ALLMATCHES))) {
	    rc2 = run_pdf_hooks(pdf, PDF_PHASE_POSTDUMP, fout, obj - pdf->objs);
	    if (rc2 == CL_VIRUS)
		rc = rc2;
	}
	if (((rc == CL_CLEAN) || ((rc == CL_VIRUS) && (pdf->ctx->options & CL_SCAN_ALLMATCHES)))
		&& (obj->flags & (1 << OBJ_CONTENTS))) {
	    lseek(fout, 0, SEEK_SET);
	    cli_dbgmsg("cli_pdf: dumping contents %u %u\n", obj->id>>8, obj->id&0xff);
	    rc2 = pdf_scan_contents(fout, pdf);
	    if (rc2 == CL_VIRUS)
		rc = rc2;
	    noisy_msg(pdf, "extracted text from obj %u %u\n", obj->id>>8, obj->id&0xff);
	}
    }
    close(fout);
    free(ascii_decoded);
    free(decrypted);
    if (!pdf->ctx->engine->keeptmp)
	if (cli_unlink(fullname) && rc != CL_VIRUS)
	    rc = CL_EUNLINK;
    return rc;
}

enum objstate {
    STATE_NONE,
    STATE_S,
    STATE_FILTER,
    STATE_JAVASCRIPT,
    STATE_OPENACTION,
    STATE_LINEARIZED,
    STATE_LAUNCHACTION,
    STATE_CONTENTS,
    STATE_ANY /* for actions table below */
};

struct pdfname_action {
    const char *pdfname;
    enum pdf_objflags set_objflag;/* OBJ_DICT is noop */
    enum objstate from_state;/* STATE_NONE is noop */
    enum objstate to_state;
};

static struct pdfname_action pdfname_actions[] = {
    {"ASCIIHexDecode", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER},
    {"ASCII85Decode", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER},
    {"A85", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER},
    {"AHx", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER},
    {"EmbeddedFile", OBJ_EMBEDDED_FILE, STATE_NONE, STATE_NONE},
    {"FlateDecode", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER},
    {"Fl", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER},
    {"Image", OBJ_IMAGE, STATE_NONE, STATE_NONE},
    {"LZWDecode", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER},
    {"LZW", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER},
    {"RunLengthDecode", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER},
    {"RL", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER},
    {"CCITTFaxDecode", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER},
    {"CCF", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER},
    {"JBIG2Decode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER},
    {"DCTDecode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER},
    {"DCT", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER},
    {"JPXDecode", OBJ_FILTER_JPX, STATE_FILTER, STATE_FILTER},
    {"Crypt",  OBJ_FILTER_CRYPT, STATE_FILTER, STATE_NONE},
    {"Standard", OBJ_FILTER_STANDARD, STATE_FILTER, STATE_FILTER},
    {"Sig",    OBJ_SIGNED, STATE_ANY, STATE_NONE},
    {"V",     OBJ_SIGNED, STATE_ANY, STATE_NONE},
    {"R",     OBJ_SIGNED, STATE_ANY, STATE_NONE},
    {"Linearized", OBJ_DICT, STATE_NONE, STATE_LINEARIZED},
    {"Filter", OBJ_HASFILTERS, STATE_ANY, STATE_FILTER},
    {"JavaScript", OBJ_JAVASCRIPT, STATE_S, STATE_JAVASCRIPT},
    {"Length", OBJ_DICT, STATE_FILTER, STATE_NONE},
    {"S", OBJ_DICT, STATE_NONE, STATE_S},
    {"Type", OBJ_DICT, STATE_NONE, STATE_NONE},
    {"OpenAction", OBJ_OPENACTION, STATE_ANY, STATE_OPENACTION},
    {"Launch", OBJ_LAUNCHACTION, STATE_ANY, STATE_LAUNCHACTION},
    {"Page", OBJ_PAGE, STATE_NONE, STATE_NONE},
    {"Contents", OBJ_CONTENTS, STATE_NONE, STATE_CONTENTS}
};

#define KNOWN_FILTERS ((1 << OBJ_FILTER_AH) | (1 << OBJ_FILTER_RL) | (1 << OBJ_FILTER_A85) | (1 << OBJ_FILTER_FLATE) | (1 << OBJ_FILTER_LZW) | (1 << OBJ_FILTER_FAX) | (1 << OBJ_FILTER_DCT) | (1 << OBJ_FILTER_JPX) | (1 << OBJ_FILTER_CRYPT))

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
    if (!act) {
	if (*state == STATE_FILTER &&
	    !(obj->flags & (1 << OBJ_SIGNED)) &&
	    /* these are digital signature objects, filter doesn't matter,
	     * we don't need them anyway */
	    !(obj->flags & KNOWN_FILTERS)) {
	    cli_dbgmsg("cli_pdf: unknown filter %s\n", pdfname);
	    obj->flags |= 1 << OBJ_FILTER_UNKNOWN;
	}
	return;
    }
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
	    cli_dbgmsg("cli_pdf: duplicate stream filter %s\n", pdfname);
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

static int pdf_readint(const char *q0, int len, const char *key);

static void pdf_parse_encrypt(struct pdf_struct *pdf, const char *enc, int len)
{
    const char *q, *q2;
    uint32_t objid;

    if (len >= 16 && !strncmp(enc, "/EncryptMetadata", 16)) {
	q = cli_memstr(enc+16, len-16, "/Encrypt", 8);
	if (!q)
	    return;
	len -= q - enc;
	enc = q;
    }
    q = enc + 8;
    len -= 8;
    q2 = pdf_nextobject(q, len);
    if (!q2 || !isdigit(*q2))
	return;
    objid = atoi(q2) << 8;
    len -= q2 - q;
    q = q2;
    q2 = pdf_nextobject(q, len);
    if (!q2 || !isdigit(*q2))
	return;
    objid |= atoi(q2) & 0xff;
    len -= q2 - q;
    q = q2;
    q2 = pdf_nextobject(q, len);
    if (!q2 || *q2 != 'R')
	return;
    cli_dbgmsg("cli_pdf: Encrypt dictionary in obj %d %d\n", objid>>8, objid&0xff);
    pdf->enc_objid = objid;
}

static void pdf_parse_trailer(struct pdf_struct *pdf, const char *s, long length)
{
    const char *enc;
    enc = cli_memstr(s, length, "/Encrypt", 8);
    if (enc) {
	char *newID;
	pdf->flags |= 1 << ENCRYPTED_PDF;
	pdf_parse_encrypt(pdf, enc, s + length - enc);
	newID = pdf_readstring(s, length, "/ID", &pdf->fileIDlen, NULL, 0);
	if (newID) {
	    free(pdf->fileID);
	    pdf->fileID = newID;
	}
    }
}

static void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    /* enough to hold common pdf names, we don't need all the names */
    char pdfname[64];
    const char *q2, *q3;
    const char *nextobj, *nextopen, *nextclose;
    const char *q = obj->start + pdf->map;
    const char *dict, *enddict, *start;
    off_t dict_length, full_dict_length;
    off_t objsize = obj_size(pdf, obj, 1);
    off_t bytesleft;
    unsigned i, filters=0;
    unsigned blockopens=0;
    enum objstate objstate = STATE_NONE;

    if (objsize < 0)
	return;
    start = q;
    bytesleft = objsize;

    /* find start of dictionary */
    do {
	nextobj = pdf_nextobject(q, bytesleft);
	bytesleft -= nextobj -q;
	if (!nextobj || bytesleft < 0) {
	    cli_dbgmsg("cli_pdf: %u %u obj: no dictionary\n", obj->id>>8, obj->id&0xff);
	    return;
	}
	q3 = memchr(q-1, '<', nextobj-q+1);
	nextobj++;
	bytesleft--;
	q = nextobj;
    } while (!q3 || q3[1] != '<');
    dict = q3+2;
    q = dict;
    blockopens++;
    bytesleft = objsize - (q - start);
    enddict = q + bytesleft - 1;

    /* find end of dictionary block */
    if (bytesleft < 0) {
        cli_dbgmsg("cli_pdf: %u %u obj: broken dictionary\n", obj->id>>8, obj->id&0xff);
        return;
    }

    /* while still looking ... */
    while ((q < enddict-1) && (blockopens > 0)) {
        /* find next close */
        nextclose = memchr(q, '>', enddict-q);
        if (nextclose && (nextclose[1] == '>')) {
            /* check for nested open */
            while ((nextopen = memchr(q-1, '<', nextclose-q+1)) != NULL) {
                if (nextopen[1] == '<') {
                    /* nested open */
                    blockopens++;
                    q = nextopen + 2;
                }
                else {
                    /* unmatched < before next close */
                    q = nextopen + 2;
                }
            }
            /* close block */
            blockopens--;
            q = nextclose + 2;
        }
        else if (nextclose) {
            /* found one > but not two */
            q = nextclose + 2;
        }
        else {
            /* next closing not found */
            break;
        }
    }

    /* Was end of dictionary found? */
    if (blockopens) {
        /* probably truncated */
        cli_dbgmsg("cli_pdf: %u %u obj broken dictionary\n", obj->id>>8, obj->id&0xff);
        return;
    }
    enddict = nextclose;
    obj->flags |= 1 << OBJ_DICT;
    full_dict_length = dict_length = enddict - dict;

    /* This code prints the dictionary content.
    {
        char * dictionary = malloc(dict_length + 1);
        if (dictionary) {
            for (i = 0; i < dict_length; i++) {
                if (isprint(dict[i]) || isspace(dict[i]))
                    dictionary[i] = dict[i];
                else
                    dictionary[i] = '*';
            }
            dictionary[dict_length] = '\0';
            cli_dbgmsg("cli_pdf: dictionary is <<%s>>\n", dictionary);
            free(dictionary);
        }
    }
    */

    /*  process pdf names */
    for (q = dict;dict_length > 0;) {
	int escapes = 0;
	q2 = memchr(q, '/', dict_length);
	if (!q2)
	    break;
	dict_length -= q2 - q;
	q = q2;
	/* normalize PDF names */
	for (i = 0;dict_length > 0 && (i < sizeof(pdfname)-1); i++) {
	    q++;
	    dict_length--;
	    if (*q == '#') {
		if (cli_hex2str_to(q+1, pdfname+i, 2) == -1)
		    break;
		q += 2;
		dict_length -= 2;
		escapes = 1;
		continue;
	    }
	    if (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n' ||
		*q == '/' || *q == '>' || *q == ']' || *q == '[' || *q == '<'
		|| *q == '(')
		break;
	    pdfname[i] = *q;
	}
	pdfname[i] = '\0';

	handle_pdfname(pdf, obj, pdfname, escapes, &objstate);
	if (objstate == STATE_LINEARIZED) {
	    long trailer_end, trailer;
	    pdfobj_flag(pdf, obj, LINEARIZED_PDF);
	    objstate = STATE_NONE;
	    trailer_end = pdf_readint(dict, full_dict_length, "/H");
	    if (trailer_end > 0 && trailer_end < pdf->size) {
		const char *enc;
		trailer = trailer_end - 1024;
		if (trailer < 0) trailer = 0;
		q2 = pdf->map + trailer;
		cli_dbgmsg("cli_pdf: looking for trailer in linearized pdf: %ld - %ld\n", trailer, trailer_end);
		pdf_parse_trailer(pdf, q2, trailer_end - trailer);
		if (pdf->fileID)
		    cli_dbgmsg("cli_pdf: found fileID\n");
	    }
	}
	if (objstate == STATE_LAUNCHACTION)
	    pdfobj_flag(pdf, obj, HAS_LAUNCHACTION);
	if (dict_length > 0 &&
	    (objstate == STATE_JAVASCRIPT ||
	     objstate == STATE_OPENACTION ||
	     objstate == STATE_CONTENTS)) {
	    if (objstate == STATE_OPENACTION)
		pdfobj_flag(pdf, obj, HAS_OPENACTION);
	    q2 = pdf_nextobject(q, dict_length);
	    if (q2 && isdigit(*q2)) {
		uint32_t objid = atoi(q2) << 8;
		while (isdigit(*q2)) q2++;
		q2 = pdf_nextobject(q2, dict_length);
		if (q2 && isdigit(*q2)) {
		    objid |= atoi(q2) & 0xff;
		    q2 = pdf_nextobject(q2, dict_length);
		    if (q2 && *q2 == 'R') {
			struct pdf_obj *obj2;
			cli_dbgmsg("cli_pdf: found %s stored in indirect object %u %u\n",
				   pdfname,
				   objid >> 8, objid&0xff);
			obj2 = find_obj(pdf, obj, objid);
			if (obj2) {
			    enum pdf_objflags flag =
				objstate == STATE_JAVASCRIPT ? OBJ_JAVASCRIPT :
				objstate == STATE_OPENACTION ? OBJ_OPENACTION :
				OBJ_CONTENTS;
			    obj2->flags |= 1 << flag;
			    obj->flags &= ~(1 << flag);
			} else {
			    pdfobj_flag(pdf, obj, BAD_INDOBJ);
			}
		    }
		}
	    }
	    objstate = STATE_NONE;
	}
    }
    for (i=0;i<sizeof(pdfname_actions)/sizeof(pdfname_actions[0]);i++) {
	const struct pdfname_action *act = &pdfname_actions[i];
	if ((obj->flags & (1 << act->set_objflag)) &&
	    act->from_state == STATE_FILTER &&
	    act->to_state == STATE_FILTER &&
	    act->set_objflag != OBJ_FILTER_CRYPT &&
	    act->set_objflag != OBJ_FILTER_STANDARD) {
	    filters++;
	}
    }
    if (filters > 2) { /* more than 2 non-crypt filters */
	pdfobj_flag(pdf, obj, MANY_FILTERS);
    }
    if (obj->flags & ((1 << OBJ_SIGNED) | KNOWN_FILTERS))
	obj->flags &= ~(1 << OBJ_FILTER_UNKNOWN);
    if (obj->flags & (1 << OBJ_FILTER_UNKNOWN))
	pdfobj_flag(pdf, obj, UNKNOWN_FILTER);
    cli_dbgmsg("cli_pdf: %u %u obj flags: %02x\n", obj->id>>8, obj->id&0xff, obj->flags);
}

static const char *pdf_getdict(const char *q0, int* len, const char *key)
{
    const char *q;

    if (*len <= 0) {
	cli_dbgmsg("cli_pdf: bad length %d\n", *len);
	return NULL;
    }
    if (!q0) {
        return NULL;
    }
    q = cli_memstr(q0, *len, key, strlen(key));
    if (!q) {
	cli_dbgmsg("cli_pdf: %s not found in dict\n", key);
	return NULL;
    }
    *len -= q - q0;
    q0 = q;
    q = pdf_nextobject(q0 + 1, *len - 1);
    if (!q) {
	cli_dbgmsg("cli_pdf: %s is invalid in dict\n", key);
	return NULL;
    }
    if (q[-1] == '<')
	q--;
    *len -= q - q0;
    return q;
}

static char *pdf_readstring(const char *q0, int len, const char *key, unsigned *slen, const char **qend, int noescape)
{
    char *s, *s0;
    const char *start, *q, *end;
    if (slen)
	*slen = 0;
    if (qend)
        *qend = q0;
    q = pdf_getdict(q0, &len, key);
    if (!q)
	return NULL;
    if (*q == '(') {
	int paren = 1;
	start = ++q;
	for (;paren > 0 && len > 0; q++,len--) {
	    switch (*q) {
		case '(':
		    paren++;
		    break;
		case ')':
		    paren--;
		    break;
		case '\\':
		    q++;
		    len--;
		    break;
		default:
		    break;
	    }
	}
        if (qend)
            *qend = q;
	q--;
	len  = q - start;
	s0 = s = cli_malloc(len + 1);
	if (!s) {
        cli_errmsg("pdf_readstring: Unable to allocate buffer\n");
        return NULL;
    }
	end = start + len;
        if (noescape) {
            memcpy(s0, start, len);
            s = s0 + len;
        } else {
	for (q = start;q < end;q++) {
	    if (*q != '\\') {
		*s++ = *q;
	    } else {
		q++;
		switch (*q) {
		    case 'n':
			*s++ = '\n';
			break;
		    case 'r':
			*s++ = '\r';
			break;
		    case 't':
			*s++ = '\t';
			break;
		    case 'b':
			*s++ = '\b';
			break;
		    case 'f':
			*s++ = '\f';
			break;
		    case '(':/* fall-through */
		    case ')':/* fall-through */
		    case '\\':
			*s++ = *q;
			break;
		    case '\n':
			/* ignore */
			break;
		    case '\r':
			/* ignore */
			if (q+1 < end && q[1] == '\n')
			    q++;
			break;
		    case '0':
		    case '1':
		    case '2':
		    case '3':
		    case '4':
		    case '5':
		    case '6':
		    case '7':
		    case '8':
		    case '9':
			/* octal escape */
			if (q+2 < end)
			    q++;
			*s++ = 64*(q[0] - '0')+
			      8*(q[1] - '0')+
			        (q[2] - '0');
			break;
		    default:
			/* ignore */
                        *s++ = '\\';
                        q--;
			break;
		}
	    }
	}
        }
	*s++ = '\0';
	if (slen)
	    *slen = s - s0 - 1;
	return s0;
    }
    if (*q == '<') {
	start = ++q;
	q = memchr(q+1, '>', len);
	if (!q)
	    return NULL;
        if (qend)
            *qend = q;
	s = cli_malloc((q - start)/2 + 1);
	if (s == NULL) { /* oops, couldn't allocate memory */
	  cli_dbgmsg("cli_pdf: unable to allocate memory...\n");
	  return NULL;
	}
	if (cli_hex2str_to(start, s, q - start)) {
	    cli_dbgmsg("cli_pdf: %s has bad hex value\n", key);
	    free(s);
	    return NULL;
	}
	s[(q-start)/2] = '\0';
	if (slen)
	    *slen = (q - start)/2;
	return s;
    }
    cli_dbgmsg("cli_pdf: %s is invalid string in dict\n", key);
    return NULL;
}

static char *pdf_readval(const char *q, int len, const char *key)
{
    const char *end;
    char *s;

    q = pdf_getdict(q, &len, key);
    if (!q || len <= 0)
	return NULL;
    while (len > 0 && *q && *q == ' ') { q++; len--; }
    if (*q != '/')
	return NULL;
    q++;
    len--;
    end = q;
    while (len > 0 && *end && !(*end == '/' || (len > 1 && end[0] == '>' && end[1] == '>'))) {
	end++; len--;
    }
    s = cli_malloc(end - q + 1);
    if (!s)
	return NULL;
    memcpy(s, q, end-q);
    s[end-q] = '\0';
    return s;
}

static int pdf_readint(const char *q0, int len, const char *key)
{
    const char *q  = pdf_getdict(q0, &len, key);
    if (!q)
	return -1;
    return atoi(q);
}

static int pdf_readbool(const char *q0, int len, const char *key, int Default)
{
    const char *q  = pdf_getdict(q0, &len, key);
    if (!q || len < 5)
	return Default;
    if (!strncmp(q, "true", 4))
	return 1;
    if (!strncmp(q, "false", 5))
	return 0;
    cli_dbgmsg("cli_pdf: invalid value for %s bool\n", key);
    return Default;
}

static const char *key_padding =
"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4e\x56\xff\xfa\x01\x08"
"\x2e\x2e\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

static void dbg_printhex(const char *msg, const char *hex, unsigned len)
{
    if (cli_debug_flag) {
	char *kh = cli_str2hex(hex, len);
	cli_dbgmsg("cli_pdf: %s: %s\n", msg, kh);
	free(kh);
    }
}

static void check_user_password(struct pdf_struct *pdf, int R, const char *O,
				const char *U, int32_t P, int EM,
				const char *UE,
				unsigned length, unsigned oulen)
{
    unsigned i;
    uint8_t result[16];
    char data[32];
    struct arc4_state arc4;
    unsigned password_empty = 0;

    dbg_printhex("U: ", U, 32);
    dbg_printhex("O: ", O, 32);
    if (R == 5) {
	uint8_t result2[32];
	/* supplement to ISO3200, 3.5.2 Algorithm 3.11 */
	/* user validation salt */
    cl_sha256(U+32, 8, result2, NULL);
	dbg_printhex("Computed U", result2, 32);
	if (!memcmp(result2, U, 32)) {
	    off_t n;
	    password_empty = 1;
	    /* Algorithm 3.2a could be used to recover encryption key */
        cl_sha256(U+40, 8, result2, NULL);
	    n = UE ? strlen(UE) : 0;
	    if (n != 32) {
		cli_dbgmsg("cli_pdf: UE length is not 32: %d\n", (int)n);
		noisy_warnmsg("cli_pdf: UE length is not 32: %d\n", n);
	    } else {
		pdf->keylen = 32;
		pdf->key = cli_malloc(32);
		if (!pdf->key) {
            cli_errmsg("check_user_password: Cannot allocate memory for pdf->key\n");
            return;
        }
		aes_decrypt(UE, &n, pdf->key, result2, 32, 0);
		dbg_printhex("cli_pdf: Candidate encryption key", pdf->key, pdf->keylen);
	    }
	}
    } else if ((R >= 2) && (R <= 4)) {
        unsigned char *d;
        size_t sz = 68 + pdf->fileIDlen + (R >= 4 && !EM ? 4 : 0);
        d = calloc(1, sz);

        if (!(d))
            return;

        memcpy(d, key_padding, 32);
        memcpy(d+32, O, 32);
        P = le32_to_host(P);
        memcpy(d+64, &P, 4);
        memcpy(d+68, pdf->fileID, pdf->fileIDlen);
	/* 7.6.3.3 Algorithm 2 */
	/* empty password, password == padding */
	if (R >= 4 && !EM) {
	    uint32_t v = 0xFFFFFFFF;
        memcpy(d+68+pdf->fileIDlen, &v, 4);
	}
    cl_hash_data("md5", d, sz, result, NULL);
    free(d);
	if (length > 128)
	    length = 128;
	if (R >= 3) {
        /* Yes, this really is on purpose */
	    for (i=0;i<50;i++)
            cl_hash_data("md5", result, length/8, result, NULL);
	}
	if (R == 2)
	    length = 40;
	pdf->keylen = length / 8;
	pdf->key = cli_malloc(pdf->keylen);
	if (!pdf->key)
	    return;
	memcpy(pdf->key, result, pdf->keylen);
	dbg_printhex("md5", result, 16);
	dbg_printhex("Candidate encryption key", pdf->key, pdf->keylen);

	/* 7.6.3.3 Algorithm 6 */
	if (R == 2) {
	    /* 7.6.3.3 Algorithm 4 */
	    memcpy(data, key_padding, 32);
	    arc4_init(&arc4, pdf->key, pdf->keylen);
	    arc4_apply(&arc4, data, 32);
	    dbg_printhex("computed U (R2)", data, 32);
	    if (!memcmp(data, U, 32))
		password_empty = 1;
	} else if (R >= 3) {
	    unsigned len = pdf->keylen;
        unsigned char *d;

        d = calloc(1, 32 + pdf->fileIDlen);
        if (!(d))
            return;

	    /* 7.6.3.3 Algorithm 5 */
        memcpy(d, key_padding, 32);
        memcpy(d+32, pdf->fileID, pdf->fileIDlen);
        cl_hash_data("md5", d, 32 + pdf->fileIDlen, result, NULL);
	    memcpy(data, pdf->key, len);
	    arc4_init(&arc4, data, len);
	    arc4_apply(&arc4, result, 16);
	    for (i=1;i<=19;i++) {
		unsigned j;
		for (j=0;j<len;j++)
		    data[j] = pdf->key[j] ^ i;
		arc4_init(&arc4, data, len);
		arc4_apply(&arc4, result, 16);
	    }
	    dbg_printhex("fileID", pdf->fileID, pdf->fileIDlen);
	    dbg_printhex("computed U (R>=3)", result, 16);
	    if (!memcmp(result, U, 16))
		password_empty = 1;
	} else {
	    cli_dbgmsg("cli_pdf: invalid revision %d\n", R);
	    noisy_warnmsg("cli_pdf: invalid revision %d\n", R);
	}
    }
    else {
	/* Supported R is in {2,3,4,5} */
	cli_dbgmsg("cli_pdf: R value out of range\n");
	noisy_warnmsg("cli_pdf: R value out of range\n");
	return;
    }
    if (password_empty) {
	cli_dbgmsg("cli_pdf: user password is empty\n");
	noisy_msg(pdf, "cli_pdf: encrypted PDF found, user password is empty, will attempt to decrypt\n");
	/* The key we computed above is the key used to encrypt the streams.
	 * We could decrypt it now if we wanted to */
	pdf->flags |= 1 << DECRYPTABLE_PDF;
    } else {
	cli_dbgmsg("cli_pdf: user/owner password would be required for decryption\n");
	noisy_warnmsg("cli_pdf: encrypted PDF found, user password is NOT empty, cannot decrypt!\n");
	/* the key is not valid, we would need the user or the owner password to
	 * decrypt */
    }
}

static enum enc_method parse_enc_method(const char *dict, unsigned len, const char *key, enum enc_method def)
{
    const char *q;
    char *CFM = NULL;
    enum enc_method ret = ENC_UNKNOWN;
    if (!key)
	return def;
    if (!strcmp(key, "Identity"))
	return ENC_IDENTITY;
    q = pdf_getdict(dict, &len, key);
    if (!q)
	return def;
    CFM = pdf_readval(q, len, "/CFM");
    if (CFM) {
	cli_dbgmsg("cli_pdf: %s CFM: %s\n", key, CFM);
	if (!strncmp(CFM,"V2", 2)){
	    ret = ENC_V2;
	}    
	else if (!strncmp(CFM,"AESV2",5)){
	    ret = ENC_AESV2;
	}    
	else if (!strncmp(CFM,"AESV3",5)){
	    ret = ENC_AESV3;
	}    
	else if (!strncmp(CFM,"None",4)){
	    ret = ENC_NONE;
	}
	free(CFM);
    }
    return ret;
}

static void pdf_handle_enc(struct pdf_struct *pdf)
{
    struct pdf_obj *obj;
    uint32_t len, required_flags, n, R, P, length, EM = 1, i, oulen;
    char *O, *U, *UE, *StmF, *StrF, *EFF;
    const char *q, *q2;

    if (pdf->enc_objid == ~0u)
	return;
    if (!pdf->fileID) {
	cli_dbgmsg("cli_pdf: pdf_handle_enc no file ID\n");
	noisy_warnmsg("cli_pdf: pdf_handle_enc no file ID\n");
	return;
    }
    obj = find_obj(pdf, pdf->objs, pdf->enc_objid);
    if (!obj) {
	cli_dbgmsg("cli_pdf: can't find encrypted object %d %d\n", pdf->enc_objid>>8, pdf->enc_objid&0xff);
	noisy_warnmsg("cli_pdf: can't find encrypted object %d %d\n", pdf->enc_objid>>8, pdf->enc_objid&0xff);
	return;
    }
    len = obj_size(pdf, obj, 1);
    q = pdf->map + obj->start;

    O = U = UE = StmF = StrF = EFF = NULL;
    do {

	pdf->enc_method_string = ENC_UNKNOWN;
	pdf->enc_method_stream = ENC_UNKNOWN;
	pdf->enc_method_embeddedfile = ENC_UNKNOWN;
	P = pdf_readint(q, len, "/P");
	if (P == ~0u) {
	    cli_dbgmsg("cli_pdf: invalid P\n");
	    noisy_warnmsg("cli_pdf: invalid P\n");
	    break;
	}

	q2 = cli_memstr(q, len, "/Standard", 9);
	if (!q2) {
	    cli_dbgmsg("cli_pdf: /Standard not found\n");
	    noisy_warnmsg("cli_pdf: /Standard not found\n");
	    break;
	}
	/* we can have both of these:
	* /AESV2/Length /Standard/Length
	* /Length /Standard
	* make sure we don't mistake AES's length for Standard's */
	length = pdf_readint(q2, len - (q2 - q), "/Length");
	if (length == ~0u)
	    length = pdf_readint(q, len, "/Length");
	if (length < 40) {
	    cli_dbgmsg("cli_pdf: invalid length: %d\n", length);
	    length = 40;
	}

	R = pdf_readint(q, len, "/R");
	if (R == ~0u) {
	    cli_dbgmsg("cli_pdf: invalid R\n");
	    noisy_warnmsg("cli_pdf: invalid R\n");
	    break;
	}
	if ((R > 5) || (R < 2)) {
	    cli_dbgmsg("cli_pdf: R value outside supported range [2..5]\n");
	    noisy_warnmsg("cli_pdf: R value outside supported range [2..5]\n");
	    break;
	}

	if (R < 5)
	    oulen = 32;
	else
	    oulen = 48;
	if (R == 2 || R == 3) {
	    pdf->enc_method_stream = ENC_V2;
	    pdf->enc_method_string = ENC_V2;
	    pdf->enc_method_embeddedfile = ENC_V2;
	} else if (R == 4 || R == 5) {
	    EM = pdf_readbool(q, len, "/EncryptMetadata", 1);
	    StmF = pdf_readval(q, len, "/StmF");
	    StrF = pdf_readval(q, len, "/StrF");
	    EFF = pdf_readval(q, len, "/EFF");
	    n = len;
	    pdf->CF = pdf_getdict(q, &n, "/CF");
	    pdf->CF_n = n;
	    if (StmF)
		cli_dbgmsg("cli_pdf: StmF: %s\n", StmF);
	    if (StrF)
		cli_dbgmsg("cli_pdf: StrF: %s\n", StrF);
	    if (EFF)
		cli_dbgmsg("cli_pdf: EFF: %s\n", EFF);
	    pdf->enc_method_stream = parse_enc_method(pdf->CF, n, StmF, ENC_IDENTITY);
	    pdf->enc_method_string = parse_enc_method(pdf->CF, n, StrF, ENC_IDENTITY);
	    pdf->enc_method_embeddedfile = parse_enc_method(pdf->CF, n, EFF, pdf->enc_method_stream);
	    free(StmF);
	    free(StrF);
	    free(EFF);

	    cli_dbgmsg("cli_pdf: EncryptMetadata: %s\n",
		       EM ? "true" : "false");
	    if (R == 4)
		length = 128;
	    else {
		n = 0;
		UE = pdf_readstring(q, len, "/UE", &n, NULL, 0);
		length = 256;
	    }
	}
	if (length == ~0u)
	    length = 40;

	n = 0;
	O = pdf_readstring(q, len, "/O", &n, NULL, 0);
	if (!O || n < oulen) {
	    cli_dbgmsg("cli_pdf: invalid O: %d\n", n);
	    cli_dbgmsg("cli_pdf: invalid O: %d\n", n);
	    if (O)
		dbg_printhex("invalid O", O, n);
	    break;
	}
	if (n > oulen) {
	    for (i=oulen;i<n;i++)
		if (O[i])
		    break;
	    if (i != n) {
		dbg_printhex("too long O", O, n);
		noisy_warnmsg("too long O", O, n);
		break;
	    }
	}

	n = 0;
	U = pdf_readstring(q, len, "/U", &n, NULL, 0);
	if (!U || n < oulen) {
	    cli_dbgmsg("cli_pdf: invalid U: %d\n", n);
	    noisy_warnmsg("cli_pdf: invalid U: %d\n", n);
	    if (U)
		dbg_printhex("invalid U", U, n);
	    break;
	}
	if (n > oulen) {
	    for (i=oulen;i<n;i++)
		if (U[i])
		    break;
	    if (i != n) {
		dbg_printhex("too long U", U, n);
		break;
	    }
	}
	cli_dbgmsg("cli_pdf: Encrypt R: %d, P %x, length: %d\n", R, P, length);
	if (length % 8) {
	    cli_dbgmsg("cli_pdf: wrong key length, not multiple of 8\n");
	    noisy_warnmsg("cli_pdf: wrong key length, not multiple of 8\n");
	    break;
	}
	check_user_password(pdf, R, O, U, P, EM, UE, length, oulen);
    } while (0);
    free(O);
    free(U);
    free(UE);
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
    int rc, badobjects = 0;
    unsigned i, alerts = 0;

    cli_dbgmsg("in cli_pdf(%s)\n", dir);
    memset(&pdf, 0, sizeof(pdf));
    pdf.ctx = ctx;
    pdf.dir = dir;
    pdf.enc_objid = ~0u;

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
	noisy_warnmsg("cli_pdf: no PDF- header found\n");
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
    map_off = (off_t)map->len - 2048;
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
	const char *t;
	/*size = q - eofmap + map_off;*/
	q -= 9;
	for (;q > eofmap;q--) {
	    if (memcmp(q, "startxref", 9) == 0)
		break;
	}
	if (q <= eofmap) {
	    pdf.flags |= 1 << BAD_PDF_TRAILER;
	    cli_dbgmsg("cli_pdf: startxref not found\n");
	} else {
	    for (t=q;t > eofmap; t--) {
		if (memcmp(t,"trailer",7) == 0)
		    break;
	    }

	    pdf_parse_trailer(&pdf, eofmap, eof - eofmap);
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
    }
    size -= offset;

    pdf.size = size;
    pdf.map = fmap_need_off(map, offset, size);
    pdf.startoff = offset;
    if (!pdf.map) {
	cli_errmsg("cli_pdf: mmap() failed (3)\n");
	return CL_EMAP;
    }
    rc = run_pdf_hooks(&pdf, PDF_PHASE_PRE, -1, -1);
    if ((rc == CL_VIRUS) && SCAN_ALL) {
        cli_dbgmsg("cli_pdf: (pre hooks) returned %d\n", rc);
        alerts++;
        rc = CL_CLEAN;
    }
    else if (rc) {
	cli_dbgmsg("cli_pdf: (pre hooks) returning %d\n", rc);
	return rc == CL_BREAK ? CL_CLEAN : rc;
    }

    /* parse PDF and find obj offsets */
    while ((rc = pdf_findobj(&pdf)) > 0) {
	struct pdf_obj *obj = &pdf.objs[pdf.nobjs-1];
	cli_dbgmsg("cli_pdf: found %d %d obj @%ld\n", obj->id >> 8, obj->id&0xff, obj->start + offset);
    }
    if (pdf.nobjs)
	pdf.nobjs--;
    if (rc == -1)
	pdf.flags |= 1 << BAD_PDF_TOOMANYOBJS;

    /* must parse after finding all objs, so we can flag indirect objects */
    for (i=0;i<pdf.nobjs;i++) {
	struct pdf_obj *obj = &pdf.objs[i];
	pdf_parseobj(&pdf, obj);
    }

    pdf_handle_enc(&pdf);
    if (pdf.flags & (1 << ENCRYPTED_PDF))
	cli_dbgmsg("cli_pdf: encrypted pdf found, %s!\n",
		   (pdf.flags & (1 << DECRYPTABLE_PDF)) ?
		   "decryptable" : "not decryptable, stream will probably fail to decompress");

    if (DETECT_ENCRYPTED &&
	(pdf.flags & (1 << ENCRYPTED_PDF)) &&
	!(pdf.flags & (1 << DECRYPTABLE_PDF))) {
	/* It is encrypted, and a password/key needs to be supplied to decrypt.
	 * This doesn't trigger for PDFs that are encrypted but don't need
	 * a password to decrypt */
	cli_append_virus(ctx, "Heuristics.Encrypted.PDF");
	alerts++;
        if (!SCAN_ALL)
            rc = CL_VIRUS;
    }

    if (!rc) {
	rc = run_pdf_hooks(&pdf, PDF_PHASE_PARSED, -1, -1);
        cli_dbgmsg("cli_pdf: (parsed hooks) returned %d\n", rc);
        if (rc == CL_VIRUS) {
            alerts++;
            if (SCAN_ALL) {
                rc = CL_CLEAN;
            }
        }
    }

    /* extract PDF objs */
    for (i=0;!rc && i<pdf.nobjs;i++) {
        struct pdf_obj *obj = &pdf.objs[i];
        rc = pdf_extract_obj(&pdf, obj);
        switch (rc) {
            case CL_EFORMAT:
                /* Don't halt on one bad object */
                cli_dbgmsg("cli_pdf: bad format object, skipping to next\n");
                badobjects++;
                rc = CL_CLEAN;
                break;
            case CL_VIRUS:
                alerts++;
                if (SCAN_ALL) {
                    rc = CL_CLEAN;
                }
                break;
            default:
                break;
        }
    }

    if (pdf.flags & (1 << ENCRYPTED_PDF))
	pdf.flags &= ~ ((1 << BAD_FLATESTART) | (1 << BAD_STREAMSTART) |
	    (1 << BAD_ASCIIDECODE));

   if (pdf.flags && !rc) {
	cli_dbgmsg("cli_pdf: flags 0x%02x\n", pdf.flags);
	rc = run_pdf_hooks(&pdf, PDF_PHASE_END, -1, -1);
        if (rc == CL_VIRUS) {
            alerts++;
            if (SCAN_ALL) {
                rc = CL_CLEAN;
            }
        }
        if (!rc && SCAN_ALGO && (ctx->dconf->other & OTHER_CONF_PDFNAMEOBJ)) {
            if (pdf.flags & (1 << ESCAPED_COMMON_PDFNAME)) {
                /* for example /Fl#61te#44#65#63#6f#64#65 instead of /FlateDecode */
                cli_append_virus(ctx, "Heuristics.PDF.ObfuscatedNameObject");
                rc = cli_found_possibly_unwanted(ctx);
            }
        }
#if 0
	/* TODO: find both trailers, and /Encrypt settings */
	if (pdf.flags & (1 << LINEARIZED_PDF))
	    pdf.flags &= ~ (1 << BAD_ASCIIDECODE);
	if (pdf.flags & (1 << MANY_FILTERS))
	    pdf.flags &= ~ (1 << BAD_ASCIIDECODE);
	if (!rc && (pdf.flags &
	    ((1 << BAD_PDF_TOOMANYOBJS) | (1 << BAD_STREAM_FILTERS) |
	     (1<<BAD_FLATE) | (1<<BAD_ASCIIDECODE)|
    	     (1<<UNTERMINATED_OBJ_DICT) | (1<<UNKNOWN_FILTER)))) {
	    rc = CL_EUNPACK;
	}
#endif
    }

    if (alerts) {
        rc = CL_VIRUS;
    }
    else if (!rc && badobjects) {
        rc = CL_EFORMAT;
    }

    cli_dbgmsg("cli_pdf: returning %d\n", rc);
    free(pdf.objs);
    free(pdf.fileID);
    free(pdf.key);

    /* PDF hooks may abort, don't return CL_BREAK to caller! */
    return rc == CL_BREAK ? CL_CLEAN : rc;
}

static int asciihexdecode(const char *buf, off_t len, char *output)
{
    unsigned i,j;
    for (i=0,j=0;i+1<len;i++) {
	if (buf[i] == ' ')
	    continue;
	if (buf[i] == '>')
	    break;
	if (cli_hex2str_to(buf+i, output+j, 2) == -1) {
	    if (len - i < 4)
		continue;
	    return -1;
	}
	j++;
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

		if((byte == '~') && (len > 0) && (*ptr == '>'))
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
				cli_dbgmsg("cli_pdf: ascii85decode: unexpected 'z'\n");
				return -1;
			}
			*output++ = '\0';
			*output++ = '\0';
			*output++ = '\0';
			*output++ = '\0';
			ret += 4;
		} else if(byte == EOF) {
			cli_dbgmsg("cli_pdf: ascii85decode: quintet %d\n", quintet);
			if(quintet) {
				int i;

				if(quintet == 1) {
					cli_dbgmsg("cli_pdf: ascii85Decode: only 1 byte in last quintet\n");
					return -1;
				}
				for(i = quintet; i < 5; i++)
					sum *= 85;

				if(quintet > 1)
					sum += (0xFFFFFF >> ((quintet - 2) * 8));
				ret += quintet-1;
				for(i = 0; i < quintet - 1; i++)
					*output++ = (unsigned char)((sum >> (24 - 8 * i)) & 0xFF);
			}
			break;
		} else if(!isspace(byte)) {
			cli_dbgmsg("cli_pdf: ascii85Decode: invalid character 0x%x, len %lu\n",
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
			case '(': /* start of JS */
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
