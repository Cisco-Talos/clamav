/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

#if HAVE_ICONV
#include <iconv.h>
#endif

#ifdef _WIN32
#include <stdint.h>
#endif

#include "clamav.h"
#include "others.h"
#include "pdf.h"
#include "pdfdecode.h"
#include "scanners.h"
#include "fmap.h"
#include "str.h"
#include "bytecode.h"
#include "bytecode_api.h"
#include "arc4.h"
#include "rijndael.h"
#include "textnorm.h"
#include "conv.h"
#include "json_api.h"

#ifdef	CL_DEBUG
/*#define	SAVE_TMP	
 *Save the file being worked on in tmp */
#endif

struct pdf_struct;

static	int	asciihexdecode(const char *buf, off_t len, char *output);
static	int	ascii85decode(const char *buf, off_t len, unsigned char *output);
static	const	char	*pdf_nextlinestart(const char *ptr, size_t len);
static	const	char	*pdf_nextobject(const char *ptr, size_t len);

/* PDF statistics callbacks and related */
struct pdfname_action;

#if HAVE_JSON
static void pdf_export_json(struct pdf_struct *);

static void ASCIIHexDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void ASCII85Decode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void EmbeddedFile_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void FlateDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Image_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void LZWDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void RunLengthDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void CCITTFaxDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void JBIG2Decode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void DCTDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void JPXDecode_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Crypt_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Standard_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Sig_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void JavaScript_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void OpenAction_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Launch_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Page_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Author_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Creator_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Producer_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void CreationDate_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void ModificationDate_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Title_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Subject_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Keywords_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Pages_cb(struct pdf_struct *, struct pdf_obj *, struct pdfname_action *);
static void Colors_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act);
static void RichMedia_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act);
static void AcroForm_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act);
static void XFA_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act);
#endif
/* End PDF statistics callbacks and related */

static int pdf_readint(const char *q0, int len, const char *key);
static const char *pdf_getdict(const char *q0, int* len, const char *key);
static char *pdf_readval(const char *q, int len, const char *key);
static char *pdf_readstring(const char *q0, int len, const char *key, unsigned *slen, const char **qend, int noescape);

static int xrefCheck(const char *xref, const char *eof)
{
    const char *q;

    while (xref < eof && (*xref == ' ' || *xref == '\n' || *xref == '\r'))
        xref++;

    if (xref + 4 >= eof)
        return -1;

    if (!memcmp(xref, "xref", strlen("xref"))) {
        cli_dbgmsg("cli_pdf: found xref\n");
        return 0;
    }

    /* could be xref stream */
    for (q=xref; q+5 < eof; q++) {
        if (!memcmp(q,"/XRef", strlen("/XRef"))) {
            cli_dbgmsg("cli_pdf: found /XRef\n");
            return 0;
        }
    }

    return -1;
}

/* define this to be noisy about things that we can't parse properly */
#undef NOISY

#ifdef NOISY
#define noisy_msg(pdf, ...) cli_infomsg(pdf->ctx, __VA_ARGS__)
#define noisy_warnmsg(...) cli_warnmsg(__VA_ARGS__)
#else
#define noisy_msg(pdf, ...)
#define noisy_warnmsg(...)
#endif

/**
 * @brief   Searching BACKwards, find the next character that is not a whitespace.
 *
 * @param q         Index to start from (at the end of the search space)
 * @param start     Beginning of the search space.
 *
 * @return const char*  Address of the final non-whitespace character OR the same address as the start.
 */
static const char *findNextNonWSBack(const char *q, const char *start)
{
    while (q > start && (*q == 0 || *q == 9 || *q == 0xa || *q == 0xc || *q == 0xd || *q == 0x20))
        q--;

    return q;
}

/**
 * @brief   Searching FORwards, find the next character that is not a whitespace.
 *
 * @param q         Index to start from (at the end of the search space)
 * @param start     Beginning of the search space.
 *
 * @return const char*  Address of the final non-whitespace character OR the same address as the start.
 */
static const char *findNextNonWS(const char *q, const char *end)
{
    while (q < end && (*q == 0 || *q == 9 || *q == 0xa || *q == 0xc || *q == 0xd || *q == 0x20))
        q++;

    return q;
}

/**
 * @brief   Find bounds of stream.
 *
 * PDF streams are prefixed with "stream" and suffixed with "endstream".
 * Return value indicates success or failure.
 *
 * @param start             start address of search space.
 * @param size              size of search space
 * @param[out] stream       output param, address of start of stream data
 * @param[out] stream_size  output param, size of stream data
 * @param newline_hack      hack to support newlines that are \r\n, and not just \n or just \r.
 *
 * @return cl_error_t       CL_SUCCESS if stream bounds were found.
 * @return cl_error_t       CL_BREAK if stream bounds could not be found.
 * @return cl_error_t       CL_EFORMAT if stream start was found, but not end. (truncated)
 * @return cl_error_t       CL_EARG if invalid args were provided.
 */
static cl_error_t find_stream_bounds(
    const char *start,
    size_t size,
    const char **stream,
    size_t *stream_size,
    int newline_hack)
{
    cl_error_t status = CL_BREAK;

    const char *idx;
    const char *stream_begin;
    const char *endstream_begin;
    size_t bytesleft = size;

    if ((NULL == start) || (0 == bytesleft) || (NULL == stream) || (NULL == stream_size)) {
        status = CL_EARG;
        return status;
    }

    *stream = NULL;
    *stream_size = 0;

    /* Begin by finding the "stream" string that prefixes stream data. */
    if ((stream_begin = cli_memstr(start, bytesleft, "stream", strlen("stream")))) {
        idx = stream_begin + strlen("stream");
        bytesleft -= idx - start;
        if (bytesleft < 0)
            goto done;

        /* Skip any new line charcters. */
        if (bytesleft >= 2 && idx[0] == '\xd' && idx[1] == '\xa') {
            idx += 2;
            if (newline_hack && (bytesleft > 2) && idx[0] == '\xa')
                idx++;
        } else if (bytesleft && idx[0] == '\xa') {
            idx++;
        }

        /* Pass back start of the stream data. */
        *stream = idx;

        bytesleft = size - (idx - start);
        if (bytesleft <= 0)
            goto done;

        /* Now find the "endstream" string that suffixes stream data. */
        endstream_begin = cli_memstr(idx, bytesleft, "endstream", strlen("endstream"));
        if (!endstream_begin) {
            /* Couldn't find "endstream", but that's ok --
             * -- we'll just count the rest of the provided buffer. */
            cli_dbgmsg("find_stream_bounds: Truncated stream found!\n");
            endstream_begin = start + size;
            status = CL_EFORMAT;
        }

        /* Pass back end of the stream data, as offset from start. */
        *stream_size = endstream_begin - *stream;

        if (CL_EFORMAT != status)
            status = CL_SUCCESS;
    }

done:

    return status;
}

/**
 * @brief Find the next *indirect* object in an object stream, adds it to our list of
 *        objects, and increments nobj.
 *
 * Indirect objects in a stream DON'T begin with "obj" and end with "endobj".
 * Instead, they have an obj ID and an offset from the first object to point you
 * right at them.
 *
 * If found, objstm->current will be updated to the next obj id.
 *
 * All objects in an object stream are indirect and thus do not begin or start
 * with "obj" or "endobj".  Instead, the object stream takes the following
 * format.
 *
 *      <dictionary describing stream> objstm content endobjstm
 *
 * where content looks something like the following:
 *
 *      15 0 16 3 17 46 (ab)<</IDS 8 0 R/JavaScript 27 0 R/URLS 9 0 R>><</Names[(Test)28 0 R]>>
 *
 * In the above example, the literal string (ab) is indirect object # 15, and
 * begins at offset 0 of the set of objects.  The next object, # 16 begis at
 * offset 3 is a dictionary.  The final object is also a dictionary, beginning
 * at offset 46.
 *
 * @param pdf   Pdf struct that keeps track of all information found in the PDF.
 * @param objstm
 *
 * @return CL_SUCCESS  if success
 * @return CL_EPARSE   if parsing error
 * @return CL_EMEM     if error allocating memory
 * @return CL_EARG     if invalid arguments
 */
int pdf_findobj_in_objstm(struct pdf_struct *pdf, struct objstm_struct *objstm, struct pdf_obj **obj_found)
{
    cl_error_t status = CL_EPARSE;
    struct pdf_obj *obj = NULL;
    unsigned long objid = 0, objoff = 0;
    long temp_long         = 0;
    const char *index = NULL;
    size_t bytes_remaining = 0;

    if (NULL == pdf || NULL == objstm) {
        cli_warnmsg("pdf_findobj_in_objstm: invalid arguments\n");
        return CL_EARG;
    }

    *obj_found = NULL;

    index = objstm->streambuf + objstm->current_pair;
    bytes_remaining = objstm->streambuf_len - objstm->current_pair;

    obj = calloc(sizeof(struct pdf_obj), 1);
    if (!obj) {
        cli_warnmsg("pdf_findobj_in_objstm: out of memory finding objects in stream\n");
        status = CL_EMEM;
        goto done;
    }

    /* This object is in a stream, not in the regular map buffer. */
    obj->objstm = objstm;

    /* objstm->current_pair points directly to the obj id */
    if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
        /* Failed to find objid */
        cli_dbgmsg("pdf_findobj_in_objstm: Failed to find objid for obj in object stream\n");
        status = CL_EPARSE;
        goto done;
    } else if (temp_long < 0) {
        cli_dbgmsg("pdf_findobj_in_objstm: Encountered invalid negative objid (%ld).\n", temp_long);
        status = CL_EPARSE;
        goto done;
    }
    objid = (unsigned long)temp_long;

    /* Find the obj offset that appears just after the obj id*/
    while ((index < objstm->streambuf + objstm->streambuf_len) && isdigit(*index)) {
        index++;
        bytes_remaining--;
    }
    index = findNextNonWS(index, objstm->streambuf + objstm->first);
    bytes_remaining = objstm->streambuf + objstm->streambuf_len - index;

    if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
        /* Failed to find obj offset */
        cli_dbgmsg("pdf_findobj_in_objstm: Failed to find obj offset for obj in object stream\n");
        status = CL_EPARSE;
        goto done;
    } else if (temp_long < 0) {
        cli_dbgmsg("pdf_findobj_in_objstm: Encountered invalid negative obj offset (%ld).\n", temp_long);
        status = CL_EPARSE;
        goto done;
    }
    objoff = (unsigned long)temp_long;

    if ((size_t)objstm->first + (size_t)objoff > objstm->streambuf_len) {
        /* Alleged obj location is further than the length of the stream */
        cli_dbgmsg("pdf_findobj_in_objstm: obj offset found is greater than the length of the stream.\n");
        status = CL_EPARSE;
        goto done;
    }

    objstm->current = objstm->first + objoff;

    obj->id = (objid << 8) | (0 & 0xff);
    obj->start = objstm->current;
    obj->flags = 0;

    objstm->nobjs_found++;

    while ((index < objstm->streambuf + objstm->streambuf_len) && isdigit(*index)) {
        index++;
        bytes_remaining--;
    }
    objstm->current_pair = (uint32_t)(findNextNonWS(index, objstm->streambuf + objstm->first) - objstm->streambuf);

    /* Update current_pair, if there are more */
    if ((objstm->nobjs_found < objstm->n) &&
        (index < objstm->streambuf + objstm->streambuf_len))
    {
        unsigned long next_objid = 0, next_objoff = 0;

        /*
         * While we're at it,
         *   lets record the size as running up to the next object offset.
         *
         * To do so, we will need to parse the next obj pair.
         */
        /* objstm->current_pair points directly to the obj id */
        index = objstm->streambuf + objstm->current_pair;
        bytes_remaining = objstm->streambuf + objstm->streambuf_len - index;

        if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
            /* Failed to find objid for next obj */
            cli_dbgmsg("pdf_findobj_in_objstm: Failed to find next objid for obj in object stream though there should be {%u} more.\n", objstm->n - objstm->nobjs_found);
            status = CL_EPARSE;
            goto done;
        } else if (temp_long < 0) {
            cli_dbgmsg("pdf_findobj_in_objstm: Encountered invalid negative objid (%ld).\n", temp_long);
            status = CL_EPARSE;
            goto done;
        }
        next_objid = (unsigned long)temp_long;

        /* Find the obj offset that appears just after the obj id*/
        while ((index < objstm->streambuf + objstm->streambuf_len) && isdigit(*index)) {
            index++;
            bytes_remaining--;
        }
        index = findNextNonWS(index, objstm->streambuf + objstm->first);
        bytes_remaining = objstm->streambuf + objstm->streambuf_len - index;

        if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
            /* Failed to find obj offset for next obj */
            cli_dbgmsg("pdf_findobj_in_objstm: Failed to find next obj offset for obj in object stream though there should be {%u} more.\n", objstm->n - objstm->nobjs_found);
            status = CL_EPARSE;
            goto done;
        } else if (temp_long < 0) {
            cli_dbgmsg("pdf_findobj_in_objstm: Encountered invalid negative obj offset (%ld).\n", temp_long);
            status = CL_EPARSE;
            goto done;
        }
        next_objoff = (unsigned long)temp_long;

        if (next_objoff <= objoff) {
            /* Failed to find obj offset for next obj */
            cli_dbgmsg("pdf_findobj_in_objstm: Found next obj offset for obj in object stream but it's less than or equal to the current one!\n");
            status = CL_EPARSE;
            goto done;
        }
        else if (objstm->first + next_objoff > objstm->streambuf_len) {
            /* Failed to find obj offset for next obj */
            cli_dbgmsg("pdf_findobj_in_objstm: Found next obj offset for obj in object stream but it's further out than the size of the stream!\n");
            status = CL_EPARSE;
            goto done;
        }

        obj->size = next_objoff - objoff;
    }
    else
    {
        /*
         * Should be no more objects. We should verify.
         *
         * Either way...
         *   obj->size should be the rest of the buffer.
         */
        if (objstm->nobjs_found < objstm->n) {
            cli_warnmsg("pdf_findobj_in_objstm: Fewer objects found in object stream than expected!\n");
        }

        obj->size = objstm->streambuf_len - obj->start;
    }

    /* Success! Add the object to the list of all objects found. */
    pdf->nobjs++;
    pdf->objs = cli_realloc2(pdf->objs, sizeof(struct pdf_obj*) * pdf->nobjs);
    if (!pdf->objs) {
        cli_warnmsg("pdf_findobj_in_objstm: out of memory finding objects in stream\n");
        status = CL_EMEM;
        goto done;
    }
    pdf->objs[pdf->nobjs-1] = obj;

    *obj_found = obj;

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != obj) {
            free(obj);
        }
    }
    return status;
}

/**
 * @brief Find the next *indirect* object.
 *
 * Indirect objects located outside of an object stream are prefaced with:
 *      <objid> <genid> obj
 *
 * Each of the above are separated by whitespace of some sort.
 *
 * Indirect objects are postfaced with:
 *      endobj
 *
 * The specification does not say if whitespace is required before or after "endobj".
 *
 * Identify truncated objects.
 *
 * If found, pdf->offset will be updated to just after the "endobj".
 * If truncated, pdf->offset will == pdf->size.
 * If not found, pdf->offset will not be updated.
 *
 * @param pdf   Pdf context struct that keeps track of all information found in the PDF.
 *
 * @return CL_SUCCESS  if success
 * @return CL_BREAK    if no more objects
 * @return CL_EPARSE   if parsing error
 * @return CL_EMEM     if error allocating memory
 */
cl_error_t pdf_findobj(struct pdf_struct *pdf)
{
    cl_error_t status = CL_EPARSE;
    const char *start, *idx, *genid_search_index, *objid_search_index;

    const char *obj_begin = NULL, *obj_end = NULL;
    const char *endobj_begin = NULL, *endobj_end = NULL;

    struct pdf_obj *obj = NULL;
    size_t bytesleft;
    unsigned long genid, objid;
    long temp_long;

    pdf->nobjs++;
    pdf->objs = cli_realloc2(pdf->objs, sizeof(struct pdf_obj*) * pdf->nobjs);
    if (!pdf->objs) {
        status = CL_EMEM;
        goto done;
    }

    obj = malloc(sizeof(struct pdf_obj));
    if (!obj) {
        status = CL_EMEM;
        goto done;
    }
    pdf->objs[pdf->nobjs-1] = obj;

    memset(obj, 0, sizeof(*obj));

    start = pdf->map + pdf->offset;
    bytesleft = pdf->size - pdf->offset;

    /*
     * Start by searching for "obj"
     */
    idx = start + 1;
    while (bytesleft > 1 + strlen("obj")) {
        /* `- 1` accounts for size of white space before obj */
        idx = cli_memstr(idx, bytesleft - 1, "obj", strlen("obj"));
        if (NULL == idx) {
            status = CL_BREAK;
            goto done; /* No more objs. */
        }

        /* verify that the word has a whitespace before it, and is not the end of
         * a previous word */
        idx--;
        bytesleft = (pdf->size - pdf->offset) - (size_t)(idx - start);

        if (*idx != 0 && *idx != 9 && *idx != 0xa && *idx != 0xc && *idx != 0xd && *idx != 0x20) {
            /* This instance of "obj" appears to be part of a longer string.
             * Skip it, and keep searching for an object. */
            idx += 1 + strlen("obj");
            bytesleft -= 1 + strlen("obj");
            continue;
        }

        /* Found the beginning of the word */
        obj_begin = idx;
        obj_end = idx + 1 + strlen("obj");

        break;
    }

    if ((NULL == obj_begin) || (NULL == obj_end)) {
        status = CL_BREAK;
        goto done; /* No more objs. */
    }

    /* Find the generation id (genid) that appears before the "obj" */
    genid_search_index = findNextNonWSBack(obj_begin - 1, start);
    while (genid_search_index > start && isdigit(*genid_search_index))
        genid_search_index--;

    if (CL_SUCCESS != cli_strntol_wrap(genid_search_index, (size_t)((obj_begin) - genid_search_index), 0, 10, &temp_long)) {
        cli_dbgmsg("pdf_findobj: Failed to parse object genid (# objects found: %u)\n", pdf->nobjs);
        /* Failed to parse, probably not a real object.  Skip past the "obj" thing, and continue. */
        pdf->offset = obj_end - pdf->map;
        status = CL_EPARSE;
        goto done;
    } else if (temp_long < 0) {
        cli_dbgmsg("pdf_findobj: Encountered invalid negative obj genid (%ld).\n", temp_long);
        pdf->offset = obj_end - pdf->map;
        status      = CL_EPARSE;
        goto done;
    }
    genid = (unsigned long)temp_long;

    /* Find the object id (objid) that appears before the genid */
    objid_search_index = findNextNonWSBack(genid_search_index - 1, start);
    while (objid_search_index > start && isdigit(*objid_search_index))
        objid_search_index--;

    if (CL_SUCCESS != cli_strntol_wrap(objid_search_index, (size_t)((genid_search_index) - objid_search_index), 0, 10, &temp_long)) {
        /*
         * Edge case:
         *
         * PDFs with multiple revisions will have %%EOF before the end of the file,
         * followed by the next revision of the PDF, which will probably be an immediate objid.
         *
         * Example:
         *   %%EOF1 1 obj <blah> endobj
         *
         * If this is the case, we can detect it and continue parsing after the %%EOF.
         */
        if (objid_search_index - strlen("\%\%EO") > start) {
            const char* lastfile = objid_search_index - strlen("\%\%EO");
            if (0 != strncmp(lastfile, "\%\%EOF", 5)) {
                /* Nope, wasn't %%EOF */
                cli_dbgmsg("pdf_findobj: Failed to parse object objid (# objects found: %u)\n", pdf->nobjs);
                /* Skip past the "obj" thing, and continue. */
                pdf->offset = obj_end - pdf->map;
                status      = CL_EPARSE;
                goto done;
            }
            /* Yup, Looks, like the file continues after %%EOF.
             * Probably another revision.  Keep parsing... */
            objid_search_index++;
            cli_dbgmsg("pdf_findobj: \%\%EOF detected before end of file, at offset: %zu\n", (size_t)(objid_search_index - pdf->map));
        } else {
            /* Failed parsing at the very beginning */
            cli_dbgmsg("pdf_findobj: Failed to parse object objid (# objects found: %u)\n", pdf->nobjs);
            /* Probably not a real object.  Skip past the "obj" thing, and continue. */
            pdf->offset = obj_end - pdf->map;
            status      = CL_EPARSE;
            goto done;
        }
        /* Try again, with offset slightly adjusted */
        if (CL_SUCCESS != cli_strntol_wrap(objid_search_index, (size_t)((genid_search_index - 1) - objid_search_index), 0, 10, &temp_long)) {
            cli_dbgmsg("pdf_findobj: Failed to parse object objid (# objects found: %u)\n", pdf->nobjs);
            /* Still failed... Probably not a real object.  Skip past the "obj" thing, and continue. */
            pdf->offset = obj_end - pdf->map;
            status      = CL_EPARSE;
            goto done;
        } else if (temp_long < 0) {
            cli_dbgmsg("pdf_findobj: Encountered invalid negative objid (%ld).\n", temp_long);
            pdf->offset = obj_end - pdf->map;
            status      = CL_EPARSE;
            goto done;
        }

        cli_dbgmsg("pdf_findobj: There appears to be an additional revision. Continuing to parse...\n");
    } else if (temp_long < 0) {
        cli_dbgmsg("pdf_findobj: Encountered invalid negative objid (%ld).\n", temp_long);
        pdf->offset = obj_end - pdf->map;
        status      = CL_EPARSE;
        goto done;
    }
    objid = (unsigned long)temp_long;

    obj->id = (objid << 8) | (genid & 0xff);
    obj->start = obj_end - pdf->map; /* obj start begins just after the "obj" string */
    obj->flags = 0;

    /*
     * We now have the objid, genid, and object start.
     * Find the object end ("endobj").
     */
    /* `- 1` accounts for size of white space before obj */
    endobj_begin = cli_memstr(obj_end, pdf->map + pdf->size - obj_end, "endobj", strlen("endobj"));
    if (NULL == endobj_begin) {
        /* No end to object.
         * PDF appears to be malformed or truncated.
         * Will record the object size as going ot the end of the file.
         * Will record that the object is truncated.
         * Will position the pdf offset to the end of the PDF.
         * The next iteration of this function will find no more objects. */
        obj->flags |= 1 << OBJ_TRUNCATED;
        obj->size   = (pdf->map + pdf->size) - obj_end;
        pdf->offset = pdf->size;

        /* Truncated "object" found! */
        status = CL_SUCCESS;
        goto done;
    }
    endobj_end = endobj_begin + strlen("endobj");

    /* Size of the object goes from "obj" <-> "endobject". */
    obj->size = endobj_begin - obj_end;
    pdf->offset = endobj_end - pdf->map;

    /*
     * Object found!
     */
    status = CL_SUCCESS; /* truncated file, no end to obj. */

done:
    if (status == CL_SUCCESS) {
        cli_dbgmsg("pdf_findobj: found %d %d obj @%lld, size: %zu bytes.\n", obj->id >> 8, obj->id&0xff, (long long)(obj->start + pdf->startoff), obj->size);
    }
    else
    {
        /* Remove the unused obj reference from our list of objects found */
        /* No need to realloc pdf->objs back down.  It won't leak. */
        pdf->objs[pdf->nobjs-1] = NULL;
        pdf->nobjs--;

        /* Free up the obj struct. */
        if (NULL != obj)
            free(obj);

        if(status == CL_BREAK) {
            cli_dbgmsg("pdf_findobj: No more objects (# objects found: %u)\n", pdf->nobjs);
        } else if(status == CL_EMEM) {
            cli_warnmsg("pdf_findobj: Error allocating memory (# objects found: %u)\n", pdf->nobjs);
        } else {
            cli_dbgmsg("pdf_findobj: Unexpected status code %d.\n", status);
        }
    }

    return status;
}

static size_t filter_writen(struct pdf_struct *pdf, struct pdf_obj *obj, int fout, const char *buf, size_t len, size_t *sum)
{
    UNUSEDPARAM(obj);

    if (cli_checklimits("pdf", pdf->ctx, (unsigned long)*sum, 0, 0)) /* TODO: May truncate for large values on 64-bit platforms */
        return len; /* pretend it was a successful write to suppress CL_EWRITE */

    *sum += len;

    return cli_writen(fout, buf, (unsigned int)len);
}

void pdfobj_flag(struct pdf_struct *pdf, struct pdf_obj *obj, enum pdf_flag flag)
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

    cli_dbgmsg("pdfobj_flag: %s flagged in object %u %u\n", s, obj->id>>8, obj->id&0xff);
}

struct pdf_obj *find_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t objid)
{
    uint32_t j;
    uint32_t i;

    /* search starting at previous obj (if exists) */
    for (i = 0; i < pdf->nobjs; i++) {
        if (pdf->objs[i] == obj)
            break;
    }

    for (j = i; j < pdf->nobjs; j++) {
        obj = pdf->objs[j];
        if (obj->id == objid)
            return obj;
    }

    /* restart search from beginning if not found */
    for (j = 0; j < i; j++) {
        obj = pdf->objs[j];
        if (obj->id == objid)
            return obj;
    }

    return NULL;
}

/**
 * @brief   Find and interpret the "/Length" dictionary key value.
 *
 * The value may be:
 *  - a direct object (i.e. just a number)
 *  - an indirect object, where the value is somewhere else in the document and we have to look it up.
 *    indirect objects are referenced using an object id (objid), generation id (genid) genid, and the letter 'R'.
 *
 * Example dictionary with a single key "/Length" that relies direct object for the value.
 *
 *      1 0 obj
 *          << /Length 534
 *              /Filter [ /ASCII85Decode /LZWDecode ]
 *          >>
 *          stream
 *              J..)6T`?p&<!J9%_[umg"B7/Z7KNXbN'S+,*Q/&"OLT'FLIDK#!n`$"<Atdi`\Vn%b%)&'cA*VnK\CJY(sF>c!Jnl@
 *              RM]WM;jjH6Gnc75idkL5]+cPZKEBPWdR>FF(kj1_R%W_d&/jS!;iuad7h?[L-F$+]]0A3Ck*$I0KZ?;<)CJtqi65Xb
 *              Vc3\n5ua:Q/=0$W<#N3U;H,MQKqfg1?:lUpR;6oN[C2E4ZNr8Udn.'p+?#X+1>0Kuk$bCDF/(3fL5]Oq)^kJZ!C2H1
 *              'TO]Rl?Q:&'<5&iP!$Rq;BXRecDN[IJB`,)o8XJOSJ9sDS]hQ;Rj@!ND)bD_q&C\g:inYC%)&u#:u,M6Bm%IY!Kb1+
 *              ":aAa'S`ViJglLb8<W9k6Yl\\0McJQkDeLWdPN?9A'jX*al>iG1p&i;eVoK&juJHs9%;Xomop"5KatWRT"JQ#qYuL,
 *              JD?M$0QP)lKn06l1apKDC@\qJ4B!!(5m+j.7F790m(Vj88l8Q:_CZ(Gm1%X\N1&u!FKHMB~>
 *          endstream
 *      endobj
 *
 * Example dictionary with a single key "/Length" that relies on an indirect object for the value.
 *
 *      7 0 obj
 *          << /Length 8 0 R >> % An indirect reference to object 8, with generation id 0.
 *          stream
 *              BT
 *                  /F1 12 Tf
 *                   72 712 Td
 *                  ( A stream with an indirect length ) Tj
 *              ET
 *          endstream
 *      endobj
 *
 *      8 0 obj
 *          77 % The length of the preceding stream
 *      endobj
 *
 * @param pdf       Pdf context structure.
 * @param obj       Pdf object context structure.
 * @param start     Pointer start of the dictionary string.
 * @param len       Remaining length of the dictioary string in bytes.
 * @return size_t   Unsigned integer value of the "/Length" key
 */
static size_t find_length(struct pdf_struct *pdf, struct pdf_obj *obj, const char *dict_start, size_t dict_len)
{
    size_t length = 0;
    const char *obj_start = dict_start;
    size_t bytes_remaining = dict_len;
    long temp_long         = 0;
    const char *index;

    if (bytes_remaining < 8) {
        return 0;
    }

    /*
     * Find the "/Length" dictionary key
     */
    index = cli_memstr(obj_start, bytes_remaining, "/Length", 7);
    if (!index)
        return 0;

    if (bytes_remaining < 1) {
        return 0;
    }

    /* Step the index into the "/Length" string. */
    index++;
    bytes_remaining -= index - obj_start;

    /* Find the start of the next direct or indirect object.
     * pdf_nextobject() assumes we started searching from within a previous object */
    obj_start = pdf_nextobject(index, bytes_remaining);
    if (!obj_start)
        return 0;

    if (bytes_remaining < (size_t)(obj_start - index)) {
        return 0;
    }
    bytes_remaining -= obj_start - index;
    index = obj_start;

    /* Read the value.  This could either be the direct length value,
       or the object id of the indirect object that has the length */
    if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
        cli_dbgmsg("find_length: failed to parse object length or objid\n");
        return 0;
    } else if (temp_long < 0) {
        cli_dbgmsg("find_length: Encountered invalid negative object length or objid (%ld).\n", temp_long);
        return 0;
    }
    length = (size_t)temp_long; /* length or maybe object id */

    /*
     * Keep parsing, skipping past the first integer that might have been what we wanted.
     * If it's an indirect object, we'll find a Generation ID followed by the letter 'R'
     * I.e. something like " 0 R"
     */
    while ((bytes_remaining > 0) && isdigit(*index)) {
        index++;
        bytes_remaining--;
    }

    if ((bytes_remaining > 0) && (*index == ' ')) {
        unsigned long genid;

        index++;
        bytes_remaining--;

        if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
            cli_dbgmsg("find_length: failed to parse object genid\n");
            return 0;
        } else if (temp_long < 0) {
            cli_dbgmsg("find_length: Encountered invalid negative object genid (%ld).\n", temp_long);
            return 0;
        }
        genid = (unsigned long)temp_long;

        while((bytes_remaining > 0) && isdigit(*index)) {
            index++;
            bytes_remaining--;
        }

        if (bytes_remaining < 2) {
            return 0;
        }

        if (index[0] == ' ' && index[1] == 'R') {
            /*
             * Ok so we found a genid and that 'R'.  Which means that first value
             * was actually the objid.
             * We can look up the indirect object using this information.
             */
            unsigned long objid = length;
            const char* indirect_obj_start = NULL;

            cli_dbgmsg("find_length: length is in indirect object %lu %lu\n", objid, genid);

            obj = find_obj(pdf, obj, (length << 8) | (genid&0xff));
            if (!obj) {
                cli_dbgmsg("find_length: indirect object not found\n");
                return 0;
            }

            indirect_obj_start = pdf->map + obj->start;
            bytes_remaining = pdf->size - obj->start;

            /* Ok so we found the indirect object, lets read the value. */
            index = pdf_nextobject(indirect_obj_start, bytes_remaining);
            if (!index) {
                cli_dbgmsg("find_length: next object not found\n");
                return 0;
            }

            if (bytes_remaining < (size_t)(index - indirect_obj_start)) {
                return 0;
            }
            bytes_remaining -= index - indirect_obj_start;

            /* Found the value, so lets parse it as a long, but prohibit negative lengths. */
            if (CL_SUCCESS != cli_strntol_wrap(index, bytes_remaining, 0, 10, &temp_long)) {
                cli_dbgmsg("find_length: failed to parse object length from indirect object\n");
                return 0;
            } else if (temp_long < 0) {
                cli_dbgmsg("find_length: Encountered invalid negative obj length (%ld).\n", temp_long);
                return 0;
            }
            length = (size_t)temp_long;
        }
    }

    /* limit length */
    if ((size_t)(obj_start - pdf->map) + length + 5 > pdf->size)
        length = pdf->size - (obj_start - pdf->map) - 5;

    return length;
}

#define DUMP_MASK ((1 << OBJ_CONTENTS) | (1 << OBJ_FILTER_FLATE) | (1 << OBJ_FILTER_DCT) | (1 << OBJ_FILTER_AH) | (1 << OBJ_FILTER_A85) | (1 << OBJ_EMBEDDED_FILE) | (1 << OBJ_JAVASCRIPT) | (1 << OBJ_OPENACTION) | (1 << OBJ_LAUNCHACTION))

static int run_pdf_hooks(struct pdf_struct *pdf, enum pdf_phase phase, int fd, int dumpid)
{
    int ret;
    struct cli_bc_ctx *bc_ctx;
    cli_ctx *ctx = pdf->ctx;
    fmap_t *map;

    UNUSEDPARAM(dumpid);

    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("run_pdf_hooks: can't allocate memory for bc_ctx\n");
        return CL_EMEM;
    }

    map = *ctx->fmap;
    if (fd != -1) {
        map = fmap(fd, 0, 0);
        if (!map) {
            cli_dbgmsg("run_pdf_hooks: can't mmap pdf extracted obj\n");
            map = *ctx->fmap;
            fd = -1;
        }
    }

    cli_bytecode_context_setpdf(bc_ctx, phase, pdf->nobjs, pdf->objs, &pdf->flags, pdf->size, pdf->startoff);
    cli_bytecode_context_setctx(bc_ctx, ctx);
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PDF, map);
    cli_bytecode_context_destroy(bc_ctx);

    if (fd != -1)
        funmap(map);

    return ret;
}

static void dbg_printhex(const char *msg, const char *hex, unsigned len);

static void aes_decrypt(const unsigned char *in, size_t *length, unsigned char *q, char *key, unsigned key_n, int has_iv)
{
    unsigned long rk[RKLENGTH(256)];
    unsigned char iv[16];
    size_t len = *length;
    unsigned char pad, i;
    int nrounds;

    cli_dbgmsg("aes_decrypt: key length: %d, data length: %zu\n", key_n, *length);
    if (key_n > 32) {
        cli_dbgmsg("aes_decrypt: key length is %d!\n", key_n*8);
        return;
    }

    if (len < 32) {
        cli_dbgmsg("aes_decrypt: len is <32: %zu\n", len);
        noisy_warnmsg("aes_decrypt: len is <32: %zu\n", len);
        return;
    }

    if (has_iv) {
        memcpy(iv, in, 16);
        in += 16;
        len -= 16;
    } else {
        memset(iv, 0, sizeof(iv));
    }

    cli_dbgmsg("aes_decrypt: Calling rijndaelSetupDecrypt\n");
    nrounds = rijndaelSetupDecrypt(rk, (const unsigned char *)key, key_n*8);
    if (!nrounds) {
    cli_dbgmsg("aes_decrypt: nrounds = 0\n");
    return;
    }
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
            cli_dbgmsg("aes_decrypt: bad pad: %x (extra len: %zu)\n", pad, len-16);
            noisy_warnmsg("aes_decrypt: bad pad: %x (extra len: %zu)\n", pad, len-16);
            *length -= len;
            return;
        }

        q -= pad;
        for (i=1;i<pad;i++) {
            if (q[i] != pad) {
                cli_dbgmsg("aes_decrypt: bad pad: %x != %x\n",q[i],pad);
                noisy_warnmsg("aes_decrypt: bad pad: %x != %x\n",q[i],pad);
                *length -= len;

                return;
            }
        }

        len += pad;
    }

    *length -= len;

    cli_dbgmsg("aes_decrypt: length is %zu\n", *length);
}


char *decrypt_any(struct pdf_struct *pdf, uint32_t id, const char *in, size_t *length, enum enc_method enc_method)
{
    unsigned char *key, *q, result[16];
    unsigned n;
    struct arc4_state arc4;

    if (!length || !*length || !in) {
        noisy_warnmsg("decrypt_any: decrypt failed for obj %u %u\n", id>>8, id&0xff);
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

    q = cli_calloc(*length, sizeof(char));
    if (!q) {
        noisy_warnmsg("decrypt_any: malloc failed\n");
        return NULL;
    }

    switch (enc_method) {
    case ENC_V2:
        cli_dbgmsg("cli_pdf: enc is v2\n");
        memcpy(q, in, *length);
        arc4_init(&arc4, result, n);
        arc4_apply(&arc4, q, (unsigned)*length); /* TODO: may truncate for very large lengths */

        noisy_msg(pdf, "decrypt_any: decrypted ARC4 data\n");

        break;
    case ENC_AESV2:
        cli_dbgmsg("cli_pdf: enc is aesv2\n");
        aes_decrypt((const unsigned char *)in, length, q, (char *)result, n, 1);

        noisy_msg(pdf, "decrypt_any: decrypted AES(v2) data\n");

        break;
    case ENC_AESV3:
        cli_dbgmsg("decrypt_any: enc is aesv3\n");
        if (pdf->keylen == 0) {
            cli_dbgmsg("decrypt_any: no key\n");
            return NULL;
        }

        aes_decrypt((const unsigned char *)in, length, q, pdf->key, pdf->keylen, 1);

        noisy_msg(pdf, "decrypted AES(v3) data\n");

        break;
    case ENC_IDENTITY:
        cli_dbgmsg("decrypt_any: enc is identity\n");
        memcpy(q, in, *length);

        noisy_msg(pdf, "decrypt_any: identity encryption\n");

        break;
    case ENC_NONE:
        cli_dbgmsg("decrypt_any: enc is none\n");

        noisy_msg(pdf, "encryption is none\n");

        free(q);
        return NULL;
    case ENC_UNKNOWN:
        cli_dbgmsg("decrypt_any: enc is unknown\n");
        free(q);

        noisy_warnmsg("decrypt_any: unknown encryption method for obj %u %u\n",
               id>>8,id&0xff);

        return NULL;
    }

    return (char *)q;
}

enum enc_method get_enc_method(struct pdf_struct *pdf, struct pdf_obj *obj)
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
            if (*buf == '[') {
                *st = CSTATE_TJ;
            } else {
                const char *nl = memchr(buf, '\n', length);
                if (!nl)
                    return;

                length -= nl - buf;
                buf = nl;
            }

            break;
        case CSTATE_TJ:
            if (*buf == '(')
                *st = CSTATE_TJ_PAROPEN;

            break;
        case CSTATE_TJ_PAROPEN:
            if (*buf == ')') {
                *st = CSTATE_TJ;
            } else {
                if (text_normalize_buffer(s, (const unsigned char *)buf, 1) != 1) {
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
    int fout, n;
    cl_error_t rc;
    enum cstate st = CSTATE_NONE;

    snprintf(fullname, sizeof(fullname), "%s"PATHSEP"pdf%02u_c", pdf->dir, (pdf->files-1));
    fout = open(fullname,O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
    if (fout < 0) {
        char err[128];

        cli_errmsg("pdf_scan_contents: can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
        return CL_ETMPFILE;
    }

    text_normalize_init(&s, (unsigned char *)outbuff, sizeof(outbuff));
    while (1) {
        n = cli_readn(fd, inbuf, sizeof(inbuf));
        if (n <= 0)
            break;

        process(&s, &st, inbuf, n, fout);
    }

    cli_writen(fout, s.out, s.out_pos);

    lseek(fout, 0, SEEK_SET);
    rc = cli_magic_scandesc(fout, fullname, pdf->ctx);
    close(fout);

    if (!pdf->ctx->engine->keeptmp)
        if (cli_unlink(fullname) && rc != CL_VIRUS)
            rc = CL_EUNLINK;

    return rc;
}

int pdf_extract_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t flags)
{
    cli_ctx *ctx = pdf->ctx;
    char fullname[NAME_MAX + 1];
    int fout = -1;
    size_t sum = 0;
    cl_error_t rc = CL_SUCCESS;
    int dump = 1;

    cli_dbgmsg("pdf_extract_obj: obj %u %u\n", obj->id>>8, obj->id&0xff);

    if (obj->objstm) {
        cli_dbgmsg("pdf_extract_obj: extracting obj found in objstm.\n");
        if (obj->objstm->streambuf == NULL) {
            cli_warnmsg("pdf_extract_obj: object in object stream has null stream buffer!\n");
            return CL_EFORMAT;
        }
    }

    /* TODO: call bytecode hook here, allow override dumpability */
    if ((!(obj->flags & (1 << OBJ_STREAM)) || (obj->flags & (1 << OBJ_HASFILTERS))) && !(obj->flags & DUMP_MASK)) {
        /* don't dump all streams */
        dump = 0;
    }

    if ((obj->flags & (1 << OBJ_IMAGE)) && !(obj->flags & (1 << OBJ_FILTER_DCT))) {
        /* don't dump / scan non-JPG images */
        dump = 0;
    }

    if (obj->flags & (1 << OBJ_FORCEDUMP)) {
        /* bytecode can force dump by setting this flag */
        dump = 1;
    }

    if (!dump)
        return CL_CLEAN;

    cli_dbgmsg("pdf_extract_obj: dumping obj %u %u\n", obj->id>>8, obj->id&0xff);

    snprintf(fullname, sizeof(fullname), "%s"PATHSEP"pdf%02u", pdf->dir, pdf->files++);
    fout = open(fullname,O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
    if (fout < 0) {
        char err[128];
        cli_errmsg("pdf_extract_obj: can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));

        return CL_ETMPFILE;
    }

    if (!(flags & PDF_EXTRACT_OBJ_SCAN))
        obj->path = strdup(fullname);

    if ((NULL == obj->objstm) &&
        (obj->flags & (1 << OBJ_STREAM))) {
        /*
         * Object contains a stream. Parse this now.
         */
        cli_dbgmsg("pdf_extract_obj: parsing a stream in obj %u %u\n", obj->id>>8, obj->id&0xff);

        const char *start = pdf->map + obj->start;

        size_t length;
        size_t orig_length;
        int dict_len = obj->stream - start; /* Dictionary should end where the stream begins */

        const char *pstr;
        struct pdf_dict *dparams = NULL;
        struct objstm_struct *objstm = NULL;
        int xref = 0;

        /* Find and interpret the length dictionary value */
        length = find_length(pdf, obj, start, dict_len);
        if (length < 0)
            length = 0;

        orig_length = length;

        if (length > obj->stream_size) {
            cli_dbgmsg("cli_pdf: Stream length exceeds object length by %zu bytes. Length truncated to %zu bytes\n", length - obj->stream_size, obj->stream_size);
            noisy_warnmsg("Stream length exceeds object length by %zu bytes. Length truncated to %zu bytes\n", length - obj->stream_size, obj->stream_size);

            length = obj->stream_size;
        }

        if (!(obj->flags & (1 << OBJ_FILTER_FLATE)) && (length <= 0)) {
            /*
             * If the length is unknown and this doesn't contain a FLATE encoded filter...
             * Calculate the length using the stream size, and trimming
             * off any newline/carriage returns from the end of the stream.
             */
            const char *q = start + obj->stream_size;
            length = obj->stream_size;
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

            cli_dbgmsg("pdf_extract_obj: calculated length %lld\n", (long long)length);
        } else {
            if (obj->stream_size > (size_t)length + 2) {
                cli_dbgmsg("cli_pdf: calculated length %zu < %zu\n",
                            (size_t)length, obj->stream_size);
                length = obj->stream_size;
            }
        }

        if ((0 != orig_length) && (obj->stream_size > (size_t)orig_length + 20)) {
            cli_dbgmsg("pdf_extract_obj: orig length: %lld, length: %lld, size: %zu\n",
                        (long long)orig_length, (long long)length, obj->stream_size);
            pdfobj_flag(pdf, obj, BAD_STREAMLEN);
        }

        if (0 == length) {
            length = obj->stream_size;
            if (0 == length) {
                cli_dbgmsg("pdf_extract_obj: Alleged or calculated stream length and stream buffer size both 0\n");
                goto done; /* Empty stream, nothing to scan */
            }
        }

        /* Check if XRef is enabled */
        if (cli_memstr(start, dict_len, "/XRef", strlen("/XRef"))) {
            xref = 1;
        }

        cli_dbgmsg("-------------EXPERIMENTAL-------------\n");

        /*
         * Identify the DecodeParms, if available.
         */
        if (NULL != (pstr = pdf_getdict(start, &dict_len, "/DecodeParms")))
        {
            cli_dbgmsg("pdf_extract_obj: Found /DecodeParms\n");
        }
        else if (NULL != (pstr = pdf_getdict(start, &dict_len, "/DP")))
        {
            cli_dbgmsg("pdf_extract_obj: Found /DP\n");
        }

        if (pstr) {
            /* shift pstr left to "<<" for pdf_parse_dict */
            while ((*pstr == '<') && (pstr > start)) {
                pstr--;
                dict_len++;
            }

            /* shift pstr right to "<<" for pdf_parse_dict */
            while ((*pstr != '<') && (dict_len > 0)) {
                pstr++;
                dict_len--;
            }

            if (dict_len > 4)
                dparams = pdf_parse_dict(pdf, obj, obj->size, (char *)pstr, NULL);
            else
                cli_dbgmsg("pdf_extract_obj: failed to locate DecodeParms dictionary start\n");
        }

        /*
         * Go back to the start of the dictionary and check to see if the stream
         * is an object stream. If so, collect the relevant info.
         */
        dict_len = obj->stream - start;
        if (NULL != (pstr = pdf_getdict(start, &dict_len, "/Type/ObjStm")))
        {
            int32_t objstm_first = -1;
            int32_t objstm_length = -1;
            int32_t objstm_n = -1;

            cli_dbgmsg("pdf_extract_obj: Found /Type/ObjStm\n");

            dict_len = obj->stream - start;
            if ((-1 == (objstm_first = pdf_readint(start, dict_len, "/First"))))
            {
                cli_warnmsg("pdf_extract_obj: Failed to find offset of first object in object stream\n");
            }
            else if ((-1 == (objstm_length = pdf_readint(start, dict_len, "/Length"))))
            {
                cli_warnmsg("pdf_extract_obj: Failed to find length of object stream\n");
            }
            else if ((-1 == (objstm_n = pdf_readint(start, dict_len, "/N"))))
            {
                cli_warnmsg("pdf_extract_obj: Failed to find num objects in object stream\n");
            }
            else
            {
                /* Add objstm to pdf struct, so it can be freed eventually */
                pdf->nobjstms++;
                pdf->objstms = cli_realloc2(pdf->objstms, sizeof(struct objstm_struct*) * pdf->nobjstms);
                if (!pdf->objstms) {
                    cli_warnmsg("pdf_extract_obj: out of memory parsing object stream (%u)\n", pdf->nobjstms);
                    pdf_free_dict(dparams);
                    return CL_EMEM;
                }

                objstm = malloc(sizeof(struct objstm_struct));
                if (!objstm) {
                    cli_warnmsg("pdf_extract_obj: out of memory parsing object stream (%u)\n", pdf->nobjstms);
                    pdf_free_dict(dparams);
                    return CL_EMEM;
                }
                pdf->objstms[pdf->nobjstms-1] = objstm;

                memset(objstm, 0, sizeof(*objstm));

                objstm->first =         (uint32_t)objstm_first;
                objstm->current =       (uint32_t)objstm_first;
                objstm->current_pair =  0;
                objstm->length =        (uint32_t)objstm_length;
                objstm->n =             (uint32_t)objstm_n;

                cli_dbgmsg("pdf_extract_obj: ObjStm first obj at offset %d\n", objstm->first);
                cli_dbgmsg("pdf_extract_obj: ObjStm length is %d bytes\n", objstm->length);
                cli_dbgmsg("pdf_extract_obj: ObjStm should contain %d objects\n", objstm->n);
            }
        }

        sum = pdf_decodestream(pdf, obj, dparams, obj->stream, (uint32_t)length, xref, fout, &rc, objstm);
        if ((CL_SUCCESS != rc) && (CL_VIRUS != rc)) {
            cli_dbgmsg("Error decoding stream! Error code: %d\n", rc);

            /* It's ok if we couldn't decode the stream,
             *   make a best effort to keep parsing. */
            if (CL_EPARSE == rc)
                rc = CL_SUCCESS;

            if (NULL != objstm) {
                /*
                 * If we were expecting an objstm and there was a failure...
                 *   discard the memory for last object stream.
                 */
                if (NULL != pdf->objstms) {
                    if (NULL != pdf->objstms[pdf->nobjstms - 1]) {
                        if (NULL != pdf->objstms[pdf->nobjstms - 1]->streambuf) {
                            free(pdf->objstms[pdf->nobjstms - 1]->streambuf);
                            pdf->objstms[pdf->nobjstms - 1]->streambuf = NULL;
                        }
                        free(pdf->objstms[pdf->nobjstms - 1]);
                        pdf->objstms[pdf->nobjstms - 1] = NULL;
                    }

                    /* Pop the objstm off the end of the pdf->objstms array. */
                    if (pdf->nobjstms > 0) {
                        pdf->nobjstms--;
                        if (0 == pdf->nobjstms) {
                            free(pdf->objstms);
                            pdf->objstms = NULL;
                        } else {
                            pdf->objstms = cli_realloc2(pdf->objstms, sizeof(struct objstm_struct*) * pdf->nobjstms);

                            if (!pdf->objstms) {
                                cli_warnmsg("pdf_extract_obj: out of memory when shrinking down objstm array\n");
                                return CL_EMEM;
                            }
                        }
                    } else {
                        /* hm.. this shouldn't happen */
                        cli_warnmsg("pdf_extract_obj: Failure counting objstms.\n");
                    }
                }
            }
        }

        if (dparams)
            pdf_free_dict(dparams);

        if ((rc == CL_VIRUS) && !SCAN_ALLMATCHES) {
            sum = 0; /* prevents post-filter scan */
            goto done;
        }

        cli_dbgmsg("-------------EXPERIMENTAL-------------\n");

    } else if (obj->flags & (1 << OBJ_JAVASCRIPT)) {
        const char *q2;
        const char *q = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                        : (const char *)(obj->start + pdf->map);

        /* TODO: get obj-endobj size */
        off_t bytesleft = obj->size;

        if (bytesleft < 0) {
            goto done;
        }

        do {
            char *js = NULL;
            size_t js_len = 0;
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
                char *decrypted = NULL;
                const char *out = js;
                js_len = strlen(js);
                if (pdf->flags & (1 << DECRYPTABLE_PDF)) {
                    cli_dbgmsg("pdf_extract_obj: encrypted string\n");
                    decrypted = decrypt_any(pdf, obj->id, js, &js_len, pdf->enc_method_string);

                    if (decrypted) {
                        noisy_msg(pdf, "pdf_extract_obj: decrypted Javascript string from obj %u %u\n", obj->id>>8,obj->id&0xff);
                        out = decrypted;
                    }
                }

                if (filter_writen(pdf, obj, fout, out, js_len, (size_t*)&sum) != js_len) {
                    rc = CL_EWRITE;
                            free(js);
                    break;
                }

                free(decrypted);
                free(js);
                cli_dbgmsg("pdf_extract_obj: bytesleft: %d\n", (int)bytesleft);

                if (bytesleft > 0) {
                    q2 = pdf_nextobject(q, bytesleft);
                    if (!q2)
                        q2 = q + bytesleft - 1;

                    /* non-conforming PDFs that don't escape ) properly */
                    q3 = memchr(q, ')', bytesleft);
                    if (q3 && q3 < q2)
                        q2 = q3;

                    while (q2 > q && q2[-1] == ' ')
                        q2--;

                    if (q2 > q) {
                        q--;
                        filter_writen(pdf, obj, fout, q, q2 - q, (size_t*)&sum);
                        q++;
                    }
                }
            }

        } while (bytesleft > 0);
    } else {
        off_t bytesleft = obj->size;

        if (bytesleft < 0)
            rc = CL_EFORMAT;
        else {
            if (obj->objstm) {
                if (filter_writen(pdf, obj, fout , obj->objstm->streambuf + obj->start, bytesleft, (size_t*)&sum) != (size_t)bytesleft)
                    rc = CL_EWRITE;
            } else {
                if (filter_writen(pdf, obj, fout , pdf->map + obj->start, bytesleft, (size_t*)&sum) != (size_t)bytesleft)
                    rc = CL_EWRITE;
            }
        }
    }

done:

    cli_dbgmsg("pdf_extract_obj: extracted %td bytes %u %u obj\n", sum, obj->id>>8, obj->id&0xff);
    cli_dbgmsg("pdf_extract_obj:         ... to %s\n", fullname);

    if (flags & PDF_EXTRACT_OBJ_SCAN && sum) {
        int rc2;

        cli_updatelimits(pdf->ctx, sum);

        /* TODO: invoke bytecode on this pdf obj with metainformation associated */
        lseek(fout, 0, SEEK_SET);
        rc2 = cli_magic_scandesc(fout, fullname, pdf->ctx);
        if (rc2 == CL_VIRUS || rc == CL_SUCCESS)
            rc = rc2;

        if ((rc == CL_CLEAN) || ((rc == CL_VIRUS) && SCAN_ALLMATCHES)) {
            unsigned int dumpid = 0;
            for (dumpid = 0; dumpid < pdf->nobjs; dumpid++) {
                if (pdf->objs[dumpid] == obj)
                    break;
            }
            rc2 = run_pdf_hooks(pdf, PDF_PHASE_POSTDUMP, fout, dumpid);
            if (rc2 == CL_VIRUS)
                rc = rc2;
        }

        if (((rc == CL_CLEAN) || ((rc == CL_VIRUS) && SCAN_ALLMATCHES)) && (obj->flags & (1 << OBJ_CONTENTS))) {
            lseek(fout, 0, SEEK_SET);
            cli_dbgmsg("pdf_extract_obj: dumping contents %u %u\n", obj->id>>8, obj->id&0xff);

            rc2 = pdf_scan_contents(fout, pdf);
            if (rc2 == CL_VIRUS)
                rc = rc2;

            noisy_msg(pdf, "pdf_extract_obj: extracted text from obj %u %u\n", obj->id>>8, obj->id&0xff);
        }
    }

    close(fout);

    if (flags & PDF_EXTRACT_OBJ_SCAN && !pdf->ctx->engine->keeptmp)
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

#define NAMEFLAG_NONE       0x0
#define NAMEFLAG_HEURISTIC  0x1

struct pdfname_action {
    const char *pdfname;
    enum pdf_objflags set_objflag;/* OBJ_DICT is noop */
    enum objstate from_state;/* STATE_NONE is noop */
    enum objstate to_state;
    uint32_t nameflags;
#if HAVE_JSON
    void (*pdf_stats_cb)(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act);
#endif
};

#if HAVE_JSON
static struct pdfname_action pdfname_actions[] = {
    {"ASCIIHexDecode", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, ASCIIHexDecode_cb},
    {"ASCII85Decode", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, ASCII85Decode_cb},
    {"A85", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, ASCII85Decode_cb},
    {"AHx", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, ASCIIHexDecode_cb},
    {"EmbeddedFile", OBJ_EMBEDDED_FILE, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC, EmbeddedFile_cb},
    {"FlateDecode", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, FlateDecode_cb},
    {"Fl", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, FlateDecode_cb},
    {"Image", OBJ_IMAGE, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC, Image_cb},
    {"LZWDecode", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, LZWDecode_cb},
    {"LZW", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, LZWDecode_cb},
    {"RunLengthDecode", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, RunLengthDecode_cb},
    {"RL", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, RunLengthDecode_cb},
    {"CCITTFaxDecode", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, CCITTFaxDecode_cb},
    {"CCF", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, CCITTFaxDecode_cb},
    {"JBIG2Decode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, JBIG2Decode_cb},
    {"DCTDecode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, DCTDecode_cb},
    {"DCT", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, DCTDecode_cb},
    {"JPXDecode", OBJ_FILTER_JPX, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, JPXDecode_cb},
    {"Crypt",  OBJ_FILTER_CRYPT, STATE_FILTER, STATE_NONE, NAMEFLAG_HEURISTIC, Crypt_cb},
    {"Standard", OBJ_FILTER_STANDARD, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC, Standard_cb},
    {"Sig",    OBJ_SIGNED, STATE_ANY, STATE_NONE, NAMEFLAG_HEURISTIC, Sig_cb},
    {"V",     OBJ_SIGNED, STATE_ANY, STATE_NONE, NAMEFLAG_HEURISTIC, NULL},
    {"R",     OBJ_SIGNED, STATE_ANY, STATE_NONE, NAMEFLAG_HEURISTIC, NULL},
    {"Linearized", OBJ_DICT, STATE_NONE, STATE_LINEARIZED, NAMEFLAG_HEURISTIC, NULL},
    {"Filter", OBJ_HASFILTERS, STATE_ANY, STATE_FILTER, NAMEFLAG_HEURISTIC, NULL},
    {"JavaScript", OBJ_JAVASCRIPT, STATE_S, STATE_JAVASCRIPT, NAMEFLAG_HEURISTIC, JavaScript_cb},
    {"Length", OBJ_DICT, STATE_FILTER, STATE_NONE, NAMEFLAG_HEURISTIC, NULL},
    {"S", OBJ_DICT, STATE_NONE, STATE_S, NAMEFLAG_HEURISTIC, NULL},
    {"Type", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC, NULL},
    {"OpenAction", OBJ_OPENACTION, STATE_ANY, STATE_OPENACTION, NAMEFLAG_HEURISTIC, OpenAction_cb},
    {"Launch", OBJ_LAUNCHACTION, STATE_ANY, STATE_LAUNCHACTION, NAMEFLAG_HEURISTIC, Launch_cb},
    {"Page", OBJ_PAGE, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC, Page_cb},
    {"Contents", OBJ_CONTENTS, STATE_NONE, STATE_CONTENTS, NAMEFLAG_HEURISTIC, NULL},
    {"Author", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Author_cb},
    {"Producer", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Producer_cb},
    {"CreationDate", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, CreationDate_cb},
    {"ModDate", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, ModificationDate_cb},
    {"Creator", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Creator_cb},
    {"Title", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Title_cb},
    {"Keywords", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Keywords_cb},
    {"Subject", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Subject_cb},
    {"Pages", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Pages_cb},
    {"Colors", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, Colors_cb},
    {"RichMedia", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, RichMedia_cb},
    {"AcroForm", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, AcroForm_cb},
    {"XFA", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_NONE, XFA_cb}
};
#else
static struct pdfname_action pdfname_actions[] = {
    {"ASCIIHexDecode", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"ASCII85Decode", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"A85", OBJ_FILTER_A85, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"AHx", OBJ_FILTER_AH, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"EmbeddedFile", OBJ_EMBEDDED_FILE, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"FlateDecode", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"Fl", OBJ_FILTER_FLATE, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"Image", OBJ_IMAGE, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"LZWDecode", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"LZW", OBJ_FILTER_LZW, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"RunLengthDecode", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"RL", OBJ_FILTER_RL, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"CCITTFaxDecode", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"CCF", OBJ_FILTER_FAX, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"JBIG2Decode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"DCTDecode", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"DCT", OBJ_FILTER_DCT, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"JPXDecode", OBJ_FILTER_JPX, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"Crypt",  OBJ_FILTER_CRYPT, STATE_FILTER, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"Standard", OBJ_FILTER_STANDARD, STATE_FILTER, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"Sig",    OBJ_SIGNED, STATE_ANY, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"V",     OBJ_SIGNED, STATE_ANY, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"R",     OBJ_SIGNED, STATE_ANY, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"Linearized", OBJ_DICT, STATE_NONE, STATE_LINEARIZED, NAMEFLAG_HEURISTIC},
    {"Filter", OBJ_HASFILTERS, STATE_ANY, STATE_FILTER, NAMEFLAG_HEURISTIC},
    {"JavaScript", OBJ_JAVASCRIPT, STATE_S, STATE_JAVASCRIPT, NAMEFLAG_HEURISTIC},
    {"Length", OBJ_DICT, STATE_FILTER, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"S", OBJ_DICT, STATE_NONE, STATE_S, NAMEFLAG_HEURISTIC},
    {"Type", OBJ_DICT, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"OpenAction", OBJ_OPENACTION, STATE_ANY, STATE_OPENACTION, NAMEFLAG_HEURISTIC},
    {"Launch", OBJ_LAUNCHACTION, STATE_ANY, STATE_LAUNCHACTION, NAMEFLAG_HEURISTIC},
    {"Page", OBJ_PAGE, STATE_NONE, STATE_NONE, NAMEFLAG_HEURISTIC},
    {"Contents", OBJ_CONTENTS, STATE_NONE, STATE_CONTENTS, NAMEFLAG_HEURISTIC}
};
#endif

#define KNOWN_FILTERS ((1 << OBJ_FILTER_AH) | (1 << OBJ_FILTER_RL) | (1 << OBJ_FILTER_A85) | (1 << OBJ_FILTER_FLATE) | (1 << OBJ_FILTER_LZW) | (1 << OBJ_FILTER_FAX) | (1 << OBJ_FILTER_DCT) | (1 << OBJ_FILTER_JPX) | (1 << OBJ_FILTER_CRYPT))

static void handle_pdfname(struct pdf_struct *pdf, struct pdf_obj *obj, const char *pdfname, int escapes, enum objstate *state)
{
    struct pdfname_action *act = NULL;
    unsigned j;

    obj->statsflags |= OBJ_FLAG_PDFNAME_DONE;

    for (j=0;j<sizeof(pdfname_actions)/sizeof(pdfname_actions[0]);j++) {
        if (!strcmp(pdfname, pdfname_actions[j].pdfname)) {
            act = &pdfname_actions[j];
            break;
        }
    }

    if (!act) {
        /* these are digital signature objects, filter doesn't matter,
         * we don't need them anyway */
        if (*state == STATE_FILTER && !(obj->flags & (1 << OBJ_SIGNED)) && !(obj->flags & KNOWN_FILTERS)) {
            cli_dbgmsg("handle_pdfname: unknown filter %s\n", pdfname);
            obj->flags |= 1 << OBJ_FILTER_UNKNOWN;
        }

        return;
    }

    /* record filter order */
    if (obj->numfilters < PDF_FILTERLIST_MAX && (*state == STATE_FILTER) && ((1 << act->set_objflag) & KNOWN_FILTERS))
        obj->filterlist[obj->numfilters++] = act->set_objflag;

    if ((act->nameflags & NAMEFLAG_HEURISTIC) && escapes) {
        /* if a commonly used PDF name is escaped that is certainly
           suspicious. */
        cli_dbgmsg("handle_pdfname: pdfname %s is escaped\n", pdfname);
        pdfobj_flag(pdf, obj, ESCAPED_COMMON_PDFNAME);
    }

#if HAVE_JSON
    if ((act->pdf_stats_cb))
        act->pdf_stats_cb(pdf, obj, act);
#endif

    if (act->from_state == *state || act->from_state == STATE_ANY) {
        *state = act->to_state;

        if (*state == STATE_FILTER && act->set_objflag != OBJ_DICT && (obj->flags & (1 << act->set_objflag))) {
            cli_dbgmsg("handle_pdfname: duplicate stream filter %s\n", pdfname);
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

static void pdf_parse_encrypt(struct pdf_struct *pdf, const char *enc, int len)
{
    const char *q, *q2;
    unsigned long objid;
    unsigned long genid;
    long temp_long;

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
    len -= q2 - q;
    q = q2;

    if (CL_SUCCESS != cli_strntol_wrap(q2, (size_t)len, 0, 10, &temp_long)) {
        cli_dbgmsg("pdf_parse_encrypt: Found Encrypt dictionary but failed to parse objid\n");
        return;
    } else if (temp_long < 0) {
        cli_dbgmsg("pdf_parse_encrypt: Encountered invalid negative objid (%ld).\n", temp_long);
        return;
    }
    objid = (unsigned long)temp_long;

    objid = objid << 8;
    q2 = pdf_nextobject(q, len);
    if (!q2 || !isdigit(*q2))
        return;
    len -= q2 - q;
    q = q2;

    if (CL_SUCCESS != cli_strntol_wrap(q2, (size_t)len, 0, 10, &temp_long)) {
        cli_dbgmsg("pdf_parse_encrypt: Found Encrypt dictionary but failed to parse genid\n");
        return;
    } else if (temp_long < 0) {
        cli_dbgmsg("pdf_parse_encrypt: Encountered invalid negative genid (%ld).\n", temp_long);
        return;
    }
    genid = (unsigned long)temp_long;

    objid |= genid & 0xff;
    q2 = pdf_nextobject(q, len);
    if (!q2 || *q2 != 'R')
        return;

    cli_dbgmsg("pdf_parse_encrypt: Encrypt dictionary in obj %lu %lu\n", objid>>8, objid&0xff);

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

void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    /* enough to hold common pdf names, we don't need all the names */
    char pdfname[64];
    const char *q2, *q3;
    const char *nextobj = NULL, *nextopen = NULL, *nextclose = NULL;
    const char *q = NULL;
    const char *dict = NULL, *enddict = NULL, *start = NULL;
    off_t dict_length = 0, full_dict_length = 0, bytesleft = 0;
    size_t i = 0;
    unsigned filters = 0, blockopens = 0;
    enum objstate objstate = STATE_NONE;
#if HAVE_JSON
    json_object *pdfobj=NULL, *jsonobj=NULL;
#endif

    if (NULL == pdf || NULL == obj) {
        cli_warnmsg("pdf_parseobj: invalid arguments\n");
        return;
    }

    cli_dbgmsg("pdf_parseobj: Parsing object %u %u\n", obj->id >> 8, obj->id & 0xff);

    if (obj->objstm) {
        if ((size_t)obj->start > obj->objstm->streambuf_len) {
            cli_dbgmsg("pdf_parseobj: %u %u obj: obj start (%u) is greater than size of object stream (%zu).\n",
                obj->id >> 8, obj->id & 0xff, obj->start, obj->objstm->streambuf_len);
            return;
        }
        q = (const char *)(obj->start + obj->objstm->streambuf);
    } else {
        if ((size_t)obj->start > pdf->size) {
            cli_dbgmsg("pdf_parseobj: %u %u obj: obj start (%u) is greater than size of PDF (%lld).\n",
                obj->id >> 8, obj->id & 0xff, obj->start, (long long)pdf->size);
            return;
        }
        q = (const char *)(obj->start + pdf->map);
    }
    start = q;

    if (obj->size <= 0)
        return;

    if (obj->objstm) {
        bytesleft = MIN(obj->size, obj->objstm->streambuf_len - obj->start);
    } else {
        bytesleft = MIN(obj->size, pdf->size - obj->start);
    }

    /* For objects that aren't already in an object stream^, check if they contain a stream.
     * ^Objects in object streams aren't supposed to contain streams, so we don't check them. */
    if (NULL == obj->objstm) {
        /* Check if object contains stream */
        cl_error_t has_stream;
        const char* stream = NULL;
        size_t stream_size = 0;

        has_stream = find_stream_bounds(
            start,
            obj->size,
            &stream,
            &stream_size,
            (pdf->enc_method_stream <= ENC_IDENTITY) && (pdf->enc_method_embeddedfile <= ENC_IDENTITY));

        if ((CL_SUCCESS == has_stream) ||
            (CL_EFORMAT == has_stream)) {
            /* Stream found. Store this fact and the stream bounds. */
            cli_dbgmsg("pdf_parseobj: %u %u contains stream, size: %zu\n", obj->id>>8, obj->id&0xff, stream_size);
            obj->flags |= (1 << OBJ_STREAM);
            obj->stream = stream;
            obj->stream_size = stream_size;
        }
    }

    /* find start of dictionary */
    do {
        nextobj = pdf_nextobject(q, bytesleft);
        bytesleft -= nextobj -q;

        if (!nextobj || bytesleft < 0) {
            cli_dbgmsg("pdf_parseobj: %u %u obj: no dictionary\n", obj->id>>8, obj->id&0xff);
#if HAVE_JSON
            if (!(pdfobj) && pdf->ctx->wrkproperty != NULL) {
                pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
                if (!(pdfobj))
                    return;
            }

            if (pdfobj) {
                if (!(jsonobj))
                    jsonobj = cli_jsonarray(pdfobj, "ObjectsWithoutDictionaries");
                if (jsonobj)
                    cli_jsonint_array(jsonobj, obj->id>>8);
            }
#endif
            return;
        }

        /*
         * Opening `<` for object's dictionary may be back 1 character,
         * provided q is not at the start of the buffer (it shouldn't be).
         */
        if (obj->objstm) {
            if (obj->objstm->streambuf == q) {
                q3 = memchr(q, '<', nextobj - q);
            } else {
        q3 = memchr(q-1, '<', nextobj-q+1);
            }
        } else {
            if (pdf->map == q) {
                q3 = memchr(q, '<', nextobj - q);
            } else {
                q3 = memchr(q - 1, '<', nextobj - q + 1);
            }
        }
        nextobj++;
        bytesleft--;
        q = nextobj;
    } while (!q3 || q3[1] != '<');
    dict = q3+2;
    q = dict;
    blockopens++;
    bytesleft = obj->size - (q - start);
    enddict = q + bytesleft - 1;

    /* find end of dictionary block */
    if (bytesleft < 0) {
        cli_dbgmsg("pdf_parseobj: %u %u obj: broken dictionary\n", obj->id>>8, obj->id&0xff);
#if HAVE_JSON
        if (!(pdfobj) && pdf->ctx->wrkproperty != NULL) {
            pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
            if (!(pdfobj))
                return;
        }

        if (pdfobj) {
            if (!(jsonobj))
                jsonobj = cli_jsonarray(pdfobj, "ObjectsWithBrokenDictionaries");
            if (jsonobj)
                cli_jsonint_array(jsonobj, obj->id>>8);
        }
#endif
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
        cli_dbgmsg("pdf_parseobj: %u %u obj broken dictionary\n", obj->id>>8, obj->id&0xff);
#if HAVE_JSON
        if (!(pdfobj) && pdf->ctx->wrkproperty != NULL) {
            pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
            if (!(pdfobj))
                return;
        }

        if (pdfobj) {
            if (!(jsonobj))
                jsonobj = cli_jsonarray(pdfobj, "ObjectsWithBrokenDictionaries");
            if (jsonobj)
                cli_jsonint_array(jsonobj, obj->id>>8);
        }
#endif
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
                if (dict[i] == '\r')
                    dictionary[i] = '\n';
                else if (isprint(dict[i]) || isspace(dict[i]))
                    dictionary[i] = dict[i];
                else
                    dictionary[i] = '*';
            }
            dictionary[dict_length] = '\0';
            cli_dbgmsg("pdf_parseobj: dictionary is <<%s>>\n", dictionary);
            free(dictionary);
        }
    }
    */

    /*  process pdf names */
    for (q = dict;dict_length > 0;) {
        int escapes = 0, breakout=0;
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

            switch (*q) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
            case '/':
            case '>':
            case '[':
            case ']':
            case '<':
            case '(':
                breakout = 1;
            }

            if (breakout)
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
            if ((trailer_end > 0) && ((size_t)trailer_end < pdf->size)) {
                trailer = trailer_end - 1024;
                if (trailer < 0)
                    trailer = 0;

                q2 = pdf->map + trailer;
                cli_dbgmsg("pdf_parseobj: looking for trailer in linearized pdf: %ld - %ld\n", trailer, trailer_end);
                pdf_parse_trailer(pdf, q2, trailer_end - trailer);
                if (pdf->fileID)
                    cli_dbgmsg("pdf_parseobj: found fileID\n");
            }
        }

        if (objstate == STATE_LAUNCHACTION)
            pdfobj_flag(pdf, obj, HAS_LAUNCHACTION);
        if (dict_length > 0 && (objstate == STATE_JAVASCRIPT || objstate == STATE_OPENACTION || objstate == STATE_CONTENTS)) {
            off_t dict_remaining = dict_length;

            if (objstate == STATE_OPENACTION)
                pdfobj_flag(pdf, obj, HAS_OPENACTION);

            q2 = pdf_nextobject(q, dict_remaining);
            if (q2 && isdigit(*q2)) {
                const char * q2_old = NULL;
                unsigned long objid;
                unsigned long genid;
                long temp_long;

                dict_remaining -= (off_t)(q2 - q);

                if (CL_SUCCESS != cli_strntol_wrap(q2, (size_t)dict_remaining, 0, 10, &temp_long)) {
                    cli_dbgmsg("pdf_parseobj: failed to parse object objid\n");
                    return;
                } else if (temp_long < 0) {
                    cli_dbgmsg("pdf_parseobj: Encountered invalid negative genid (%ld).\n", temp_long);
                    return;
                }
                objid = (unsigned long)temp_long;

                objid = objid << 8;

                while ((dict_remaining > 0) && isdigit(*q2)) {
                    q2++;
                    dict_remaining--;
                }

                q2_old = q2;
                q2 = pdf_nextobject(q2, dict_remaining);
                if (q2 && isdigit(*q2)) {
                    dict_remaining -= (off_t)(q2 - q2_old);
                    if (CL_SUCCESS != cli_strntol_wrap(q2, (size_t)dict_remaining, 0, 10, &temp_long)) {
                        cli_dbgmsg("pdf_parseobj: failed to parse object genid\n");
                        return;
                    } else if (temp_long < 0) {
                        cli_dbgmsg("pdf_parseobj: Encountered invalid negative genid (%ld).\n", temp_long);
                        return;
                    }
                    genid = (unsigned long)temp_long;

                    objid |= genid & 0xff;

                    q2 = pdf_nextobject(q2, dict_remaining);
                    if (q2 && *q2 == 'R') {
                        struct pdf_obj *obj2;

                        cli_dbgmsg("pdf_parseobj: found %s stored in indirect object %lu %lu\n", pdfname, objid >> 8, objid&0xff);
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

    if (filters > 2) {
        /* more than 2 non-crypt filters */
        pdfobj_flag(pdf, obj, MANY_FILTERS);
    }

    if (obj->flags & ((1 << OBJ_SIGNED) | KNOWN_FILTERS))
        obj->flags &= ~(1 << OBJ_FILTER_UNKNOWN);

    if (obj->flags & (1 << OBJ_FILTER_UNKNOWN))
        pdfobj_flag(pdf, obj, UNKNOWN_FILTER);

    cli_dbgmsg("pdf_parseobj: %u %u obj flags: %02x\n", obj->id>>8, obj->id&0xff, obj->flags);
}

/**
 * @brief   Given a pointer to a dictionary object and a key, get the key's value.
 *
 * @param q0            Offset of the start of the dictionary.
 * @param[in,out] len   In: The number of bytes in the dictionary.
 *                      Out: The number of bytes remaining from the start
 *                           of the value to the end of the dict
 * @param key           Null terminated 'key' to search for.
 * @return const char*  Address of the dictionary key's 'value'.
 */
static const char *pdf_getdict(const char *q0, int* len, const char *key)
{
    const char *q;

    if (*len <= 0) {
        cli_dbgmsg("pdf_getdict: bad length %d\n", *len);
        return NULL;
    }

    if (!q0)
        return NULL;

    /* find the key */
    q = cli_memstr(q0, *len, key, strlen(key));
    if (!q) {
        cli_dbgmsg("pdf_getdict: %s not found in dict\n", key);
        return NULL;
    }

    *len -= q - q0;
    q0 = q;

    /* find the start of the value object */
    q = pdf_nextobject(q0 + 1, *len - 1);
    if (!q) {
        cli_dbgmsg("pdf_getdict: %s is invalid in dict\n", key);
        return NULL;
    }

    /* if the value is a dictionary object, include the < > brackets.*/
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
    if (!q || len <= 0)
        return NULL;

    if (*q == '(') {
        int paren = 1;
        start = ++q;
        len--;
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

        if (len <= 0) {
            cli_errmsg("pdf_readstring: Invalid, truncated dictionary.\n");
            return NULL;
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

                        *s++ = 64*(q[0] - '0') + 8*(q[1] - '0') + (q[2] - '0');
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

    if ((*q == '<') && (len >= 3))  {
        start = ++q;
        len -= 1;
        q = memchr(q+1, '>', len-1);
        if (!q)
            return NULL;

        if (qend)
            *qend = q;

        s = cli_malloc((q - start)/2 + 1);
        if (s == NULL) { /* oops, couldn't allocate memory */
          cli_dbgmsg("pdf_readstring: unable to allocate memory...\n");
          return NULL;
        }

        if (cli_hex2str_to(start, s, q - start)) {
            cli_dbgmsg("pdf_readstring: %s has bad hex value\n", key);
            free(s);
            return NULL;
        }

        s[(q-start)/2] = '\0';
        if (slen)
            *slen = (q - start)/2;

        return s;
    }

    cli_dbgmsg("pdf_readstring: %s is invalid string in dict\n", key);
    return NULL;
}

static char *pdf_readval(const char *q, int len, const char *key)
{
    const char *end;
    char *s;
    int origlen = len;

    q = pdf_getdict(q, &len, key);
    if (!q || len <= 0)
        return NULL;

    while (len > 0 && *q && *q == ' ') {
        q++;
        len--;
    }

    if (*q != '/')
        return NULL;

    q++;
    len--;
    end = q;

    while (len > 0 && *end && !(*end == '/' || (len > 1 && end[0] == '>' && end[1] == '>'))) {
        end++;
        len--;
    }

    /* end-of-buffer whitespace trimming */
    while (len < origlen && isspace(*(end-1))) {
        end--;
        len++;
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
    long value = 0;
    const char *q  = pdf_getdict(q0, &len, key);

    if (q == NULL) {
        value = -1;
    }
    else if (CL_SUCCESS != cli_strntol_wrap(q, (size_t)len, 0, 10, &value)) {
        value = -1;
    }
    return value;
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

    cli_dbgmsg("pdf_readbool: invalid value for %s bool\n", key);

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

    UNUSEDPARAM(oulen);

    dbg_printhex("U: ", U, 32);
    dbg_printhex("O: ", O, 32);
    if (R == 5) {
        uint8_t result2[32];

        /* supplement to ISO3200, 3.5.2 Algorithm 3.11 */
        /* user validation salt */
        cl_sha256(U+32, 8, result2, NULL);
        dbg_printhex("Computed U", (const char *)result2, 32);
        if (!memcmp(result2, U, 32)) {
            size_t UE_len;

            /* Algorithm 3.2a could be used to recover encryption key */
            password_empty = 1;
            cl_sha256(U+40, 8, result2, NULL);
            UE_len = UE ? strlen(UE) : 0;
            if (UE_len != 32) {
                cli_dbgmsg("check_user_password: UE length is not 32: %zu\n", UE_len);
                noisy_warnmsg("check_user_password: UE length is not 32: %zu\n", UE_len);
            } else {
                pdf->keylen = 32;
                pdf->key = cli_malloc(32);
                if (!pdf->key) {
                    cli_errmsg("check_user_password: Cannot allocate memory for pdf->key\n");
                    return;
                }

                aes_decrypt((const unsigned char *)UE, &UE_len, (unsigned char *)(pdf->key), (char *)result2, 32, 0);
                dbg_printhex("check_user_password: Candidate encryption key", pdf->key, pdf->keylen);
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
        dbg_printhex("md5", (const char *)result, 16);
        dbg_printhex("Candidate encryption key", pdf->key, pdf->keylen);

        /* 7.6.3.3 Algorithm 6 */
        if (R == 2) {
            /* 7.6.3.3 Algorithm 4 */
            memcpy(data, key_padding, 32);
            arc4_init(&arc4, (const uint8_t *)(pdf->key), pdf->keylen);
            arc4_apply(&arc4, (uint8_t *)data, 32);
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

            arc4_init(&arc4, (const uint8_t *)data, len);
            arc4_apply(&arc4, result, 16);
            for (i=1;i<=19;i++) {
                unsigned j;

                for (j=0;j<len;j++)
                    data[j] = pdf->key[j] ^ i;

                arc4_init(&arc4, (const uint8_t *)data, len);
                arc4_apply(&arc4, result, 16);
            }

            dbg_printhex("fileID", pdf->fileID, pdf->fileIDlen);
            dbg_printhex("computed U (R>=3)", (const char *)result, 16);
            if (!memcmp(result, U, 16))
                password_empty = 1;
            free(d);
        } else {
            cli_dbgmsg("check_user_password: invalid revision %d\n", R);
            noisy_warnmsg("check_user_password: invalid revision %d\n", R);
        }
    } else {
        /* Supported R is in {2,3,4,5} */
        cli_dbgmsg("check_user_password: R value out of range\n");
        noisy_warnmsg("check_user_password: R value out of range\n");

        return;
    }

    if (password_empty) {
        cli_dbgmsg("check_user_password: user password is empty\n");
        noisy_msg(pdf, "check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt\n");
        /* The key we computed above is the key used to encrypt the streams.
         * We could decrypt it now if we wanted to */
        pdf->flags |= 1 << DECRYPTABLE_PDF;
    } else {
        /* the key is not valid, we would need the user or the owner password to decrypt */
        cli_dbgmsg("check_user_password: user/owner password would be required for decryption\n");
        noisy_warnmsg("check_user_password: encrypted PDF found, user password is NOT empty, cannot decrypt!\n");
    }
}

enum enc_method parse_enc_method(const char *dict, unsigned len, const char *key, enum enc_method def)
{
    const char *q;
    char *CFM = NULL;
    enum enc_method ret = ENC_UNKNOWN;

    if (!key)
        return def;

    if (!strcmp(key, "Identity"))
        return ENC_IDENTITY;

    q = pdf_getdict(dict, (int *)(&len), key);
    if (!q)
        return def;

    CFM = pdf_readval(q, len, "/CFM");
    if (CFM) {
        cli_dbgmsg("parse_enc_method: %s CFM: %s\n", key, CFM);
        if (!strncmp(CFM,"V2", 2))
            ret = ENC_V2;
        else if (!strncmp(CFM,"AESV2",5))
            ret = ENC_AESV2;
        else if (!strncmp(CFM,"AESV3",5))
            ret = ENC_AESV3;
        else if (!strncmp(CFM,"None",4))
            ret = ENC_NONE;

        free(CFM);
    }

    return ret;
}

void pdf_handle_enc(struct pdf_struct *pdf)
{
    struct pdf_obj *obj;
    uint32_t len, n, R, P, length, EM = 1, i, oulen;
    char *O, *U, *UE, *StmF, *StrF, *EFF;
    const char *q, *q2;

    if (pdf->enc_objid == ~0u)
        return;
    if (!pdf->fileID) {
        cli_dbgmsg("pdf_handle_enc: no file ID\n");
        noisy_warnmsg("pdf_handle_enc: no file ID\n");
        return;
    }

    obj = find_obj(pdf, pdf->objs[0], pdf->enc_objid);
    if (!obj) {
        cli_dbgmsg("pdf_handle_enc: can't find encrypted object %d %d\n", pdf->enc_objid>>8, pdf->enc_objid&0xff);
        noisy_warnmsg("pdf_handle_enc: can't find encrypted object %d %d\n", pdf->enc_objid>>8, pdf->enc_objid&0xff);
        return;
    }

    len = obj->size;
    q = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                      : (const char *)(obj->start + pdf->map);

    O = U = UE = StmF = StrF = EFF = NULL;
    do {

        pdf->enc_method_string = ENC_UNKNOWN;
        pdf->enc_method_stream = ENC_UNKNOWN;
        pdf->enc_method_embeddedfile = ENC_UNKNOWN;
        P = pdf_readint(q, len, "/P");
        if (P == ~0u) {
            cli_dbgmsg("pdf_handle_enc: invalid P\n");
            noisy_warnmsg("pdf_handle_enc: invalid P\n");
            break;
        }

        q2 = cli_memstr(q, len, "/Standard", 9);
        if (!q2) {
            cli_dbgmsg("pdf_handle_enc: /Standard not found\n");
            noisy_warnmsg("pdf_handle_enc: /Standard not found\n");
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
            cli_dbgmsg("pdf_handle_enc: invalid length: %d\n", length);
            length = 40;
        }

        R = pdf_readint(q, len, "/R");
        if (R == ~0u) {
            cli_dbgmsg("pdf_handle_enc: invalid R\n");
            noisy_warnmsg("pdf_handle_enc: invalid R\n");
            break;
        }

        if ((R > 5) || (R < 2)) {
            cli_dbgmsg("pdf_handle_enc: R value outside supported range [2..5]\n");
            noisy_warnmsg("pdf_handle_enc: R value outside supported range [2..5]\n");
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
            pdf->CF = pdf_getdict(q, (int *)(&n), "/CF");
            pdf->CF_n = n;

            if (StmF)
                cli_dbgmsg("pdf_handle_enc: StmF: %s\n", StmF);
            if (StrF)
                cli_dbgmsg("pdf_handle_enc: StrF: %s\n", StrF);
            if (EFF)
                cli_dbgmsg("pdf_handle_enc: EFF: %s\n", EFF);

            pdf->enc_method_stream = parse_enc_method(pdf->CF, n, StmF, ENC_IDENTITY);
            pdf->enc_method_string = parse_enc_method(pdf->CF, n, StrF, ENC_IDENTITY);
            pdf->enc_method_embeddedfile = parse_enc_method(pdf->CF, n, EFF, pdf->enc_method_stream);

            free(StmF);
            free(StrF);
            free(EFF);

            cli_dbgmsg("pdf_handle_enc: EncryptMetadata: %s\n", EM ? "true" : "false");

            if (R == 4) {
                length = 128;
            } else {
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
            cli_dbgmsg("pdf_handle_enc: invalid O: %d\n", n);
            cli_dbgmsg("pdf_handle_enc: invalid O: %d\n", n);
            if (O)
                dbg_printhex("invalid O", O, n);

            break;
        }
        if (n > oulen) {
            for (i=oulen;i<n;i++)
                if (O[i])
                    break;

            if (i != n) {
                dbg_printhex("pdf_handle_enc: too long O", O, n);
                noisy_warnmsg("pdf_handle_enc: too long O: %u", n);
                break;
            }
        }

        n = 0;
        U = pdf_readstring(q, len, "/U", &n, NULL, 0);
        if (!U || n < oulen) {
            cli_dbgmsg("pdf_handle_enc: invalid U: %u\n", n);
            noisy_warnmsg("pdf_handle_enc: invalid U: %u\n", n);

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

        cli_dbgmsg("pdf_handle_enc: Encrypt R: %d, P %x, length: %u\n", R, P, length);
        if (length % 8) {
            cli_dbgmsg("pdf_handle_enc: wrong key length, not multiple of 8\n");
            noisy_warnmsg("pdf_handle_enc: wrong key length, not multiple of 8\n");
            break;
        }
        check_user_password(pdf, R, O, U, P, EM, UE, length, oulen);
    } while (0);

    free(O);
    free(U);
    free(UE);
}

/**
 * @brief Search pdf buffer for objects.  Parse each.
 *
 * Newly found objects will be extracted after completion when the extraction for loop continues.
 *
 * @param pdf           Pdf struct that keeps track of all information found in the PDF.
 * @param objstm        Pointer to an object stream to parse.
 *
 * @return cl_error_t   Error code.
 */
cl_error_t pdf_find_and_parse_objs_in_objstm(struct pdf_struct *pdf, struct objstm_struct *objstm)
{
    cl_error_t status = CL_EFORMAT;
    cl_error_t retval = CL_EPARSE;
    int32_t alerts = 0;
    uint32_t badobjects = 0;
    size_t i = 0;

    struct pdf_obj* obj = NULL;

    if ((NULL == objstm) || (NULL == objstm->streambuf)) {
        status = CL_EARG;
        goto done;
    }

    if ((0 == objstm->first) ||
        (0 == objstm->streambuf_len) ||
        (0 == objstm->n))
    {
        cli_dbgmsg("pdf_find_and_parse_objs_in_objstm: Empty object stream.\n");
        goto done;
    }

    if (objstm->first >= objstm->streambuf_len)
    {
        cli_dbgmsg("pdf_find_and_parse_objs_in_objstm: Invalid objstm values. Offset of first obj greater than stream length.\n");
        goto done;
    }

    /* Process each object */
    for (i = 0; i < objstm->n; i++)
    {
        obj = NULL;

        if (cli_checktimelimit(pdf->ctx) != CL_SUCCESS) {
            cli_errmsg("Timeout reached in the PDF parser while parsing object stream.\n");
            status = CL_ETIMEOUT;
            goto done;
        }

        /* Find object */
        retval = pdf_findobj_in_objstm(pdf, objstm, &obj);

        if (retval != CL_SUCCESS)
        {
            cli_dbgmsg("pdf_find_and_parse_objs_in_objstm: Fewer objects in stream than expected: %u found, %u expected.\n",
                objstm->nobjs_found, objstm->n);
            badobjects++;
            pdf->stats.ninvalidobjs++;
            break;
        }

        cli_dbgmsg("pdf_find_and_parse_objs_in_objstm: Found object %u %u in object stream at offset: %u\n", obj->id >> 8, obj->id & 0xff, obj->start);

        if (cli_checktimelimit(pdf->ctx) != CL_SUCCESS) {
            cli_errmsg("Timeout reached in the PDF parser while parsing object stream.\n");
            status = CL_ETIMEOUT;
            goto done;
        }

        /* Parse object */
        pdf_parseobj(pdf, obj);
    }

    if (alerts) {
        status = CL_VIRUS;
        goto done;
    }
    else if (badobjects) {
        status = CL_EFORMAT;
        goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Search pdf buffer for objects.  Parse each and then extract each.
 *
 * @param pdf               Pdf struct that keeps track of all information found in the PDF.
 * @param alerts[in/out]    The number of alerts, relevant in ALLMATCH mode.
 *
 * @return cl_error_t   Error code.
 */
cl_error_t pdf_find_and_extract_objs(struct pdf_struct *pdf, uint32_t *alerts)
{
    cl_error_t status = CL_SUCCESS;
    int32_t rv = 0;
    unsigned int i = 0;
    uint32_t badobjects = 0;
    cli_ctx *ctx = pdf->ctx;

    /* parse PDF and find obj offsets */
    while (CL_BREAK != (rv = pdf_findobj(pdf))) {
        if (rv == CL_EMEM) {
            break;
        }
    }

    if (rv == -1)
        pdf->flags |= 1 << BAD_PDF_TOOMANYOBJS;

    /* must parse after finding all objs, so we can flag indirect objects */
    for (i=0; i < pdf->nobjs; i++) {
        struct pdf_obj *obj = pdf->objs[i];

        if (cli_checktimelimit(pdf->ctx) != CL_SUCCESS) {
            cli_errmsg("pdf_find_and_extract_objs: Timeout reached in the PDF parser while parsing objects.\n");

            status = CL_ETIMEOUT;
            goto done;
        }

        pdf_parseobj(pdf, obj);
    }

    pdf_handle_enc(pdf);
    if (pdf->flags & (1 << ENCRYPTED_PDF))
        cli_dbgmsg("pdf_find_and_extract_objs: encrypted pdf found, %s!\n",
               (pdf->flags & (1 << DECRYPTABLE_PDF)) ?
               "decryptable" : "not decryptable, stream will probably fail to decompress");

    if (SCAN_HEURISTIC_ENCRYPTED_DOC &&
       (pdf->flags & (1 << ENCRYPTED_PDF)) &&
       !(pdf->flags & (1 << DECRYPTABLE_PDF)))
    {
        /* It is encrypted, and a password/key needs to be supplied to decrypt.
         * This doesn't trigger for PDFs that are encrypted but don't need
         * a password to decrypt */
        status = cli_append_virus(pdf->ctx, "Heuristics.Encrypted.PDF");
        if (status == CL_VIRUS) {
            alerts++;
            if (SCAN_ALLMATCHES)
                status = CL_CLEAN;
        }
    }

    if (!status) {
        status = run_pdf_hooks(pdf, PDF_PHASE_PARSED, -1, -1);
        cli_dbgmsg("pdf_find_and_extract_objs: (parsed hooks) returned %d\n", status);
        if (status == CL_VIRUS) {
            alerts++;
            if (SCAN_ALLMATCHES) {
                status = CL_CLEAN;
            }
        }
    }

    /* extract PDF objs */
    for (i=0; !status && i < pdf->nobjs; i++) {
        struct pdf_obj *obj = pdf->objs[i];

        if (cli_checktimelimit(pdf->ctx) != CL_SUCCESS) {
            cli_errmsg("pdf_find_and_extract_objs: Timeout reached in the PDF parser while extracting objects.\n");

            status = CL_ETIMEOUT;
            goto done;
        }

        status = pdf_extract_obj(pdf, obj, PDF_EXTRACT_OBJ_SCAN);
        switch (status) {
            case CL_EFORMAT:
                /* Don't halt on one bad object */
                cli_dbgmsg("pdf_find_and_extract_objs: Format error when extracting object, skipping to the next object.\n");
                badobjects++;
                pdf->stats.ninvalidobjs++;
                status = CL_CLEAN;
                break;
            case CL_VIRUS:
                alerts++;
                if (SCAN_ALLMATCHES) {
                    status = CL_CLEAN;
                }
                break;
            default:
                break;
        }
    }

done:
    if (!status && badobjects) {
        status = CL_EFORMAT;
    }

    return status;
}

/**
 * @brief Primary function for parsing and scanning a PDF.
 *
 * @param dir       Filepath for temp file.
 * @param ctx       clam scan context structure.
 * @param offset    offset of pdf in ctx->fmap
 *
 * @return int      Returns cl_error_t status value.
 */
int cli_pdf(const char *dir, cli_ctx *ctx, off_t offset)
{
    cl_error_t rc = CL_SUCCESS;
    struct pdf_struct pdf;
    fmap_t *map = *ctx->fmap;
    size_t size = map->len - offset;
    off_t versize = size > 1032 ? 1032 : size;
    off_t map_off, bytesleft;
    unsigned long xref;
    long temp_long;
    const char *pdfver, *tmp, *start, *eofmap, *q, *eof;
    unsigned i, alerts = 0;
    unsigned int objs_found = 0;
#if HAVE_JSON
    json_object *pdfobj=NULL;
    char *begin, *end, *p1;
#endif

    cli_dbgmsg("in cli_pdf(%s)\n", dir);
    memset(&pdf, 0, sizeof(pdf));
    pdf.ctx = ctx;
    pdf.dir = dir;
    pdf.enc_objid = ~0u;

    pdfver = start = fmap_need_off_once(map, offset, versize);

    /* Check PDF version */
    if (!pdfver) {
        cli_errmsg("cli_pdf: mmap() failed (1)\n");
        rc = CL_EMAP;
        goto done;
    }

#if HAVE_JSON
    if (ctx->wrkproperty)
        pdfobj = cli_jsonobj(ctx->wrkproperty, "PDFStats");
#endif

    /* offset is 0 when coming from filetype2 */
    tmp = cli_memstr(pdfver, versize, "%PDF-", 5);
    if (!tmp) {
        cli_dbgmsg("cli_pdf: no PDF- header found\n");
        noisy_warnmsg("cli_pdf: no PDF- header found\n");
#if HAVE_JSON
        pdf_export_json(&pdf);
#endif
        rc = CL_SUCCESS;
        goto done;
    }

    versize -= tmp - pdfver;
    pdfver = tmp;

    if (versize < 8) {
        rc = CL_EFORMAT;
        goto done;
    }

    /* Check for PDF-1.[0-9]. Although 1.7 is highest now, allow for future versions */
    if (pdfver[5] != '1' || pdfver[6] != '.' ||
        pdfver[7] < '1' || pdfver[7] > '9') {
        pdf.flags |= 1 << BAD_PDF_VERSION;
        cli_dbgmsg("cli_pdf: bad pdf version: %.8s\n", pdfver);
#if HAVE_JSON
        if (pdfobj)
            cli_jsonbool(pdfobj, "BadVersion", 1);
#endif
    } else {
#if HAVE_JSON
        if (pdfobj) {
            begin = (char *)(pdfver+5);
            end = begin+2;
            strtoul(end, &end, 10);
            p1 = cli_calloc((end - begin) + 2, 1);
            if (p1) {
                strncpy(p1, begin, end - begin);
                p1[end - begin] = '\0';
                cli_jsonstr(pdfobj, "PDFVersion", p1);
                free(p1);
            }
        }
#endif
    }

    if (pdfver != start || offset) {
        pdf.flags |= 1 << BAD_PDF_HEADERPOS;
        cli_dbgmsg("cli_pdf: PDF header is not at position 0: %lld\n", (long long)(pdfver - start + offset));
#if HAVE_JSON
        if (pdfobj)
            cli_jsonbool(pdfobj, "BadVersionLocation", 1);
#endif
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

        rc = CL_EMAP;
        goto done;
    }

    eof = eofmap + bytesleft;
    for (q=&eofmap[bytesleft-5]; q > eofmap; q--) {
        if (memcmp(q, "%%EOF", 5) == 0)
            break;
    }

    if (q <= eofmap) {
        pdf.flags |= 1 << BAD_PDF_TRAILER;
        cli_dbgmsg("cli_pdf: %%%%EOF not found\n");
#if HAVE_JSON
        if (pdfobj)
            cli_jsonbool(pdfobj, "NoEOF", 1);
#endif
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
#if HAVE_JSON
            if (pdfobj)
                cli_jsonbool(pdfobj, "NoXREF", 1);
#endif
        } else {
            for (t=q;t > eofmap; t--) {
                if (memcmp(t,"trailer",7) == 0)
                    break;
            }

            pdf_parse_trailer(&pdf, eofmap, eof - eofmap);
            q += 9;

            while (q < eof && (*q == ' ' || *q == '\n' || *q == '\r')) { q++; }

            if (CL_SUCCESS != cli_strntol_wrap(q, q - eofmap + map_off, 0, 10, &temp_long)) {
                cli_dbgmsg("cli_pdf: failed to parse PDF trailer xref\n");
                pdf.flags |= 1 << BAD_PDF_TRAILER;
            } else if (temp_long < 0) {
                cli_dbgmsg("cli_pdf: Encountered invalid negative PDF trailer xref (%ld).\n", temp_long);
                pdf.flags |= 1 << BAD_PDF_TRAILER;
            } else {
                xref      = (unsigned long)temp_long;
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
    }

    size -= offset;
    pdf.size = size;
    pdf.map = fmap_need_off(map, offset, size);
    if (!pdf.map) {
        cli_errmsg("cli_pdf: mmap() failed (3)\n");

        rc = CL_EMAP;
        goto done;
    }

    pdf.startoff = offset;

    rc = run_pdf_hooks(&pdf, PDF_PHASE_PRE, -1, -1);
    if ((rc == CL_VIRUS) && SCAN_ALLMATCHES) {
        cli_dbgmsg("cli_pdf: (pre hooks) returned %d\n", rc);
        alerts++;
        rc = CL_CLEAN;
    } else if (rc) {
        cli_dbgmsg("cli_pdf: (pre hooks) returning %d\n", rc);

        rc = rc == CL_BREAK ? CL_CLEAN : rc;
        goto done;
    }

    /*
     * Find and extract all objects in the PDF.
     * New experimental recursive methodology that adds objects from object streams.
     */
    objs_found = pdf.nobjs;
    rc = pdf_find_and_extract_objs(&pdf, &alerts);

    if (pdf.nobjs <= objs_found) {
        cli_dbgmsg("cli_pdf: pdf_find_and_extract_objs did not find any new objects!\n");
    } else {
        cli_dbgmsg("cli_pdf: pdf_find_and_extract_objs found %d new objects.\n", pdf.nobjs - objs_found);
    }

    if (pdf.flags & (1 << ENCRYPTED_PDF))
        pdf.flags &= ~ ((1 << BAD_FLATESTART) | (1 << BAD_STREAMSTART) | (1 << BAD_ASCIIDECODE));

    if (pdf.flags && !rc) {
        cli_dbgmsg("cli_pdf: flags 0x%02x\n", pdf.flags);
        rc = run_pdf_hooks(&pdf, PDF_PHASE_END, -1, -1);
        if (rc == CL_VIRUS) {
            alerts++;
            if (SCAN_ALLMATCHES) {
                rc = CL_CLEAN;
            }
        }

        if (!rc && SCAN_HEURISTICS && (ctx->dconf->other & OTHER_CONF_PDFNAMEOBJ)) {
            if (pdf.flags & (1 << ESCAPED_COMMON_PDFNAME)) {
                /* for example /Fl#61te#44#65#63#6f#64#65 instead of /FlateDecode */
                cli_append_possibly_unwanted(ctx, "Heuristics.PDF.ObfuscatedNameObject");
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

done:
    if (alerts) {
        rc = CL_VIRUS;
    }
    else if (!rc && pdf.stats.ninvalidobjs > 0) {
        rc = CL_EFORMAT;
    }

#if HAVE_JSON
    pdf_export_json(&pdf);
#endif

    if (pdf.objstms) {
        for (i = 0; i < pdf.nobjstms; i++) {
            if (pdf.objstms[i]) {
                if (pdf.objstms[i]->streambuf) {
                    free(pdf.objstms[i]->streambuf);
                    pdf.objstms[i]->streambuf = NULL;
                }
                free(pdf.objstms[i]);
                pdf.objstms[i] = NULL;
            }
        }
        free(pdf.objstms);
        pdf.objstms = NULL;
    }

    if (NULL != pdf.objs) {
        for (i = 0; i < pdf.nobjs; i++) {
            if (NULL != pdf.objs[i]) {
                free(pdf.objs[i]);
                pdf.objs[i] = NULL;
            }
        }
        free(pdf.objs);
        pdf.objs = NULL;
    }
    if (pdf.fileID) {
        free(pdf.fileID);
        pdf.fileID = NULL;
    }
    if (pdf.key) {
        free(pdf.key);
        pdf.key = NULL;
    }

    /* PDF hooks may abort, don't return CL_BREAK to caller! */
    rc = (rc == CL_BREAK) ? CL_CLEAN : rc;

    cli_dbgmsg("cli_pdf: returning %d\n", rc);
    return rc;
}

/**
 * @brief   Skip the rest of the current line, and find the start of the next line.
 *
 * @param ptr   Current offset into buffer.
 * @param len   Remaining bytes in buffer.
 *
 * @return const char*  Address of next line, or NULL if no next line in buffer.
 */
static const char *
pdf_nextlinestart(const char *ptr, size_t len)
{
    if (!ptr || (0 == len)) {
        /* Invalid args */
        return NULL;
    }

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

/**
 * @brief   Return the start of the next PDF object.
 *
 * This assumes that we're not in a stream.
 *
 * @param ptr   Current offset into buffer.
 * @param len   Remaining bytes in buffer.
 *
 * @return const char*  Address of next object in the buffer, or NULL if there is none in the buffer.
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
        case '%':   /* comment */
            p = pdf_nextlinestart(ptr, len);
            if(p == NULL)
                return NULL;

            len -= (size_t)(p - ptr);
            ptr = p;
            inobject = 0;

            break;
        case ' ':
        case '\t':
        case '[':   /* Start of an array object */
        case '\v':
        case '\f':
        case '<':   /* Start of a dictionary object */
            inobject = 0;
            ptr++;
            len--;

            break;
        case '/':   /* Start of a name object */
            return ptr;
        case '(': /* start of JS */
            return ptr;
        default:
            if(!inobject) {
                /* TODO: parse and return object type */
                return ptr;
            }

            ptr++;
            len--;
        }
    }

    return NULL;
}

/* PDF statistics */
#if HAVE_JSON
static void ASCIIHexDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nasciihexdecode++;
}
#endif

#if HAVE_JSON
static void ASCII85Decode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nascii85decode++;
}
#endif

#if HAVE_JSON
static void EmbeddedFile_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nembeddedfile++;
}
#endif

#if HAVE_JSON
static void FlateDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nflate++;
}
#endif

#if HAVE_JSON
static void Image_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nimage++;
}
#endif

#if HAVE_JSON
static void LZWDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nlzw++;
}
#endif

#if HAVE_JSON
static void RunLengthDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nrunlengthdecode++;
}
#endif

#if HAVE_JSON
static void CCITTFaxDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nfaxdecode++;
}
#endif

#if HAVE_JSON
static void JBIG2Decode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;
    struct json_object *pdfobj, *jbig2arr;

    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->ctx->wrkproperty))
        return;

    pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
    if (!(pdfobj))
        return;

    jbig2arr = cli_jsonarray(pdfobj, "JBIG2Objects");
    if (!(jbig2arr))
        return;

    cli_jsonint_array(jbig2arr, obj->id>>8);

    pdf->stats.njbig2decode++;
}
#endif

#if HAVE_JSON
static void DCTDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.ndctdecode++;
}
#endif

#if HAVE_JSON
static void JPXDecode_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.njpxdecode++;
}
#endif

#if HAVE_JSON
static void Crypt_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.ncrypt++;
}
#endif

#if HAVE_JSON
static void Standard_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nstandard++;
}
#endif

#if HAVE_JSON
static void Sig_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nsigned++;
}
#endif

#if HAVE_JSON
static void JavaScript_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;
    struct json_object *pdfobj, *jbig2arr;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->ctx->wrkproperty))
        return;

    pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
    if (!(pdfobj))
        return;

    jbig2arr = cli_jsonarray(pdfobj, "JavascriptObjects");
    if (!(jbig2arr))
        return;

    cli_jsonint_array(jbig2arr, obj->id>>8);

    pdf->stats.njs++;
}
#endif

#if HAVE_JSON
static void OpenAction_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nopenaction++;
}
#endif

#if HAVE_JSON
static void Launch_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nlaunch++;
}
#endif

#if HAVE_JSON
static void Page_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.npage++;
}
#endif

#if HAVE_JSON
static void Author_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.author)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.author = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.author))
            return;
        pdf->stats.author->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/Author", NULL, &(pdf->stats.author->meta));
    }
}
#endif

#if HAVE_JSON
static void Creator_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.creator)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.creator = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.creator))
            return;
        pdf->stats.creator->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/Creator", NULL, &(pdf->stats.creator->meta));
    }
}
#endif

#if HAVE_JSON
static void ModificationDate_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.modificationdate)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.modificationdate = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.modificationdate))
            return;
        pdf->stats.modificationdate->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/ModDate", NULL, &(pdf->stats.modificationdate->meta));
    }
}
#endif

#if HAVE_JSON
static void CreationDate_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.creationdate)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.creationdate = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.creationdate))
            return;
        pdf->stats.creationdate->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/CreationDate", NULL, &(pdf->stats.creationdate->meta));
    }
}
#endif

#if HAVE_JSON
static void Producer_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.producer)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.producer = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.producer))
            return;
        pdf->stats.producer->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/Producer", NULL, &(pdf->stats.producer->meta));
    }
}
#endif

#if HAVE_JSON
static void Title_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.title)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.title = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.title))
            return;
        pdf->stats.title->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/Title", NULL, &(pdf->stats.title->meta));
    }
}
#endif

#if HAVE_JSON
static void Keywords_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.keywords)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.keywords = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.keywords))
            return;
        pdf->stats.keywords->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/Keywords", NULL, &(pdf->stats.keywords->meta));
    }
}
#endif

#if HAVE_JSON
static void Subject_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;

    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    if (!(pdf->stats.subject)) {
        const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                             : (const char *)(obj->start + pdf->map);

        pdf->stats.subject = cli_calloc(1, sizeof(struct pdf_stats_entry));
        if (!(pdf->stats.subject))
            return;
        pdf->stats.subject->data = pdf_parse_string(pdf, obj, objstart, obj->size, "/Subject", NULL, &(pdf->stats.subject->meta));
    }
}
#endif

#if HAVE_JSON
static void RichMedia_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nrichmedia++;
}
#endif

#if HAVE_JSON
static void AcroForm_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nacroform++;
}
#endif

#if HAVE_JSON
static void XFA_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    UNUSEDPARAM(obj);
    UNUSEDPARAM(act);

    if (!(pdf))
        return;

    pdf->stats.nxfa++;
}
#endif

#if HAVE_JSON
static void Pages_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;
    struct pdf_array *array;
    const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                         : (const char *)(obj->start + pdf->map);
    const char *begin;
    unsigned long npages=0, count;
    long temp_long;
    struct pdf_array_node *node;
    json_object *pdfobj;
    size_t countsize = 0;

    UNUSEDPARAM(act);

    if (!(pdf) || !(pdf->ctx->wrkproperty))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
    if (!(pdfobj))
        return;

    begin = cli_memstr(objstart, obj->size, "/Kids", 5);
    if (!(begin))
        return;

    begin += 5;

    array = pdf_parse_array(pdf, obj, obj->size, (char *)begin, NULL);
    if (!(array)) {
        cli_jsonbool(pdfobj, "IncorrectPagesCount", 1);
        return;
    }

    for (node = array->nodes; node != NULL; node = node->next)
        if (node->datasz)
            if (strchr((char *)(node->data), 'R'))
                npages++;

    begin = cli_memstr(objstart, obj->size, "/Count", 6);
    if (!(begin)) {
        cli_jsonbool(pdfobj, "IncorrectPagesCount", 1);
        goto cleanup;
    }

    begin += 6;
    while (((size_t)(begin - objstart) < obj->size) && isspace(begin[0]))
        begin++;

    if ((size_t)(begin - objstart) >= obj->size) {
        goto cleanup;
    }

    countsize = (obj->objstm) ? (size_t)(obj->start + obj->objstm->streambuf + obj->size - begin)
                              : (size_t)(obj->start + pdf->map + obj->size - begin);

    if (CL_SUCCESS != cli_strntol_wrap(begin, countsize, 0, 10, &temp_long)) {
        cli_jsonbool(pdfobj, "IncorrectPagesCount", 1);
    } else if (temp_long < 0) {
        cli_jsonbool(pdfobj, "IncorrectPagesCount", 1);
    } else {
        count = (unsigned long)temp_long;
        if (count != npages) {
        cli_jsonbool(pdfobj, "IncorrectPagesCount", 1);
    }
    }

cleanup:
    pdf_free_array(array);
}
#endif

#if HAVE_JSON
static void Colors_cb(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdfname_action *act)
{
    cli_ctx *ctx = pdf->ctx;
    json_object *colorsobj, *pdfobj;
    unsigned long ncolors;
    long temp_long;
    char *p1;
    const char *objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                                         : (const char *)(obj->start + pdf->map);

    UNUSEDPARAM(act);

    if (!(pdf) || !(pdf->ctx) || !(pdf->ctx->wrkproperty))
        return;

    if (!(SCAN_COLLECT_METADATA))
        return;

    p1 = (char *)cli_memstr(objstart, obj->size, "/Colors", 7);
    if (!(p1))
        return;

    p1 += 7;

    /* Ensure that we have at least one whitespace character plus at least one number */
    if (obj->size - (size_t)(p1 - objstart) < 2)
        return;

    while (((size_t)(p1 - objstart) < obj->size) && isspace(p1[0]))
        p1++;

    if ((size_t)(p1 - objstart) == obj->size)
        return;

    if (CL_SUCCESS != cli_strntol_wrap(p1, (size_t)((p1 - objstart) - obj->size), 0, 10, &temp_long)) {
        return;
    } else if (temp_long < 0) {
        return;
    }
    ncolors = (unsigned long)temp_long;

    /* We only care if the number of colors > 2**24 */
    if (ncolors < 1<<24)
        return;

    pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
    if (!(pdfobj))
        return;

    colorsobj = cli_jsonarray(pdfobj, "BigColors");
    if (!(colorsobj))
        return;

    cli_jsonint_array(colorsobj, obj->id>>8);
}
#endif

#if HAVE_JSON
static void pdf_export_json(struct pdf_struct *pdf)
{
    cli_ctx *ctx = pdf->ctx;
    json_object *pdfobj;
    unsigned long i;

    if (!(pdf))
        return;

    if (!(pdf->ctx)) {
        goto cleanup;
    }

    if (!(SCAN_COLLECT_METADATA) || !(pdf->ctx->wrkproperty)) {
        goto cleanup;
    }

    pdfobj = cli_jsonobj(pdf->ctx->wrkproperty, "PDFStats");
    if (!(pdfobj)) {
        goto cleanup;
    }

    if (pdf->stats.author) {
        if (!pdf->stats.author->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.author->meta.obj, pdf->stats.author->data, pdf->stats.author->meta.length);
            if (out) {
                free(pdf->stats.author->data);
                pdf->stats.author->data = out;
                pdf->stats.author->meta.length = strlen(out);
                pdf->stats.author->meta.success = 1;
            }
        }

        if (pdf->stats.author->meta.success && cli_isutf8(pdf->stats.author->data, pdf->stats.author->meta.length)) {
            cli_jsonstr(pdfobj, "Author", pdf->stats.author->data);
        } else if (pdf->stats.author->data && pdf->stats.author->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.author->data, pdf->stats.author->meta.length);
            cli_jsonstr(pdfobj, "Author", b64);
            cli_jsonbool(pdfobj, "Author_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "Author", "");
        }
    }
    if (pdf->stats.creator) {
        if (!pdf->stats.creator->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.creator->meta.obj, pdf->stats.creator->data, pdf->stats.creator->meta.length);
            if (out) {
                free(pdf->stats.creator->data);
                pdf->stats.creator->data = out;
                pdf->stats.creator->meta.length = strlen(out);
                pdf->stats.creator->meta.success = 1;
            }
        }

        if (pdf->stats.creator->meta.success && cli_isutf8(pdf->stats.creator->data, pdf->stats.creator->meta.length)) {
            cli_jsonstr(pdfobj, "Creator", pdf->stats.creator->data);
        } else if (pdf->stats.creator->data && pdf->stats.creator->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.creator->data, pdf->stats.creator->meta.length);
            cli_jsonstr(pdfobj, "Creator", b64);
            cli_jsonbool(pdfobj, "Creator_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "Creator", "");
        }
    }
    if (pdf->stats.producer) {
        if (!pdf->stats.producer->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.producer->meta.obj, pdf->stats.producer->data, pdf->stats.producer->meta.length);
            if (out) {
                free(pdf->stats.producer->data);
                pdf->stats.producer->data = out;
                pdf->stats.producer->meta.length = strlen(out);
                pdf->stats.producer->meta.success = 1;
            }
        }

        if (pdf->stats.producer->meta.success && cli_isutf8(pdf->stats.producer->data, pdf->stats.producer->meta.length)) {
            cli_jsonstr(pdfobj, "Producer", pdf->stats.producer->data);
        } else if (pdf->stats.producer->data && pdf->stats.producer->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.producer->data, pdf->stats.producer->meta.length);
            cli_jsonstr(pdfobj, "Producer", b64);
            cli_jsonbool(pdfobj, "Producer_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "Producer", "");
        }
    }
    if (pdf->stats.modificationdate) {
        if (!pdf->stats.modificationdate->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.modificationdate->meta.obj, pdf->stats.modificationdate->data, pdf->stats.modificationdate->meta.length);
            if (out) {
                free(pdf->stats.modificationdate->data);
                pdf->stats.modificationdate->data = out;
                pdf->stats.modificationdate->meta.length = strlen(out);
                pdf->stats.modificationdate->meta.success = 1;
            }
        }

        if (pdf->stats.modificationdate->meta.success && cli_isutf8(pdf->stats.modificationdate->data, pdf->stats.modificationdate->meta.length)) {
            cli_jsonstr(pdfobj, "ModificationDate", pdf->stats.modificationdate->data);
        } else if (pdf->stats.modificationdate->data && pdf->stats.modificationdate->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.modificationdate->data, pdf->stats.modificationdate->meta.length);
            cli_jsonstr(pdfobj, "ModificationDate", b64);
            cli_jsonbool(pdfobj, "ModificationDate_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "ModificationDate", "");
        }
    }
    if (pdf->stats.creationdate) {
        if (!pdf->stats.creationdate->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.creationdate->meta.obj, pdf->stats.creationdate->data, pdf->stats.creationdate->meta.length);
            if (out) {
                free(pdf->stats.creationdate->data);
                pdf->stats.creationdate->data = out;
                pdf->stats.creationdate->meta.length = strlen(out);
                pdf->stats.creationdate->meta.success = 1;
            }
        }

        if (pdf->stats.creationdate->meta.success && cli_isutf8(pdf->stats.creationdate->data, pdf->stats.creationdate->meta.length)) {
            cli_jsonstr(pdfobj, "CreationDate", pdf->stats.creationdate->data);
        } else if (pdf->stats.creationdate->data && pdf->stats.creationdate->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.creationdate->data, pdf->stats.creationdate->meta.length);
            cli_jsonstr(pdfobj, "CreationDate", b64);
            cli_jsonbool(pdfobj, "CreationDate_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "CreationDate", "");
        }
    }
    if (pdf->stats.title) {
        if (!pdf->stats.title->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.title->meta.obj, pdf->stats.title->data, pdf->stats.title->meta.length);
            if (out) {
                free(pdf->stats.title->data);
                pdf->stats.title->data = out;
                pdf->stats.title->meta.length = strlen(out);
                pdf->stats.title->meta.success = 1;
            }
        }

        if (pdf->stats.title->meta.success && cli_isutf8(pdf->stats.title->data, pdf->stats.title->meta.length)) {
            cli_jsonstr(pdfobj, "Title", pdf->stats.title->data);
        } else if (pdf->stats.title->data && pdf->stats.title->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.title->data, pdf->stats.title->meta.length);
            cli_jsonstr(pdfobj, "Title", b64);
            cli_jsonbool(pdfobj, "Title_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "Title", "");
        }
    }
    if (pdf->stats.subject) {
        if (!pdf->stats.subject->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.subject->meta.obj, pdf->stats.subject->data, pdf->stats.subject->meta.length);
            if (out) {
                free(pdf->stats.subject->data);
                pdf->stats.subject->data = out;
                pdf->stats.subject->meta.length = strlen(out);
                pdf->stats.subject->meta.success = 1;
            }
        }

        if (pdf->stats.subject->meta.success && cli_isutf8(pdf->stats.subject->data, pdf->stats.subject->meta.length)) {
            cli_jsonstr(pdfobj, "Subject", pdf->stats.subject->data);
        } else if (pdf->stats.subject->data && pdf->stats.subject->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.subject->data, pdf->stats.subject->meta.length);
            cli_jsonstr(pdfobj, "Subject", b64);
            cli_jsonbool(pdfobj, "Subject_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "Subject", "");
        }
    }
    if (pdf->stats.keywords) {
        if (!pdf->stats.keywords->meta.success) {
            char *out = pdf_finalize_string(pdf, pdf->stats.keywords->meta.obj, pdf->stats.keywords->data, pdf->stats.keywords->meta.length);
            if (out) {
                free(pdf->stats.keywords->data);
                pdf->stats.keywords->data = out;
                pdf->stats.keywords->meta.length = strlen(out);
                pdf->stats.keywords->meta.success = 1;
            }
        }

        if (pdf->stats.keywords->meta.success && cli_isutf8(pdf->stats.keywords->data, pdf->stats.keywords->meta.length)) {
            cli_jsonstr(pdfobj, "Keywords", pdf->stats.keywords->data);
        } else if (pdf->stats.keywords->data && pdf->stats.keywords->meta.length) {
            char *b64 = cl_base64_encode(pdf->stats.keywords->data, pdf->stats.keywords->meta.length);
            cli_jsonstr(pdfobj, "Keywords", b64);
            cli_jsonbool(pdfobj, "Keywords_base64", 1);
            free(b64);
        } else {
            cli_jsonstr(pdfobj, "Keywords", "");
        }
    }
    if (pdf->stats.ninvalidobjs)
        cli_jsonint(pdfobj, "InvalidObjectCount", pdf->stats.ninvalidobjs);
    if (pdf->stats.njs)
        cli_jsonint(pdfobj, "JavaScriptObjectCount", pdf->stats.njs);
    if (pdf->stats.nflate)
        cli_jsonint(pdfobj, "DeflateObjectCount", pdf->stats.nflate);
    if (pdf->stats.nactivex)
        cli_jsonint(pdfobj, "ActiveXObjectCount", pdf->stats.nactivex);
    if (pdf->stats.nflash)
        cli_jsonint(pdfobj, "FlashObjectCount", pdf->stats.nflash);
    if (pdf->stats.ncolors)
        cli_jsonint(pdfobj, "ColorCount", pdf->stats.ncolors);
    if (pdf->stats.nasciihexdecode)
        cli_jsonint(pdfobj, "AsciiHexDecodeObjectCount", pdf->stats.nasciihexdecode);
    if (pdf->stats.nascii85decode)
        cli_jsonint(pdfobj, "Ascii85DecodeObjectCount", pdf->stats.nascii85decode);
    if (pdf->stats.nembeddedfile)
        cli_jsonint(pdfobj, "EmbeddedFileCount", pdf->stats.nembeddedfile);
    if (pdf->stats.nimage)
        cli_jsonint(pdfobj, "ImageCount", pdf->stats.nimage);
    if (pdf->stats.nlzw)
        cli_jsonint(pdfobj, "LZWCount", pdf->stats.nlzw);
    if (pdf->stats.nrunlengthdecode)
        cli_jsonint(pdfobj, "RunLengthDecodeCount", pdf->stats.nrunlengthdecode);
    if (pdf->stats.nfaxdecode)
        cli_jsonint(pdfobj, "FaxDecodeCount", pdf->stats.nfaxdecode);
    if (pdf->stats.njbig2decode)
        cli_jsonint(pdfobj, "JBIG2DecodeCount", pdf->stats.njbig2decode);
    if (pdf->stats.ndctdecode)
        cli_jsonint(pdfobj, "DCTDecodeCount", pdf->stats.ndctdecode);
    if (pdf->stats.njpxdecode)
        cli_jsonint(pdfobj, "JPXDecodeCount", pdf->stats.njpxdecode);
    if (pdf->stats.ncrypt)
        cli_jsonint(pdfobj, "CryptCount", pdf->stats.ncrypt);
    if (pdf->stats.nstandard)
        cli_jsonint(pdfobj, "StandardCount", pdf->stats.nstandard);
    if (pdf->stats.nsigned)
        cli_jsonint(pdfobj, "SignedCount", pdf->stats.nsigned);
    if (pdf->stats.nopenaction)
        cli_jsonint(pdfobj, "OpenActionCount", pdf->stats.nopenaction);
    if (pdf->stats.nlaunch)
        cli_jsonint(pdfobj, "LaunchCount", pdf->stats.nlaunch);
    if (pdf->stats.npage)
        cli_jsonint(pdfobj, "PageCount", pdf->stats.npage);
    if (pdf->stats.nrichmedia)
        cli_jsonint(pdfobj, "RichMediaCount", pdf->stats.nrichmedia);
    if (pdf->stats.nacroform)
        cli_jsonint(pdfobj, "AcroFormCount", pdf->stats.nacroform);
    if (pdf->stats.nxfa)
        cli_jsonint(pdfobj, "XFACount", pdf->stats.nxfa);
    if (pdf->flags & (1 << BAD_PDF_VERSION))
        cli_jsonbool(pdfobj, "BadVersion", 1);
    if (pdf->flags & (1 << BAD_PDF_HEADERPOS))
        cli_jsonbool(pdfobj, "BadHeaderPosition", 1);
    if (pdf->flags & (1 << BAD_PDF_TRAILER))
        cli_jsonbool(pdfobj, "BadTrailer", 1);
    if (pdf->flags & (1 << BAD_PDF_TOOMANYOBJS))
        cli_jsonbool(pdfobj, "TooManyObjects", 1);
    if (pdf->flags & (1 << ENCRYPTED_PDF)) {
        cli_jsonbool(pdfobj, "Encrypted", 1);
        if (pdf->flags & (1 << DECRYPTABLE_PDF))
            cli_jsonbool(pdfobj, "Decryptable", 1);
        else
            cli_jsonbool(pdfobj, "Decryptable", 0);
    }

    for (i=0; i < pdf->nobjs; i++) {
        if (pdf->objs[i]->flags & (1<<OBJ_TRUNCATED)) {
            json_object *truncobj;

            truncobj = cli_jsonarray(pdfobj, "TruncatedObjects");
            if (!(truncobj))
                continue;

            cli_jsonint_array(truncobj, pdf->objs[i]->id >> 8);
        }
    }

cleanup:
    if ((pdf->stats.author)) {
        if (pdf->stats.author->data)
            free(pdf->stats.author->data);
        free(pdf->stats.author);
        pdf->stats.author = NULL;
    }

    if (pdf->stats.creator) {
        if (pdf->stats.creator->data)
            free(pdf->stats.creator->data);
        free(pdf->stats.creator);
        pdf->stats.creator = NULL;
    }

    if (pdf->stats.producer) {
        if (pdf->stats.producer->data)
            free(pdf->stats.producer->data);
        free(pdf->stats.producer);
        pdf->stats.producer = NULL;
    }

    if (pdf->stats.modificationdate) {
        if (pdf->stats.modificationdate->data)
            free(pdf->stats.modificationdate->data);
        free(pdf->stats.modificationdate);
        pdf->stats.modificationdate = NULL;
    }

    if (pdf->stats.creationdate) {
        if (pdf->stats.creationdate->data)
            free(pdf->stats.creationdate->data);
        free(pdf->stats.creationdate);
        pdf->stats.creationdate = NULL;
    }

    if (pdf->stats.title) {
        if (pdf->stats.title->data)
            free(pdf->stats.title->data);
        free(pdf->stats.title);
        pdf->stats.title = NULL;
    }

    if (pdf->stats.subject) {
        if (pdf->stats.subject->data)
            free(pdf->stats.subject->data);
        free(pdf->stats.subject);
        pdf->stats.subject = NULL;
    }

    if (pdf->stats.keywords) {
        if (pdf->stats.keywords->data)
            free(pdf->stats.keywords->data);
        free(pdf->stats.keywords);
        pdf->stats.keywords = NULL;
    }
}
#endif
