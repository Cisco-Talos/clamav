/*
 * Extract component parts of OLE2 files (e.g. MS Office Documents)
 * 
 * Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Copyright (C) 2007-2013 Sourcefire, Inc.
 * 
 * Authors: Kevin Lin
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <conv.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav.h"
#include "others.h"
#include "msdoc.h"
#include "scanners.h"
#include "fmap.h"
#include "json_api.h"

#if HAVE_JSON
static char *
ole2_convert_utf(summary_ctx_t *sctx, char *begin, size_t sz, const char *encoding)
{
    char *outbuf=NULL;
#if HAVE_ICONV
    char *buf, *p1, *p2;
    off_t offset;
    size_t inlen, outlen, nonrev, sz2;
    int i, try;
    iconv_t cd;
#endif
    /* applies in the both case */
    if (sctx->codepage == 20127 || sctx->codepage == 65001) {
        char *track;
        int bcnt, scnt;

        outbuf = cli_calloc(1, sz+1);
        if (!(outbuf))
            return NULL;
        memcpy(outbuf, begin, sz);

        track = outbuf+sz-1;
        if ((sctx->codepage == 65001) && (*track & 0x80)) { /* UTF-8 with a most significant bit */
            /* locate the start of the last character */
            for (bcnt = 1; (track != outbuf); track--, bcnt++) {
                if (((uint8_t)*track & 0xC0) != 0x80)
                    break;
            }

            /* count number of set (1) significant bits */
            for (scnt = 0; scnt < sizeof(uint8_t)*8; scnt++) {
                if (((uint8_t)*track & (0x80 >> scnt)) == 0)
                    break;
            }

            if (bcnt != scnt) {
                cli_dbgmsg("ole2_convert_utf: cleaning out %d bytes from incomplete "
                           "utf-8 character length %d\n", bcnt, scnt);
                for (; bcnt > 0; bcnt--, track++)
                    *track = '\0';
            }
        }
        return outbuf;
    }

#if HAVE_ICONV
    p1 = buf = cli_calloc(1, sz);
    if (!(buf))
        return NULL;

    memcpy(buf, begin, sz);
    inlen = sz;

    /* encoding lookup if not specified */
    if (!encoding) {
        for (i = 0; i < NUMCODEPAGES; ++i) {
            if (sctx->codepage == codepage_entries[i].codepage)
                encoding = codepage_entries[i].encoding;
            else if (sctx->codepage < codepage_entries[i].codepage) {
                /* assuming sorted array */
                break;
            }
        }

        if (!encoding) {
            cli_warnmsg("ole2_convert_utf: could not locate codepage encoding for %d\n", sctx->codepage);
            sctx->flags |= OLE2_CODEPAGE_ERROR_NOTFOUND;
            free(buf);
            return NULL;
        }
    }

    cd = iconv_open("UTF-8", encoding);
    if (cd == (iconv_t)(-1)) {
        char errbuf[128];
        cli_strerror(errno, errbuf, sizeof(errbuf)); 
        cli_errmsg("ole2_convert_utf: could not initialize iconv for encoding %s: %s\n", encoding, errbuf);
        sctx->flags |= OLE2_CODEPAGE_ERROR_UNINITED;
    }
    else {
        offset = 0;
        for (try = 1; try <= 3; ++try) {
            /* charset to UTF-8 should never exceed sz*6 */
            sz2 = (try*2) * sz;
            /* use cli_realloc, reuse the buffer that has already been translated */
            outbuf = (char *)cli_realloc(outbuf, sz2+1);
            if (!outbuf) {
                free(buf);
                return NULL;
            }

            outlen = sz2 - offset;
            p2 = outbuf + offset;

            /* conversion */
            nonrev = iconv(cd, &p1, &inlen, &p2, &outlen);

            if (errno == EILSEQ) {
                cli_dbgmsg("ole2_convert_utf: input buffer contains invalid character for its encoding\n");
                sctx->flags |= OLE2_CODEPAGE_ERROR_INVALID;
                break;
            }
            else if (errno == EINVAL && nonrev == (size_t)-1) {
                cli_dbgmsg("ole2_convert_utf: input buffer contains incomplete multibyte character\n");
                sctx->flags |= OLE2_CODEPAGE_ERROR_INCOMPLETE;
                break;
            }
            else if (inlen == 0) {
                //cli_dbgmsg("ole2_convert_utf: input buffer is successfully translated\n");
                break;
            }

            //outbuf[sz2 - outlen] = '\0';
            //cli_dbgmsg("%u %s\n", inlen, outbuf);

            offset = sz2 - outlen;
            if (try < 3)
                cli_dbgmsg("ole2_convert_utf: outbuf is too small, resizing %llu -> %llu\n",
                           (long long unsigned)((try*2) * sz), (long long unsigned)(((try+1)*2) * sz));
        }

        if (errno == E2BIG && nonrev == (size_t)-1) {
            cli_dbgmsg("ole2_convert_utf: buffer could not be fully translated\n");
            sctx->flags |= OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL;
        }

        outbuf[sz2 - outlen] = '\0';
    }

    iconv_close(cd);
    free(buf);
#endif
    /* this should force base64 encoding if NULL */
    return outbuf;
}

static int
ole2_process_property(summary_ctx_t *sctx, unsigned char *databuf, uint32_t offset)
{
    uint16_t proptype, padding;
    int ret = CL_SUCCESS;

    if (cli_json_timeout_cycle_check(sctx->ctx, &(sctx->toval)) != CL_SUCCESS) {
        sctx->flags |= OLE2_SUMMARY_FLAG_TIMEOUT;
        return CL_ETIMEOUT;
    }

    if (offset+sizeof(proptype)+sizeof(padding) > sctx->pssize) {
        sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
        return CL_EFORMAT;
    }

    memcpy(&proptype, databuf+offset, sizeof(proptype));
    offset+=sizeof(proptype);
    memcpy(&padding, databuf+offset, sizeof(padding));
    offset+=sizeof(padding);
    /* endian conversion */
    proptype = sum16_endian_convert(proptype);

    //cli_dbgmsg("proptype: 0x%04x\n", proptype);
    if (padding != 0) {
        cli_dbgmsg("ole2_process_property: invalid padding value, non-zero\n");
        sctx->flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
        return CL_EFORMAT;
    }

    switch (proptype) {
    case PT_EMPTY:
    case PT_NULL:
        ret = cli_jsonnull(sctx->summary, sctx->propname);
        break;
    case PT_INT16:
	{
            int16_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum16_endian_convert(dout);

            if (sctx->writecp) {
                sctx->codepage = (uint16_t)dout;
                ret = cli_jsonint(sctx->summary, sctx->propname, sctx->codepage);
            }
            else
                ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_INT32:
    case PT_INT32v1:
	{
            int32_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum32_endian_convert(dout);

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_FLOAT32: /* review this please */
	{
            float dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum32_endian_convert(dout);

            ret = cli_jsondouble(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_DATE:
    case PT_DOUBLE64: /* review this please */
	{
            double dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum64_endian_convert(dout);

            ret = cli_jsondouble(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_BOOL:
	{
            uint16_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* no need for endian conversion */

            ret = cli_jsonbool(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_INT8v1:
	{
            int8_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* no need for endian conversion */

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT8:
	{
            uint8_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* no need for endian conversion */

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT16:
	{
            uint16_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum16_endian_convert(dout);

            if (sctx->writecp)
                sctx->codepage = dout;

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT32:
    case PT_UINT32v1:
	{
            uint32_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum32_endian_convert(dout);

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_INT64:
	{
            int64_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum64_endian_convert(dout);

            ret = cli_jsonint64(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT64:
	{
            uint64_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum64_endian_convert(dout);

            ret = cli_jsonint64(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_BSTR:
    case PT_LPSTR:
        if (sctx->codepage == 0) {
            cli_dbgmsg("ole2_propset_json: current codepage is unknown, cannot parse char stream\n");
            sctx->flags |= OLE2_SUMMARY_FLAG_CODEPAGE;
        }
        else {
            uint32_t strsize;
            char *outstr, *outstr2;

            if (offset+sizeof(strsize) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }

            memcpy(&strsize, databuf+offset, sizeof(strsize));
            offset+=sizeof(strsize);
            /* endian conversion? */
            strsize = sum32_endian_convert(strsize);

            if (offset+strsize > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }

            /* limitation on string length */
            if (strsize > PROPSTRLIMIT) {
                cli_dbgmsg("ole2_process_property: property string sized %lu truncated to size %lu\n",
                           (unsigned long)strsize, (unsigned long)PROPSTRLIMIT);
                sctx->flags |= OLE2_SUMMARY_FLAG_TRUNC_STR;
                strsize = PROPSTRLIMIT;
            }

            outstr = cli_calloc(strsize+1, 1); /* last char must be NULL */
            if (!outstr) {
                return CL_EMEM;
            }
            strncpy(outstr, (const char *)(databuf+offset), strsize);

            /* conversion of various encodings to UTF-8 */
            outstr2 = ole2_convert_utf(sctx, outstr, strsize, NULL);
            if (!outstr2) {
                /* use base64 encoding when all else fails! */
                char b64jstr[PROPSTRLIMIT];

                /* outstr2 should be 4/3 times the original (rounded up) */
                outstr2 = cl_base64_encode(outstr, strsize);
                if (!outstr2) {
                    cli_dbgmsg("ole2_process_property: failed to convert to base64 string\n");
                    return CL_EMEM;
                }

                snprintf(b64jstr, PROPSTRLIMIT, "%s_base64", sctx->propname);
                ret = cli_jsonbool(sctx->summary, b64jstr, 1);
                if (ret != CL_SUCCESS)
                    return ret;
            }

            ret = cli_jsonstr(sctx->summary, sctx->propname, outstr2);
            free(outstr);
            free(outstr2);
        }
        break;
    case PT_LPWSTR:
	{
            uint32_t strsize;
            char *outstr, *outstr2;

            if (offset+sizeof(strsize) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&strsize, databuf+offset, sizeof(strsize));
            offset+=sizeof(strsize);
            /* endian conversion; wide strings are by length, not size (x2) */
            strsize = sum32_endian_convert(strsize)*2;

            /* limitation on string length */
            if (strsize > (2*PROPSTRLIMIT)) {
                cli_dbgmsg("ole2_process_property: property string sized %lu truncated to size %lu\n",
                           (unsigned long)strsize, (unsigned long)(2*PROPSTRLIMIT));
                sctx->flags |= OLE2_SUMMARY_FLAG_TRUNC_STR;
                strsize = (2*PROPSTRLIMIT);
            }

            if (offset+strsize > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            outstr = cli_calloc(strsize+2, 1); /* last two chars must be NULL */
            if (!outstr) {
                return CL_EMEM;
            }
            memcpy(outstr, (const char *)(databuf+offset), strsize);
            /* conversion of 16-width char strings (UTF-16 or UTF-16LE??) to UTF-8 */
            outstr2 = ole2_convert_utf(sctx, outstr, strsize, UTF16_MS);
            if (!outstr2) {
                /* use base64 encoding when all else fails! */
                char b64jstr[PROPSTRLIMIT];

                outstr2 = cl_base64_encode(outstr, strsize);
                if (!outstr2) {
                    free(outstr);
                    return CL_EMEM;
                }

                snprintf(b64jstr, PROPSTRLIMIT, "%s_base64", sctx->propname);
                ret = cli_jsonbool(sctx->summary, b64jstr, 1);
                if (ret != CL_SUCCESS)
                    return ret;
            }

            ret = cli_jsonstr(sctx->summary, sctx->propname, outstr2);
            free(outstr);
            free(outstr2);
            break;
	}
    case PT_FILETIME:
	{
            uint32_t ltime, htime;
            uint64_t wtime = 0, utime =0;

            if (offset+sizeof(ltime)+sizeof(htime) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&ltime, databuf+offset, sizeof(ltime));
            offset+=sizeof(ltime);
            memcpy(&htime, databuf+offset, sizeof(htime));
            offset+=sizeof(ltime);
            ltime = sum32_endian_convert(ltime);
            htime = sum32_endian_convert(htime);

            /* UNIX timestamp formatting */
            wtime = htime;
            wtime <<= 32;
            wtime |= ltime;

            utime = wtime / 10000000;
            utime -= 11644473600LL;

            if ((uint32_t)((utime & 0xFFFFFFFF00000000) >> 32)) {
                cli_dbgmsg("ole2_process_property: UNIX timestamp is larger than 32-bit number\n");
            }
            else {
                ret = cli_jsonint(sctx->summary, sctx->propname, (uint32_t)(utime & 0xFFFFFFFF));
            }
            break;
	}
    default:
        cli_dbgmsg("ole2_process_property: unhandled property type 0x%04x for %s property\n", 
                   proptype, sctx->propname);
        sctx->flags |= OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE;
    }

    return ret;
}

static void ole2_translate_docsummary_propid(summary_ctx_t *sctx, uint32_t propid)
{
    switch(propid) {
    case DSPID_CODEPAGE:
        sctx->writecp = 1; /* must be set ONLY for codepage */
        sctx->propname = "CodePage";
        break;
    case DSPID_CATEGORY:
        sctx->propname = "Category";
        break;
    case DSPID_PRESFORMAT:
        sctx->propname = "PresentationTarget";
        break;
    case DSPID_BYTECOUNT:
        sctx->propname = "Bytes";
        break;
    case DSPID_LINECOUNT:
        sctx->propname = "Lines";
        break;
    case DSPID_PARCOUNT:
        sctx->propname = "Paragraphs";
        break;
    case DSPID_SLIDECOUNT:
        sctx->propname = "Slides";
        break;
    case DSPID_NOTECOUNT:
        sctx->propname = "Notes";
        break;
    case DSPID_HIDDENCOUNT:
        sctx->propname = "HiddenSlides";
        break;
    case DSPID_MMCLIPCOUNT:
        sctx->propname = "MMClips";
        break;
    case DSPID_SCALE:
        sctx->propname = "Scale";
        break;
    case DSPID_HEADINGPAIR: /* VT_VARIANT | VT_VECTOR */
        sctx->propname = "HeadingPairs";
        break;
    case DSPID_DOCPARTS:    /* VT_VECTOR | VT_LPSTR */
        sctx->propname = "DocPartTitles";
        break;
    case DSPID_MANAGER:
        sctx->propname = "Manager";
        break;
    case DSPID_COMPANY:
        sctx->propname = "Company";
        break;
    case DSPID_LINKSDIRTY:
        sctx->propname = "LinksDirty";
        break;
    case DSPID_CCHWITHSPACES:
        sctx->propname = "Char&WSCount";
        break;
    case DSPID_SHAREDDOC:   /* SHOULD BE FALSE! */
        sctx->propname = "SharedDoc";
        break;
    case DSPID_LINKBASE:    /* moved to user-defined */
        sctx->propname = "LinkBase";
        break;
    case DSPID_HLINKS:      /* moved to user-defined */
        sctx->propname = "HyperLinks";
        break;
    case DSPID_HYPERLINKSCHANGED:
        sctx->propname = "HyperLinksChanged";
        break;
    case DSPID_VERSION:
        sctx->propname = "Version";
        break;
    case DSPID_DIGSIG:
        sctx->propname = "DigitalSig";
        break;
    case DSPID_CONTENTTYPE:
        sctx->propname = "ContentType";
        break;
    case DSPID_CONTENTSTATUS:
        sctx->propname = "ContentStatus";
        break;
    case DSPID_LANGUAGE:
        sctx->propname = "Language";
        break;
    case DSPID_DOCVERSION:
        sctx->propname = "DocVersion";
        break;
    default:
        cli_dbgmsg("ole2_docsum_propset_json: unrecognized propid!\n");
        sctx->flags |= OLE2_SUMMARY_FLAG_UNKNOWN_PROPID;
    }
}

static void ole2_translate_summary_propid(summary_ctx_t *sctx, uint32_t propid)
{
    switch(propid) {
    case SPID_CODEPAGE:
        sctx->writecp = 1; /* must be set ONLY for codepage */
        sctx->propname = "CodePage";
        break;
    case SPID_TITLE:
        sctx->propname = "Title";
        break;
    case SPID_SUBJECT:
        sctx->propname = "Subject";
        break;
    case SPID_AUTHOR:
        sctx->propname = "Author";
        break;
    case SPID_KEYWORDS:
        sctx->propname = "Keywords";
        break;
    case SPID_COMMENTS:
        sctx->propname = "Comments";
        break;
    case SPID_TEMPLATE:
        sctx->propname = "Template";
        break;
    case SPID_LASTAUTHOR:
        sctx->propname = "LastAuthor";
        break;
    case SPID_REVNUMBER:
        sctx->propname = "RevNumber";
        break;
    case SPID_EDITTIME:
        sctx->propname = "EditTime";
        break;
    case SPID_LASTPRINTED:
        sctx->propname = "LastPrinted";
        break;
    case SPID_CREATEDTIME:
        sctx->propname = "CreatedTime";
        break;
    case SPID_MODIFIEDTIME:
        sctx->propname = "ModifiedTime";
        break;
    case SPID_PAGECOUNT:
        sctx->propname = "PageCount";
        break;
    case SPID_WORDCOUNT:
        sctx->propname = "WordCount";
        break;
    case SPID_CHARCOUNT:
        sctx->propname = "CharCount";
        break;
    case SPID_THUMBNAIL:
        sctx->propname = "Thumbnail";
        break;
    case SPID_APPNAME:
        sctx->propname = "AppName";
        break;
    case SPID_SECURITY:
        sctx->propname = "Security";
        break;
    default:
        cli_dbgmsg("ole2_translate_summary_propid: unrecognized propid!\n");
        sctx->flags |= OLE2_SUMMARY_FLAG_UNKNOWN_PROPID;
    }
}

static int ole2_summary_propset_json(summary_ctx_t *sctx, off_t offset)
{
    unsigned char *hdr, *ps;
    uint32_t numprops, limitprops;
    off_t foff = offset, psoff = 0;
    uint32_t poffset;
    int ret;
    unsigned int i;

    cli_dbgmsg("in ole2_summary_propset_json\n");

    /* summary ctx propset-specific setup*/
    sctx->codepage = 0;
    sctx->writecp = 0;
    sctx->propname = NULL;

    /* examine property set metadata */
    if ((foff+(2*sizeof(uint32_t))) > sctx->maplen) {
        sctx->flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return CL_EFORMAT;
    }
    hdr = (unsigned char*)fmap_need_off_once(sctx->sfmap, foff, (2*sizeof(uint32_t)));
    if (!hdr) {
        sctx->flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return CL_EREAD;
    }
    //foff+=(2*sizeof(uint32_t)); // keep foff pointing to start of propset segment
    psoff+=(2*sizeof(uint32_t));
    memcpy(&(sctx->pssize), hdr, sizeof(sctx->pssize));
    memcpy(&numprops, hdr+sizeof(sctx->pssize), sizeof(numprops));
    /* endian conversion */
    sctx->pssize = sum32_endian_convert(sctx->pssize);
    numprops = sum32_endian_convert(numprops);
    cli_dbgmsg("ole2_summary_propset_json: pssize: %u, numprops: %u\n", sctx->pssize, numprops);
    if (numprops > PROPCNTLIMIT) {
        sctx->flags |= OLE2_SUMMARY_LIMIT_PROPS;
        limitprops = PROPCNTLIMIT;
    }
    else {
        limitprops = numprops;
    }
    cli_dbgmsg("ole2_summary_propset_json: processing %u of %u (%u max) properties\n",
               limitprops, numprops, PROPCNTLIMIT);

    /* extract remaining fragment of propset */
    if ((size_t)(foff+(sctx->pssize)) > (size_t)(sctx->maplen)) {
        sctx->flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return CL_EFORMAT;
    }
    ps = (unsigned char*)fmap_need_off_once(sctx->sfmap, foff, sctx->pssize);
    if (!ps) {
        sctx->flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return CL_EREAD;
    }

    /* iterate over the properties */
    for (i = 0; i < limitprops; ++i) {
        uint32_t propid, propoff;

        if (psoff+sizeof(propid)+sizeof(poffset) > sctx->pssize) {
            sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
            return CL_EFORMAT;
        }
        memcpy(&propid, ps+psoff, sizeof(propid));
        psoff+=sizeof(propid);
        memcpy(&propoff, ps+psoff, sizeof(propoff));
        psoff+=sizeof(propoff);
        /* endian conversion */
        propid = sum32_endian_convert(propid);
        propoff = sum32_endian_convert(propoff);
        cli_dbgmsg("ole2_summary_propset_json: propid: 0x%08x, propoff: %u\n", propid, propoff);

        sctx->propname = NULL; sctx->writecp = 0;
        switch (sctx->mode) {
        case 1:
            ole2_translate_docsummary_propid(sctx, propid);
            break;
        default:
            ole2_translate_summary_propid(sctx, propid);
        }

        if (sctx->propname != NULL) {
            ret = ole2_process_property(sctx, ps, propoff);
            if (ret != CL_SUCCESS)
                return ret;
        }
        else {
            /* add unknown propid flag */
        }
    }

    return CL_SUCCESS;
}

static int cli_ole2_summary_json_cleanup(summary_ctx_t *sctx, int retcode)
{
    json_object *jarr;

    cli_dbgmsg("in cli_ole2_summary_json_cleanup: %d[%x]\n", retcode, sctx->flags);

    if (sctx->sfmap) {
        funmap(sctx->sfmap);
    }

    if (sctx->flags) {
        jarr = cli_jsonarray(sctx->summary, "ParseErrors");

        /* summary errors */
        if (sctx->flags & OLE2_SUMMARY_ERROR_TOOSMALL) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_TOOSMALL");
        }
        if (sctx->flags & OLE2_SUMMARY_ERROR_OOB) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_OOB");
        }
        if (sctx->flags & OLE2_SUMMARY_ERROR_DATABUF) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_DATABUF");
        }
        if (sctx->flags & OLE2_SUMMARY_ERROR_INVALID_ENTRY) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_INVALID_ENTRY");
        }
        if (sctx->flags & OLE2_SUMMARY_LIMIT_PROPS) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_LIMIT_PROPS");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_TIMEOUT) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_TIMEOUT");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_CODEPAGE) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_CODEPAGE");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_UNKNOWN_PROPID) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_UNKNOWN_PROPID");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_TRUNC_STR) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_TRUNC_STR");
        }

        /* codepage translation errors */
        if (sctx->flags & OLE2_CODEPAGE_ERROR_NOTFOUND) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_NOTFOUND");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_UNINITED) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_UNINITED");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_INVALID) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_INVALID");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_INCOMPLETE) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_INCOMPLETE");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL");
        }
    }

    return retcode;
}

int cli_ole2_summary_json(cli_ctx *ctx, int fd, int mode)
{
    summary_ctx_t sctx;
    STATBUF statbuf;
    off_t foff = 0;
    unsigned char *databuf;
    summary_stub_t sumstub;
    propset_entry_t pentry;
    int ret = CL_SUCCESS;

    cli_dbgmsg("in cli_ole2_summary_json\n");

    /* preliminary sanity checks */
    if (ctx == NULL) {
        return CL_ENULLARG;
    }

    if (fd < 0) {
        cli_dbgmsg("ole2_summary_json: invalid file descriptor\n");
        return CL_ENULLARG; /* placeholder */
    }

    if (mode < 0 && mode > 2) {
        cli_dbgmsg("ole2_summary_json: invalid mode specified\n");
        return CL_ENULLARG; /* placeholder */
    }

    /* summary ctx setup */
    memset(&sctx, 0, sizeof(sctx));
    sctx.ctx = ctx;
    sctx.mode = mode;

    if (FSTAT(fd, &statbuf) == -1) {
        cli_dbgmsg("ole2_summary_json: cannot stat file descriptor\n");
        return CL_ESTAT;
    }

    sctx.sfmap = fmap(fd, 0, statbuf.st_size);
    if (!sctx.sfmap) {
        cli_dbgmsg("ole2_summary_json: failed to get fmap\n");
        return CL_EMAP;
    }
    sctx.maplen = sctx.sfmap->len;
    cli_dbgmsg("ole2_summary_json: streamsize: %zu\n", sctx.maplen);

    switch (mode) {
    case 1:
        sctx.summary = cli_jsonobj(ctx->wrkproperty, "DocSummaryInfo");
        break;
    case 2:
        sctx.summary = cli_jsonobj(ctx->wrkproperty, "Hwp5SummaryInfo");
        break;
    case 0:
    default:
        sctx.summary = cli_jsonobj(ctx->wrkproperty, "SummaryInfo");
        break;
    }


    if (!sctx.summary) {
        cli_errmsg("ole2_summary_json: no memory for json object.\n");
        return cli_ole2_summary_json_cleanup(&sctx, CL_EMEM);
    }

    sctx.codepage = 0;
    sctx.writecp = 0;

    /* acquire property stream metadata */
    if (sctx.maplen < sizeof(summary_stub_t)) {
        sctx.flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);
    }
    databuf = (unsigned char*)fmap_need_off_once(sctx.sfmap, foff, sizeof(summary_stub_t));
    if (!databuf) {
        sctx.flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EREAD);
    }
    foff += sizeof(summary_stub_t);
    memcpy(&sumstub, databuf, sizeof(summary_stub_t));

    /* endian conversion and checks */
    sumstub.byte_order = le16_to_host(sumstub.byte_order);
    if (sumstub.byte_order != 0xfffe) {
        cli_dbgmsg("ole2_summary_json: byteorder 0x%x is invalid\n", sumstub.byte_order);
        sctx.flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);;
    }
    sumstub.version = sum16_endian_convert(sumstub.version); /*unused*/
    sumstub.system = sum32_endian_convert(sumstub.system); /*unused*/
    sumstub.num_propsets = sum32_endian_convert(sumstub.num_propsets);
    if (sumstub.num_propsets != 1 && sumstub.num_propsets != 2) {
        cli_dbgmsg("ole2_summary_json: invalid number of property sets\n");
        sctx.flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);
    }

    cli_dbgmsg("ole2_summary_json: byteorder 0x%x\n", sumstub.byte_order);
    cli_dbgmsg("ole2_summary_json: %u property set(s) detected\n", sumstub.num_propsets);

    /* first property set (index=0) is always SummaryInfo or DocSummaryInfo */
    if ((sctx.maplen-foff) < sizeof(propset_entry_t)) {
        sctx.flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);
    }
    databuf = (unsigned char*)fmap_need_off_once(sctx.sfmap, foff, sizeof(propset_entry_t));
    if (!databuf) {
        sctx.flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EREAD);
    }
    foff += sizeof(propset_entry_t);
    memcpy(&pentry, databuf, sizeof(propset_entry_t));
    /* endian conversion */
    pentry.offset = sum32_endian_convert(pentry.offset);

    if ((ret = ole2_summary_propset_json(&sctx, pentry.offset)) != CL_SUCCESS) {
        return cli_ole2_summary_json_cleanup(&sctx, ret);
    }

    /* second property set (index=1) is always a custom property set (if present) */
    if (sumstub.num_propsets == 2) {
        cli_jsonbool(ctx->wrkproperty, "HasUserDefinedProperties", 1);
    }

    return cli_ole2_summary_json_cleanup(&sctx, CL_SUCCESS);
}
#endif /* HAVE_JSON */
