/*
 *  Copyright (C) 2014, 2017-2018 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
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
#include "json_api.h"
#include "conv.h"

char *pdf_convert_utf(char *begin, size_t sz);

char *pdf_convert_utf(char *begin, size_t sz)
{
    char *res=NULL;
    char *buf, *outbuf;
#if HAVE_ICONV
    char *p1, *p2;
    size_t inlen, outlen, i;
    char *encodings[] = {
        "UTF-16",
        NULL
    };
    iconv_t cd;
#endif

    buf = cli_calloc(1, sz+1);
    if (!(buf))
        return NULL;
    memcpy(buf, begin, sz);

#if HAVE_ICONV
    p1 = buf;

    p2 = outbuf = cli_calloc(1, sz+1);
    if (!(outbuf)) {
        free(buf);
        return NULL;
    }

    for (i=0; encodings[i] != NULL; i++) {
        p1 = buf;
        p2 = outbuf;
        inlen = outlen = sz;

        cd = iconv_open("UTF-8", encodings[i]);
        if (cd == (iconv_t)(-1)) {
            char errbuf[128];
            cli_strerror(errno, errbuf, sizeof(errbuf)); 
            cli_errmsg("pdf_convert_utf: could not initialize iconv for encoding %s: %s\n", encodings[i], errbuf);
            continue;
        }

        iconv(cd, (char **)(&p1), &inlen, &p2, &outlen);

        if (outlen == sz) {
            /* Decoding unsuccessful right from the start */
            iconv_close(cd);
            continue;
        }

        outbuf[sz - outlen] = '\0';

        res = strdup(outbuf);
        iconv_close(cd);
        break;
    }
#else
    outbuf = cli_utf16_to_utf8(buf, sz, UTF16_BOM);
    if (!outbuf) {
        free(buf);
        return NULL;
    }

    res = strdup(outbuf);
#endif
    free(buf);
    free(outbuf);

    return res;
}

int is_object_reference(char *begin, char **endchar, uint32_t *id)
{
    char *end = *endchar;
    char *p1=begin, *p2;
    unsigned long n;
    uint32_t t=0;

    /*
     * Object references are always this format:
     * XXXX YYYY R
     * Where XXXX is the object ID and YYYY is the revision ID of the object.
     * The letter R signifies that this is a reference.
     *
     * In between each item can be an arbitrary amount of whitespace.
     */

    /* Skip whitespace */
    while (p1 < end && isspace(p1[0]))
        p1++;

    if (p1 == end)
        return 0;

    if (!isdigit(p1[0]))
        return 0;

    /* Ensure strtoul() isn't going to go past our buffer */
    p2 = p1+1;
    while (p2 < end && !isspace(p2[0]))
        p2++;

    if (p2 == end)
        return 0;

    n = strtoul(p1, &p2, 10);
    if (n == ULONG_MAX && errno)
        return 0;

    t = n<<8;

    /* Skip more whitespace */
    p1 = p2;
    while (p1 < end && isspace(p1[0]))
        p1++;

    if (p1 == end)
        return 0;

    if (!isdigit(p1[0]))
        return 0;

    /* Ensure strtoul() is going to go past our buffer */
    p2 = p1+1;
    while (p2 < end && !isspace(p2[0]))
        p2++;

    if (p2 == end)
        return 0;

    n = strtoul(p1, &p2, 10);
    if (n == ULONG_MAX && errno)
        return 0;

    t |= (n&0xff);

    /* Skip even more whitespace */
    p1 = p2;
    while (p1 < end && isspace(p1[0]))
        p1++;

    if (p1 == end)
        return 0;

    if (p1[0] == 'R') {
        *endchar = p1+1;
        if (id)
            *id = t;

        return 1;
    }

    return 0;
}

static char *pdf_decrypt_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *in, size_t *length)
{
    enum enc_method enc;

    /* handled only once in cli_pdf() */
    //pdf_handle_enc(pdf);
    if (pdf->flags & (1 << DECRYPTABLE_PDF)) {
        enc = get_enc_method(pdf, obj);
        return decrypt_any(pdf, obj->id, in, length, enc);
    }
    return NULL;
}

char *pdf_finalize_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *in, size_t len)
{
    char *wrkstr, *output = NULL;
    size_t wrklen = len, outlen, i;
    unsigned int likelyutf = 0;

    if (!in)
        return NULL;

    /* get a working copy */
    wrkstr = cli_calloc(len+1, sizeof(char));
    if (!wrkstr)
        return NULL;
    memcpy(wrkstr, in, len);

    //cli_errmsg("pdf_final: start(%d):   %s\n", wrklen, wrkstr);

    /* convert PDF specific escape sequences, like octal sequences */
    /* TODO: replace the escape sequences directly in the wrkstr   */
    if (strchr(wrkstr, '\\')) {
        output = cli_calloc(wrklen+1, sizeof(char));
        if (!output) {
            free(wrkstr);
            return NULL;
        }

        outlen = 0;
        for (i = 0; i < wrklen; ++i) {
            if ((i+1 < wrklen) && wrkstr[i] == '\\') {
                if ((i+3 < wrklen) &&
                    (isdigit(wrkstr[i+1]) && isdigit(wrkstr[i+2]) && isdigit(wrkstr[i+3]))) {
                    /* octal sequence */
                    char octal[4], *check;
                    unsigned long value;

                    memcpy(octal, &wrkstr[i+1], 3);
                    octal[3] = '\0';

                    value = (char)strtoul(octal, &check, 8);
                    /* check if all characters were converted */
                    if (check == &octal[3])
                        output[outlen++] = value;
                    i += 3; /* 4 with for loop [\ddd] */
                } else {
                    /* other sequences */
                    switch(wrkstr[i+1]) {
                    case 'n':
                        output[outlen++] = 0x0a;
                        break;
                    case 'r':
                        output[outlen++] = 0x0d;
                        break;
                    case 't':
                        output[outlen++] = 0x09;
                        break;
                    case 'b':
                        output[outlen++] = 0x08;
                        break;
                    case 'f':
                        output[outlen++] = 0x0c;
                        break;
                    case '(':
                        output[outlen++] = 0x28;
                        break;
                    case ')':
                        output[outlen++] = 0x29;
                        break;
                    case '\\':
                        output[outlen++] = 0x5c;
                        break;
                    default:
                        /* IGNORE THE REVERSE SOLIDUS - PDF3000-2008 */
                        break;
                    }
                    i += 1; /* 2 with for loop [\c] */
                }
            } else {
                output[outlen++] = wrkstr[i];
            }
        }

        free(wrkstr);
        wrkstr = cli_calloc(outlen+1, sizeof(char));
        if (!wrkstr) {
            free(output);
            return NULL;
        }
        memcpy(wrkstr, output, outlen);
        free(output);
        wrklen = outlen;
    }

    //cli_errmsg("pdf_final: escaped(%d): %s\n", wrklen, wrkstr);

    /* check for encryption and decrypt */
    if (pdf->flags & (1 << ENCRYPTED_PDF))
    {
        size_t tmpsz = wrklen;
        output = pdf_decrypt_string(pdf, obj, wrkstr, &tmpsz);
        outlen = tmpsz;
        free(wrkstr);
        if (output) {
            wrkstr = cli_calloc(outlen+1, sizeof(char));
            if (!wrkstr) {
                free(output);
                return NULL;
            }
            memcpy(wrkstr, output, outlen);
            free(output);
            wrklen = outlen;
        } else {
            return NULL;
        }
    }

    //cli_errmsg("pdf_final: decrypt(%d): %s\n", wrklen, wrkstr);

    /* check for UTF-* and convert to UTF-8 */
    for (i = 0; i < wrklen; ++i) {
        if (((unsigned char)wrkstr[i] > (unsigned char)0x7f) || (wrkstr[i] == '\0')) {
            likelyutf = 1;
            break;
        }
    }

    if (likelyutf) {
        output = pdf_convert_utf(wrkstr, wrklen);
        free(wrkstr);
        wrkstr = output;
    }

    //cli_errmsg("pdf_final: postutf(%d): %s\n", wrklen, wrkstr);

    return wrkstr;
}

char *pdf_parse_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *objstart, size_t objsize, const char *str, char **endchar, struct pdf_stats_metadata *meta)
{
    const char *q = objstart;
    char *p1, *p2;
    size_t len, checklen;
    char *res = NULL;
    uint32_t objid;
    size_t i;

    if (obj->objstm) {
        if (objsize > (size_t)(obj->objstm->streambuf_len - (objstart - obj->objstm->streambuf))) {
            /* Possible attempt to exploit bb11980 */
            cli_dbgmsg("Malformed PDF: Alleged size of obj in object stream in PDF would extend further than the object stream data.\n");
            return NULL;
        }
    }
    else {
        if (objsize > (size_t)(pdf->size - (objstart - pdf->map))) {
            /* Possible attempt to exploit bb11980 */
            cli_dbgmsg("Malformed PDF: Alleged size of obj in PDF would extend further than the PDF data.\n");
            return NULL;
        }
    }

    /*
     * Yes, all of this is required to find the start and end of a potentially UTF-* string
     *
     * First, find the key of the key/value pair we're looking for in this object.
     * Second, determine whether the value points to another object (NOTE: this is sketchy behavior)
     * Third, attempt to determine if we're ASCII or UTF-*
     * If we're ASCII, just copy the ASCII string into a new heap-allocated string and return that
     * Fourth, Attempt to decode from UTF-* to UTF-8
     */

    if (str) {
        checklen = strlen(str);

        if (objsize < strlen(str) + 3)
            return NULL;

        for (p1=(char *)q; (size_t)(p1 - q) < objsize-checklen; p1++)
            if (!strncmp(p1, str, checklen))
                break;

        if ((size_t)(p1 - q) == objsize - checklen)
            return NULL;

        p1 += checklen;
    } else {
        p1 = (char *)q;
    }

    while ((size_t)(p1 - q) < objsize && isspace(p1[0]))
        p1++;

    if ((size_t)(p1 - q) == objsize)
        return NULL;

    /*
     * If str is non-null:
     *     We should be at the start of the string, minus 1
     * Else:
     *     We should be at the start of the string
     */

    p2 = (char *)(q + objsize);
    if (is_object_reference(p1, &p2, &objid)) {
        struct pdf_obj *newobj;
        char *begin, *p3;
        STATBUF sb;
        uint32_t objflags;
        int fd;
        size_t objsize2;

        newobj = find_obj(pdf, obj, objid);
        if (!(newobj))
            return NULL;

        if (newobj == obj)
            return NULL;

        /* 
         * If pdf_handlename hasn't been called for this object,
         * then parse the object prior to extracting it
         */
        if (!(newobj->statsflags & OBJ_FLAG_PDFNAME_DONE))
            pdf_parseobj(pdf, newobj);

        /* Extract the object. Force pdf_extract_obj() to dump this object. */
        objflags = newobj->flags;
        newobj->flags |= (1 << OBJ_FORCEDUMP);

        if (pdf_extract_obj(pdf, newobj, PDF_EXTRACT_OBJ_NONE) != CL_SUCCESS)
            return NULL;

        newobj->flags = objflags;

        if (!(newobj->path))
            return NULL;

        fd = open(newobj->path, O_RDONLY);
        if (fd == -1) {
            cli_unlink(newobj->path);
            free(newobj->path);
            newobj->path = NULL;
            return NULL;
        }

        if (FSTAT(fd, &sb)) {
            close(fd);
            cli_unlink(newobj->path);
            free(newobj->path);
            newobj->path = NULL;
            return NULL;
        }

        if (sb.st_size) {
            begin = calloc(1, sb.st_size+1);
            if (!(begin)) {
                close(fd);
                cli_unlink(newobj->path);
                free(newobj->path);
                newobj->path = NULL;
                return NULL;
            }

            if (read(fd, begin, sb.st_size) != sb.st_size) {
                close(fd);
                cli_unlink(newobj->path);
                free(newobj->path);
                newobj->path = NULL;
                free(begin);
                return NULL;
            }

            p3 = begin;
            objsize2 = sb.st_size;
            while ((size_t)(p3 - begin) < objsize2 && isspace(p3[0])) {
                p3++;
                objsize2--;
            }

            switch (*p3) {
                case '(':
                case '<':
                    res = pdf_parse_string(pdf, obj, p3, objsize2, NULL, NULL, meta);
                    break;
                default:
                    res = pdf_finalize_string(pdf, obj, begin, objsize2);
                    if (!res) {
                        res = cli_calloc(1, objsize2+1);
                        if (!(res)) {
                            close(fd);
                            cli_unlink(newobj->path);
                            free(newobj->path);
                            newobj->path = NULL;
                            free(begin);
                            return NULL;
                        }
                        memcpy(res, begin, objsize2);
                        res[objsize2] = '\0';

                        if (meta) {
                            meta->length = objsize2;
                            meta->obj = obj;
                            meta->success = 0;
                        }
                    } else if (meta) {
                        meta->length = strlen(res);
                        meta->obj = obj;
                        meta->success = 1;
                    }
            }
            free(begin);
        }

        close(fd);
        cli_unlink(newobj->path);
        free(newobj->path);
        newobj->path = NULL;

        if (endchar)
            *endchar = p2;

        return res;
    }

    if (*p1 == '<') {
        /* Hex string */

        p2 = p1+1;
        while ((size_t)(p2 - objstart) < objsize && *p2 != '>')
            p2++;

        if ((size_t)(p2 - objstart) == objsize) {
            return NULL;
        }


        res = pdf_finalize_string(pdf, obj, p1, (p2 - p1) + 1);
        if (!res) {
            res = cli_calloc(1, (p2 - p1) + 2);
            if (!(res))
                return NULL;
            memcpy(res, p1, (p2 - p1) + 1);
            res[(p2 - p1) + 1] = '\0';

            if (meta) {
                meta->length = (p2 - p1) + 1;
                meta->obj = obj;
                meta->success = 0;
            }
        } else if (meta) {
            meta->length = strlen(res);
            meta->obj = obj;
            meta->success = 1;
        }

        if (res && endchar)
            *endchar = p2;

        return res;
    }

    /* We should be at the start of a string literal (...) here */
    if (*p1 != '(')
        return NULL;

    /* Make a best effort to find the end of the string and determine if UTF-* */
    p2 = ++p1;

    while (p2 < objstart + objsize) {
        int shouldbreak=0;

        switch (*p2) {
            case '\\':
                p2++;
                break;
            case ')':
                shouldbreak=1;
                break;
        }

        if (shouldbreak) {
            p2--;
            break;
        }

        p2++;
    }

    if (p2 >= objstart + objsize)
        return NULL;

    len = (size_t)(p2 - p1) + 1;

    res = pdf_finalize_string(pdf, obj, p1, len);
    if (!res) {
        res = cli_calloc(1, len+1);
        if (!(res))
            return NULL;
        memcpy(res, p1, len);
        res[len] = '\0';

        if (meta) {
            meta->length = len;
            meta->obj = obj;
            meta->success = 0;
        }
    } else if (meta) {
        meta->length = strlen(res);
        meta->obj = obj;
        meta->success = 1;
    }

    if (res && endchar)
        *endchar = p2;

    return res;
}

struct pdf_dict *pdf_parse_dict(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsize, char *begin, char **endchar)
{
    struct pdf_dict *res=NULL;
    struct pdf_dict_node *node=NULL;
    const char *objstart;
    char *end;
    unsigned int in_string=0, ninner=0;

    /* Sanity checking */
    if (!(pdf) || !(obj) || !(begin))
        return NULL;

    objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                             : (const char *)(obj->start + pdf->map);

    if (begin < objstart || (size_t)(begin - objstart) >= objsize - 2)
        return NULL;

    if (begin[0] != '<' || begin[1] != '<')
        return NULL;

    /* Find the end of the dictionary */
    end = begin;
    while ((size_t)(end - objstart) < objsize) {
        int increment=1;
        if (in_string) {
            if (*end == '\\') {
                end += 2;
                continue;
            }

            if (*end == ')')
                in_string = 0;

            end++;
            continue;
        }

        switch (*end) {
            case '(':
                in_string=1;
                break;
            case '<':
                if ((size_t)(end - objstart) <= objsize - 2 && end[1] == '<')
                    ninner++;
                increment=2;
                break;
            case '>':
                if ((size_t)(end - objstart) <= objsize - 2 && end[1] == '>')
                    ninner--;
                increment=2;
                break;
        }

        if ((size_t)(end - objstart) <= objsize - 2)
            if (end[0] == '>' && end[1] == '>' && ninner == 0)
                break;

        end += increment;
    }

    /* More sanity checking */
    if ((size_t)(end - objstart) >= objsize - 2)
        return NULL;

    if (end[0] != '>' || end[1] != '>')
        return NULL;

    res = cli_calloc(1, sizeof(struct pdf_dict));
    if (!(res))
        return NULL;

    /* Loop through each element of the dictionary */
    begin += 2;
    while (begin < end) {
        char *val=NULL, *key=NULL, *p1, *p2;
        struct pdf_dict *dict=NULL;
        struct pdf_array *arr=NULL;
        unsigned int nhex=0, i;

        /* Skip any whitespaces */
        while (begin < end && isspace(begin[0]))
            begin++;

        if (begin == end)
            break;

        /* Get the key */
        p1 = begin+1;
        while (p1 < end && !isspace(p1[0])) {
            int breakout=0;

            switch (*p1) {
                case '<':
                case '[':
                case '(':
                case '/':
                case '\r':
                case '\n':
                case ' ':
                case '\t':
                    breakout=1;
                    break;
                case '#':
                    /* Key name obfuscated with hex characters */
                    nhex++;
                    if (p1 > end-3) {
                        return res;
                    }

                    break;
            }
            
            if (breakout)
                break;

            p1++;
        }

        if (p1 == end)
            break;

        key = cli_calloc((p1 - begin) + 2, 1);
        if (!(key))
            break;

        if (nhex == 0) {
            /* Key isn't obfuscated with hex. Just copy the string */
            strncpy(key, begin, p1 - begin);
            key[p1 - begin] = '\0';
        } else {
            for (i=0, p2 = begin; p2 < p1; p2++, i++) {
                if (*p2 == '#') {
                    cli_hex2str_to(p2+1, key+i, 2);
                    p2 += 2;
                } else {
                    key[i] = *p2;
                }
            }
        }

        /* Now for the value */
        begin = p1;

        /* Skip any whitespaces */
        while (begin < end && isspace(begin[0]))
            begin++;

        if (begin == end) {
            free(key);
            break;
        }

        switch (begin[0]) {
            case '(':
                val = pdf_parse_string(pdf, obj, begin, end - objstart, NULL, &p1, NULL);
                begin = p1+2;
                break;
            case '[':
                arr = pdf_parse_array(pdf, obj, end - objstart, begin, &p1);
                begin = p1+1;
                break;
            case '<':
                if ((size_t)(begin - objstart) < objsize - 2) {
                    if (begin[1] == '<') {
                        dict = pdf_parse_dict(pdf, obj, end - objstart, begin, &p1);
                        begin = p1+2;
                        break;
                    }
                }

                val = pdf_parse_string(pdf, obj, begin, end - objstart, NULL, &p1, NULL);
                begin = p1+2;
                break;
            default:
                p1 = (begin[0] == '/') ? begin+1 : begin;
                while (p1 < end) {
                    int shouldbreak = 0;
                    switch (p1[0]) {
                        case '>':
                        case '/':
                            shouldbreak=1;
                            break;
                    }

                    if (shouldbreak)
                        break;

                    p1++;
                }

                is_object_reference(begin, &p1, NULL);

                val = cli_calloc((p1 - begin) + 2, 1);
                if (!(val))
                    break;

                strncpy(val, begin, p1 - begin);
                val[p1 - begin] = '\0';

                if (p1[0] != '/')
                    begin = p1+1;
                else
                    begin = p1;

                break;
        }

        if (!(val) && !(dict) && !(arr)) {
            free(key);
            break;
        }

        if (!(res->nodes)) {
            res->nodes = res->tail = node = cli_calloc(1, sizeof(struct pdf_dict_node));
            if (!(node)) {
                free(key);
                if (dict)
                    pdf_free_dict(dict);
                if (val)
                    free(val);
                if (arr)
                    pdf_free_array(arr);
                break;
            }
        } else {
            node = calloc(1, sizeof(struct pdf_dict_node));
            if (!(node)) {
                free(key);
                if (dict)
                    pdf_free_dict(dict);
                if (val)
                    free(val);
                if (arr)
                    pdf_free_array(arr);
                break;
            }

            node->prev = res->tail;
            if (res->tail)
                res->tail->next = node;
            res->tail = node;
        }

        node->key = key;
        if ((val)) {
            node->value = val;
            node->valuesz = strlen(val);
            node->type = PDF_DICT_STRING;
        } else if ((arr)) {
            node->value = arr;
            node->valuesz = sizeof(struct pdf_array);
            node->type = PDF_DICT_ARRAY;
        } else if ((dict)) {
            node->value = dict;
            node->valuesz = sizeof(struct pdf_dict);
            node->type = PDF_DICT_DICT;
        }
    }

    if (endchar)
        *endchar = end;

    return res;
}

struct pdf_array *pdf_parse_array(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsize, char *begin, char **endchar)
{
    struct pdf_array *res=NULL;
    struct pdf_array_node *node=NULL;
    const char *objstart;
    char *end;
    int in_string=0, ninner=0;

    /* Sanity checking */
    if (!(pdf) || !(obj) || !(begin))
        return NULL;

    objstart = (obj->objstm) ? (const char *)(obj->start + obj->objstm->streambuf)
                             : (const char *)(obj->start + pdf->map);

    if (begin < objstart || (size_t)(begin - objstart) >= objsize)
        return NULL;

    if (begin[0] != '[')
        return NULL;

    /* Find the end of the array */
    end = begin;
    while ((size_t)(end - objstart) < objsize) {
        if (in_string) {
            if (*end == '\\') {
                end += 2;
                continue;
            }

            if (*end == ')')
                in_string = 0;

            end++;
            continue;
        }

        switch (*end) {
            case '(':
                in_string=1;
                break;
            case '[':
                ninner++;
                break;
            case ']':
                ninner--;
                break;
        }

        if (*end == ']' && ninner == 0)
            break;

        end++;
    }

    /* More sanity checking */
    if ((size_t)(end - objstart) >= objsize)
        return NULL;

    if (*end != ']')
        return NULL;

    res = cli_calloc(1, sizeof(struct pdf_array));
    if (!(res))
        return NULL;

    begin++;
    while (begin < end) {
        char *val=NULL, *p1;
        struct pdf_array *arr=NULL;
        struct pdf_dict *dict=NULL;

        while (begin < end && isspace(begin[0]))
            begin++;

        if (begin == end)
            break;

        switch (begin[0]) {
            case '<':
                if ((size_t)(begin - objstart) < objsize - 2 && begin[1] == '<') {
                    dict = pdf_parse_dict(pdf, obj, end - objstart, begin, &begin);
                    begin+=2;
                    break;
                }

                /* Not a dictionary. Intentionally fall through. */
            case '(':
                val = pdf_parse_string(pdf, obj, begin, end - objstart, NULL, &begin, NULL);
                begin += 2;
                break;
            case '[':
                /* XXX We should have a recursion counter here */
                arr = pdf_parse_array(pdf, obj, end - objstart, begin, &begin);
                begin+=1;
                break;
            default:
                p1 = end;
                if (!is_object_reference(begin, &p1, NULL)) {
                    p1 = begin+1;
                    while (p1 < end && !isspace(p1[0]))
                        p1++;
                }

                val = cli_calloc((p1 - begin) + 2, 1);
                if (!(val))
                    break;

                strncpy(val, begin, p1 - begin);
                val[p1 - begin] = '\0';

                begin = p1;
                break;
        }

        /* Parse error, just return what we could */
        if (!(val) && !(arr) && !(dict))
            break;

        if (!(node)) {
            res->nodes = res->tail = node = calloc(1, sizeof(struct pdf_array_node));
            if (!(node)) {
                if (dict)
                    pdf_free_dict(dict);
                if (val)
                    free(val);
                if (arr)
                    pdf_free_array(arr);

                break;
            }
        } else {
            node = calloc(1, sizeof(struct pdf_array_node));
            if (!(node)) {
                if (dict)
                    pdf_free_dict(dict);
                if (val)
                    free(val);
                if (arr)
                    pdf_free_array(arr);

                break;
            }

            node->prev = res->tail;
            if (res->tail)
                res->tail->next = node;
            res->tail = node;
        }

        if (val != NULL) {
            node->type = PDF_ARR_STRING;
            node->data = val;
            node->datasz = strlen(val);
        } else if (dict != NULL) {
            node->type = PDF_ARR_DICT;
            node->data = dict;
            node->datasz = sizeof(struct pdf_dict);
        } else {
            node->type = PDF_ARR_ARRAY;
            node->data = arr;
            node->datasz = sizeof(struct pdf_array);
        }
    }

    if (endchar)
        *endchar = end;

    return res;
}

void pdf_free_dict(struct pdf_dict *dict)
{
    struct pdf_dict_node *node, *next;

    node = dict->nodes;
    while (node != NULL) {
        free(node->key);

        if (node->type == PDF_DICT_STRING)
            free(node->value);
        else if (node->type == PDF_DICT_ARRAY)
            pdf_free_array((struct pdf_array *)(node->value));
        else if (node->type == PDF_DICT_DICT)
            pdf_free_dict((struct pdf_dict *)(node->value));

        next = node->next;
        free(node);
        node = next;
    }

    free(dict);
}

void pdf_free_array(struct pdf_array *array)
{
    struct pdf_array_node *node, *next;

    if (!(array))
        return;

    node = array->nodes;
    while (node != NULL) {
        if (node->type == PDF_ARR_ARRAY)
            pdf_free_array((struct pdf_array *)(node->data));
        else if (node->type == PDF_ARR_DICT)
            pdf_free_dict((struct pdf_dict *)(node->data));
        else
            free(node->data);

        next = node->next;
        free(node);
        node = next;
    }

    free(array);
}

void pdf_print_array(struct pdf_array *array, unsigned long depth)
{
    struct pdf_array_node *node;
    unsigned long i;

    for (i=0, node = array->nodes; node != NULL; node = node->next, i++) {
        if (node->type == PDF_ARR_STRING)
            cli_errmsg("array[%lu][%lu]: %s\n", depth, i, (char *)(node->data));
        else
            pdf_print_array((struct pdf_array *)(node->data), depth+1);
    }
}

void pdf_print_dict(struct pdf_dict *dict, unsigned long depth)
{
    struct pdf_dict_node *node;

    for (node = dict->nodes; node != NULL; node = node->next) {
        if (node->type == PDF_DICT_STRING) {
            cli_errmsg("dict[%lu][%s]: %s\n", depth, node->key, (char *)(node->value));
        } else if (node->type == PDF_DICT_ARRAY) {
            cli_errmsg("dict[%lu][%s]: Array =>\n", depth, node->key);
            pdf_print_array((struct pdf_array *)(node->value), depth);
        } else if (node->type == PDF_DICT_DICT) {
            pdf_print_dict((struct pdf_dict *)(node->value), depth+1);
        }
    }
}
