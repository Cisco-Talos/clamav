/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

char *pdf_convert_utf(char *begin, size_t sz)
{
    char *res=NULL;
#if HAVE_ICONV
    char *buf, *outbuf, *p1, *p2;
    size_t inlen, outlen, i;
    char *encodings[] = {
        "UTF-16",
        NULL
    };
    iconv_t cd;

    buf = cli_calloc(1, sz);
    if (!(buf))
        return NULL;

    memcpy(buf, begin, sz);
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
            cli_errmsg("Could not initialize iconv\n");
            continue;
        }

        iconv(cd, &p1, &inlen, &p2, &outlen);

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

    free(buf);
    free(outbuf);

    return res;
#else
    res = cli_calloc(begin, sz+1);
    if ((res)) {
        memcpy(res, begin, sz);
        res[sz] = '\0';
    }

    return res;
#endif
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

char *pdf_parse_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *objstart, size_t objsize, const char *str, char **endchar)
{
    const char *q = objstart;
    char *p1, *p2;
    size_t inlen, outlen, len, checklen;
    char *buf, *outbuf, *res;
    int likelyutf = 0;
    unsigned int i;
    uint32_t objid;

    /*
     * Yes, all of this is required to find the start and end of a potentially UTF-* string
     *
     * First, find the key of the key/value pair we're looking for in this object.
     * Second, determine whether the value points to another object (NOTE: this is sketchy behavior)
     * Third, attempt to determine if we're ASCII or UTF-*
     * If we're ASCII, just copy the ASCII string into a new heap-allocated string and return that
     * Fourth, Attempt to decode from UTF-* to UTF-8
     */

    res = NULL;

    if (str) {
        checklen = strlen(str);

        if (objsize < strlen(str) + 3)
            return NULL;

        for (p1=(char *)q; (p1 - q) < objsize-checklen; p1++)
            if (!strncmp(p1, str, checklen))
                break;

        if (p1 - q == objsize - checklen)
            return NULL;

        p1 += checklen;
    } else {
        p1 = q;
    }

    while ((p1 - q) < objsize && isspace(p1[0]))
        p1++;

    if ((p1 - q) == objsize)
        return NULL;

    /*
     * If str is non-null:
     *     We should be at the start of the string, minus 1
     * Else:
     *     We should be at the start of the string
     */

    p2 = q + objsize;
    if (is_object_reference(p1, &p2, &objid)) {
        struct pdf_obj *newobj;
        char *end, *begin;
        STATBUF sb;
        uint32_t objflags;
        int fd;

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
            begin = calloc(1, sb.st_size);
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

            switch (begin[0]) {
                case '(':
                case '<':
                    res = pdf_parse_string(pdf, obj, begin, sb.st_size, NULL, NULL);
                    free(begin);
                    break;
                default:
                    res = pdf_convert_utf(begin, sb.st_size);
                    if (!(res))
                        res = begin;
                    else
                        free(begin);
            }
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
        size_t sz;

        /* Hex string */

        p2 = p1+1;
        while ((p2 - q) < objsize && *p2 != '>')
            p2++;

        if (p2 - q == objsize) {
            return NULL;
        }

        res = cli_calloc(1, (p2 - p1) + 2);
        if (!(res))
            return NULL;

        strncpy(res, p1, (p2 - p1) + 1);
        if (endchar)
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

        if (!likelyutf && (*((unsigned char *)p2) > (unsigned char)0x7f || *p2 == '\0'))
            likelyutf = 1;

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

    if (p2 == objstart + objsize)
        return NULL;

    len = (size_t)(p2 - p1) + 1;

    if (likelyutf == 0) {
        /* We're not UTF-*, so just make a copy of the string and return that */
        res = cli_calloc(1, len+1);
        if (!(res))
            return NULL;

        memcpy(res, p1, len);
        res[len] = '\0';
        if (endchar)
            *endchar = p2;

        return res;
    }

    res = pdf_convert_utf(p1, len);

    if (res && endchar)
        *endchar = p2;

    return res;
}

struct pdf_dict *pdf_parse_dict(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsz, char *begin, char **endchar)
{
    struct pdf_dict *res=NULL;
    struct pdf_dict_node *node=NULL;
    const char *objstart;
    char *end;
    unsigned int in_string=0, ninner=0;

    /* Sanity checking */
    if (!(pdf) || !(obj) || !(begin))
        return NULL;

    objstart = (const char *)(obj->start + pdf->map);

    if (begin < objstart || begin - objstart >= objsz - 2)
        return NULL;

    if (begin[0] != '<' || begin[1] != '<')
        return NULL;

    /* Find the end of the dictionary */
    end = begin;
    while (end - objstart < objsz) {
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
                if (end - objstart <= objsz - 2 && end[1] == '<')
                    ninner++;
                increment=2;
                break;
            case '>':
                if (end - objstart <= objsz - 2 && end[1] == '>')
                    ninner--;
                increment=2;
                break;
        }

        if (end - objstart <= objsz - 2)
            if (end[0] == '>' && end[1] == '>' && ninner == 0)
                break;

        end += increment;
    }

    /* More sanity checking */
    if (end - objstart >= objsz - 2)
        return NULL;

    if (end[0] != '>' || end[1] != '>')
        return NULL;

    res = cli_calloc(1, sizeof(struct pdf_dict));
    if (!(res))
        return NULL;

    /* Loop through each element of the dictionary */
    begin += 2;
    while (begin < end) {
        char *val=NULL, *key=NULL, *p1;
        struct pdf_dict *dict=NULL;
        struct pdf_array *arr=NULL;

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
                case '\\':
                    breakout=1;
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

        strncpy(key, begin, p1 - begin);
        key[p1 - begin] = '\0';

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
                val = pdf_parse_string(pdf, obj, begin, objsz, NULL, &p1);
                begin = p1+2;
                break;
            case '[':
                arr = pdf_parse_array(pdf, obj, objsz, begin, &p1);
                begin = p1+1;
                break;
            case '<':
                if (begin - objstart < objsz - 2) {
                    if (begin[1] == '<') {
                        dict = pdf_parse_dict(pdf, obj, objsz, begin, &p1);
                        begin = p1+2;
                        break;
                    }
                }

                val = pdf_parse_string(pdf, obj, begin, objsz, NULL, &p1);
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

struct pdf_array *pdf_parse_array(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsz, char *begin, char **endchar)
{
    struct pdf_array *res=NULL;
    struct pdf_array_node *node=NULL;
    const char *objstart;
    char *end, *tempend;
    int in_string=0, ninner=0;

    /* Sanity checking */
    if (!(pdf) || !(obj) || !(begin))
        return NULL;

    objstart = obj->start + pdf->map;

    if (begin < objstart || begin - objstart >= objsz)
        return NULL;

    if (begin[0] != '[')
        return NULL;

    /* Find the end of the array */
    end = begin;
    while (end - objstart < objsz) {
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
    if (end - objstart == objsz)
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
                if (begin - objstart < objsz - 2 && begin[1] == '<') {
                    dict = pdf_parse_dict(pdf, obj, objsz, begin, &begin);
                    begin+=2;
                    break;
                }

                /* Not a dictionary. Intentially fall through. */
            case '(':
                val = pdf_parse_string(pdf, obj, begin, objsz, NULL, &begin);
                begin += 2;
                break;
            case '[':
                /* XXX We should have a recursion counter here */
                arr = pdf_parse_array(pdf, obj, objsz, begin, &begin);
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
