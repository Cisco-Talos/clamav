/*
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2014 Cisco Systems, Inc. All rights reserved.
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
 */
#ifndef __PDF_H
#define __PDF_H

#include "others.h"
struct pdf_obj {
    uint32_t start;
    uint32_t id;
    uint32_t flags;
    uint32_t statsflags;
    char *path;
};

enum pdf_array_type { PDF_ARR_UNKNOWN=0, PDF_ARR_STRING, PDF_ARR_ARRAY, PDF_ARR_DICT };
enum pdf_dict_type { PDF_DICT_UNKNOWN=0, PDF_DICT_STRING, PDF_DICT_ARRAY, PDF_DICT_DICT };

struct pdf_array_node {
    void *data;
    size_t datasz;
    enum pdf_array_type type;

    struct pdf_array_node *prev;
    struct pdf_array_node *next;
};

struct pdf_array {
    struct pdf_array_node *nodes;
    struct pdf_array_node *tail;
};

struct pdf_dict_node {
    char *key;
    void *value;
    size_t valuesz;
    enum pdf_dict_type type;

    struct pdf_dict_node *prev;
    struct pdf_dict_node *next;
};

struct pdf_dict {
    struct pdf_dict_node *nodes;
    struct pdf_dict_node *tail;
};

struct pdf_stats {
    int32_t ninvalidobjs;     /* Number of invalid objects */
    int32_t njs;              /* Number of javascript objects */
    int32_t nflate;           /* Number of flate-encoded objects */
    int32_t nactivex;         /* Number of ActiveX objects */
    int32_t nflash;           /* Number of flash objects */
    int32_t ncolors;          /* Number of colors */
    int32_t nasciihexdecode;  /* Number of ASCIIHexDecode-filtered objects */
    int32_t nascii85decode;   /* Number of ASCII85Decode-filtered objects */
    int32_t nembeddedfile;    /* Number of embedded files */
    int32_t nimage;           /* Number of image objects */
    int32_t nlzw;             /* Number of LZW-filtered objects */
    int32_t nrunlengthdecode; /* Number of RunLengthDecode-filtered objects */
    int32_t nfaxdecode;       /* Number of CCITT-filtered objects */
    int32_t njbig2decode;     /* Number of JBIG2Decode-filtered objects */
    int32_t ndctdecode;       /* Number of DCTDecode-filtered objects */
    int32_t njpxdecode;       /* Number of JPXDecode-filtered objects */
    int32_t ncrypt;           /* Number of Crypt-filtered objects */
    int32_t nstandard;        /* Number of Standard-filtered objects */
    int32_t nsigned;          /* Number of Signed objects */
    int32_t nopenaction;      /* Number of OpenAction objects */
    int32_t nlaunch;          /* Number of Launch objects */
    int32_t npage;            /* Number of Page objects */
    int32_t nrichmedia;       /* Number of RichMedia objects */
    int32_t nacroform;        /* Number of AcroForm objects */
    int32_t nxfa;             /* Number of XFA objects */
    char *author;             /* Author of the PDF */
    char *creator;            /* Application used to create the PDF */
    char *producer;           /* Application used to produce the PDF */
    char *creationdate;       /* Date the PDF was created */
    char *modificationdate;   /* Date the PDF was modified */
    char *title;              /* Title of the PDF */
    char *subject;            /* Subject of the PDF */
    char *keywords;           /* Keywords of the PDF */
};


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
    struct pdf_stats stats;
};

#define OBJ_FLAG_PDFNAME_NONE 0x0
#define OBJ_FLAG_PDFNAME_DONE 0x1

#define PDF_EXTRACT_OBJ_NONE 0x0
#define PDF_EXTRACT_OBJ_SCAN 0x1

int cli_pdf(const char *dir, cli_ctx *ctx, off_t offset);
void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj);
int pdf_extract_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t flags);
int pdf_findobj(struct pdf_struct *pdf);
struct pdf_obj *find_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t objid);

char *pdf_parse_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *objstart, size_t objsize, const char *str, char **endchar);
struct pdf_array *pdf_parse_array(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsz, char *begin, char **endchar);
struct pdf_dict *pdf_parse_dict(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsz, char *begin, char **endchar);
int is_object_reference(char *begin, char **endchar, uint32_t *id);
void pdf_free_dict(struct pdf_dict *dict);
void pdf_free_array(struct pdf_array *array);
void pdf_print_dict(struct pdf_dict *dict, unsigned long depth);
void pdf_print_array(struct pdf_array *array, unsigned long depth);

#endif
