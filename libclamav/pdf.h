/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#define PDF_FILTERLIST_MAX  64

struct objstm_struct {
    uint32_t first;         // offset of first obj
    uint32_t current;       // offset of current obj
    uint32_t current_pair;  // offset of current pair describing id, location of object
    uint32_t length;        // total length of all objects (starting at first)
    uint32_t n;             // number of objects that should be found in the object stream
    uint32_t nobjs_found;   // number of objects actually found in the object stream
    char *streambuf;        // address of stream buffer, beginning with first obj pair
    size_t streambuf_len;   // length of stream buffer, includes pairs followed by actual objects
};

struct pdf_obj {
    uint32_t start;
    size_t size;
    uint32_t id;
    uint32_t flags;
    uint32_t statsflags;
    uint32_t numfilters;
    uint32_t filterlist[PDF_FILTERLIST_MAX];
    const char *stream;     // pointer to stream contained in object.
    size_t stream_size;      // size of stream contained in object.
    struct objstm_struct *objstm;  // Should be NULL unless the obj exists in an object stream (separate buffer)
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

struct pdf_stats_entry {
    char *data;

    /* populated by pdf_parse_string */
    struct pdf_stats_metadata {
        int length;
        struct pdf_obj *obj;
        int success; /* if finalize succeeds */
    } meta;
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
    struct pdf_stats_entry *author;             /* Author of the PDF */
    struct pdf_stats_entry *creator;            /* Application used to create the PDF */
    struct pdf_stats_entry *producer;           /* Application used to produce the PDF */
    struct pdf_stats_entry *creationdate;       /* Date the PDF was created */
    struct pdf_stats_entry *modificationdate;   /* Date the PDF was modified */
    struct pdf_stats_entry *title;              /* Title of the PDF */
    struct pdf_stats_entry *subject;            /* Subject of the PDF */
    struct pdf_stats_entry *keywords;           /* Keywords of the PDF */
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
    struct pdf_obj **objs;
    unsigned nobjs;
    unsigned flags;
    unsigned enc_method_stream;
    unsigned enc_method_string;
    unsigned enc_method_embeddedfile;
    const char *CF;
    long CF_n;
    const char *map;
    size_t size;
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
    struct objstm_struct **objstms;
    uint32_t nobjstms;
};

#define OBJ_FLAG_PDFNAME_NONE 0x0
#define OBJ_FLAG_PDFNAME_DONE 0x1

#define PDF_EXTRACT_OBJ_NONE 0x0
#define PDF_EXTRACT_OBJ_SCAN 0x1

int cli_pdf(const char *dir, cli_ctx *ctx, off_t offset);
void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj);
int pdf_extract_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t flags);
cl_error_t pdf_findobj(struct pdf_struct *pdf);
struct pdf_obj *find_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t objid);

void pdf_handle_enc(struct pdf_struct *pdf);
char *decrypt_any(struct pdf_struct *pdf, uint32_t id, const char *in, size_t *length, enum enc_method enc_method);
enum enc_method get_enc_method(struct pdf_struct *pdf, struct pdf_obj *obj);
enum enc_method parse_enc_method(const char *dict, unsigned len, const char *key, enum enc_method def);

void pdfobj_flag(struct pdf_struct *pdf, struct pdf_obj *obj, enum pdf_flag flag);
char *pdf_finalize_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *in, size_t len);
char *pdf_parse_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *objstart, size_t objsize, const char *str, char **endchar, struct pdf_stats_metadata *meta);
struct pdf_array *pdf_parse_array(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsize, char *begin, char **endchar);
struct pdf_dict *pdf_parse_dict(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsize, char *begin, char **endchar);
int is_object_reference(char *begin, char **endchar, uint32_t *id);
void pdf_free_dict(struct pdf_dict *dict);
void pdf_free_array(struct pdf_array *array);
void pdf_print_dict(struct pdf_dict *dict, unsigned long depth);
void pdf_print_array(struct pdf_array *array, unsigned long depth);

cl_error_t pdf_find_and_extract_objs(struct pdf_struct *pdf, uint32_t *alerts);
cl_error_t pdf_find_and_parse_objs_in_objstm(struct pdf_struct *pdf, struct objstm_struct *objstm);

#endif
