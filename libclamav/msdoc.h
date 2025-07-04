/*
 *  Extract component parts of OLE2 files (e.g. MS Office Documents)
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Kevin Lin
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

#ifndef __MSDOC_H
#define __MSDOC_H

#include "others.h"
#include "uniq.h"

#define PROPCNTLIMIT 25
#define PROPSTRLIMIT 256 /* affects property strs, NOT sanitized strs (may result in a buffer allocating PROPSTRLIMIT*6) */
#define UTF16_MS "UTF-16LE"

#define sum16_endian_convert(v) le16_to_host((uint16_t)(v))
#define sum32_endian_convert(v) le32_to_host((uint32_t)(v))
#define sum64_endian_convert(v) le64_to_host((uint64_t)(v))

enum summary_pidsi {
    SPID_CODEPAGE     = 0x00000001,
    SPID_TITLE        = 0x00000002,
    SPID_SUBJECT      = 0x00000003,
    SPID_AUTHOR       = 0x00000004,
    SPID_KEYWORDS     = 0x00000005,
    SPID_COMMENTS     = 0x00000006,
    SPID_TEMPLATE     = 0x00000007,
    SPID_LASTAUTHOR   = 0x00000008,
    SPID_REVNUMBER    = 0x00000009,
    SPID_EDITTIME     = 0x0000000A,
    SPID_LASTPRINTED  = 0x0000000B,
    SPID_CREATEDTIME  = 0x0000000C,
    SPID_MODIFIEDTIME = 0x0000000D,
    SPID_PAGECOUNT    = 0x0000000E,
    SPID_WORDCOUNT    = 0x0000000F,
    SPID_CHARCOUNT    = 0x00000010,
    SPID_THUMBNAIL    = 0x00000011,
    SPID_APPNAME      = 0x00000012,
    SPID_SECURITY     = 0x00000013
};

enum docsum_pidsi {
    DSPID_CODEPAGE          = 0x00000001,
    DSPID_CATEGORY          = 0x00000002,
    DSPID_PRESFORMAT        = 0x00000003,
    DSPID_BYTECOUNT         = 0x00000004,
    DSPID_LINECOUNT         = 0x00000005,
    DSPID_PARCOUNT          = 0x00000006,
    DSPID_SLIDECOUNT        = 0x00000007,
    DSPID_NOTECOUNT         = 0x00000008,
    DSPID_HIDDENCOUNT       = 0x00000009,
    DSPID_MMCLIPCOUNT       = 0x0000000A,
    DSPID_SCALE             = 0x0000000B,
    DSPID_HEADINGPAIR       = 0x0000000C, /* VT_VARIANT | VT_VECTOR */
    DSPID_DOCPARTS          = 0x0000000D, /* VT_VECTOR | VT_LPSTR */
    DSPID_MANAGER           = 0x0000000E,
    DSPID_COMPANY           = 0x0000000F,
    DSPID_LINKSDIRTY        = 0x00000010,
    DSPID_CCHWITHSPACES     = 0x00000011,
    DSPID_SHAREDDOC         = 0x00000013, /* must be false */
    DSPID_LINKBASE          = 0x00000014, /* moved to user-defined */
    DSPID_HLINKS            = 0x00000015, /* moved to user-defined */
    DSPID_HYPERLINKSCHANGED = 0x00000016,
    DSPID_VERSION           = 0x00000017,
    DSPID_DIGSIG            = 0x00000018,
    DSPID_CONTENTTYPE       = 0x0000001A,
    DSPID_CONTENTSTATUS     = 0x0000001B,
    DSPID_LANGUAGE          = 0x0000001C,
    DSPID_DOCVERSION        = 0x0000001D
};

enum property_type {
    PT_EMPTY    = 0x0000,
    PT_NULL     = 0x0001,
    PT_INT16    = 0x0002,
    PT_INT32    = 0x0003,
    PT_FLOAT32  = 0x0004,
    PT_DOUBLE64 = 0x0005,
    PT_DATE     = 0x0007,
    PT_BSTR     = 0x0008,
    PT_BOOL     = 0x000B,
    PT_INT8v1   = 0x0010,
    PT_UINT8    = 0x0011,
    PT_UINT16   = 0x0012,
    PT_UINT32   = 0x0013,
    PT_INT64    = 0x0014,
    PT_UINT64   = 0x0015,
    PT_INT32v1  = 0x0016,
    PT_UINT32v1 = 0x0017,
    PT_LPSTR    = 0x001E,
    PT_LPWSTR   = 0x001F,
    PT_FILETIME = 0x0040,

    /* More Types not currently handled */
};

typedef struct summary_stub {
    uint16_t byte_order;
    uint16_t version;
    uint32_t system; /* implementation-specific */
    uint8_t CLSID[16];

    uint32_t num_propsets; /* 1 or 2 */
} summary_stub_t;

typedef struct propset_summary_entry {
    uint8_t FMTID[16];
    uint32_t offset;
} propset_entry_t;

/* error codes */
#define OLE2_SUMMARY_ERROR_TOOSMALL 0x00000001
#define OLE2_SUMMARY_ERROR_OOB 0x00000002
#define OLE2_SUMMARY_ERROR_DATABUF 0x00000004
#define OLE2_SUMMARY_ERROR_INVALID_ENTRY 0x00000008
#define OLE2_SUMMARY_LIMIT_PROPS 0x00000010
#define OLE2_SUMMARY_FLAG_TIMEOUT 0x00000020
#define OLE2_SUMMARY_FLAG_CODEPAGE 0x00000040
#define OLE2_SUMMARY_FLAG_UNKNOWN_PROPID 0x00000080
#define OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE 0x00000100
#define OLE2_SUMMARY_FLAG_TRUNC_STR 0x00000200

#define OLE2_CODEPAGE_ERROR_NOTFOUND 0x00000400
#define OLE2_CODEPAGE_ERROR_UNINITED 0x00000800
#define OLE2_CODEPAGE_ERROR_INVALID 0x00001000
#define OLE2_CODEPAGE_ERROR_INCOMPLETE 0x00002000
#define OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL 0x00002000

/* metadata structures */
typedef struct summary_ctx {
    cli_ctx *ctx;
    int mode;
    fmap_t *sfmap;
    json_object *summary;
    size_t maplen;
    uint32_t flags;

    /* propset metadata */
    uint32_t pssize; /* track from propset start, not tail start */
    uint16_t codepage;
    int writecp;

    /* property metadata */
    const char *propname;

    /* timeout meta */
    int toval;
} summary_ctx_t;

/* Summary and Document Information Parsing to JSON */
int cli_ole2_summary_json(cli_ctx *ctx, int fd, int mode, const char *filepath);

#endif /* __MSDOC_H_ */
