/*
 *  Extract component parts of OLE2 files (e.g. MS Office Documents)
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

/* Summary and Document Information Parsing to JSON */
#if HAVE_JSON

#define PROPCNTLIMIT 25
#define PROPSTRLIMIT 256 /* affects property strs, NOT sanitized strs (may result in a buffer allocating PROPSTRLIMIT*6) */
#define UTF16_MS "UTF-16LE"

#define sum16_endian_convert(v) le16_to_host((uint16_t)(v))
#define sum32_endian_convert(v) le32_to_host((uint32_t)(v))
#define sum64_endian_convert(v) le64_to_host((uint64_t)(v))

enum summary_pidsi {
    SPID_CODEPAGE   = 0x00000001,
    SPID_TITLE      = 0x00000002,
    SPID_SUBJECT    = 0x00000003,
    SPID_AUTHOR     = 0x00000004,
    SPID_KEYWORDS   = 0x00000005,
    SPID_COMMENTS   = 0x00000006,
    SPID_TEMPLATE   = 0x00000007,
    SPID_LASTAUTHOR = 0x00000008,
    SPID_REVNUMBER  = 0x00000009,
    SPID_EDITTIME   = 0x0000000A,
    SPID_LASTPRINTED  = 0x0000000B,
    SPID_CREATEDTIME  = 0x0000000C,
    SPID_MODIFIEDTIME = 0x0000000D,
    SPID_PAGECOUNT = 0x0000000E,
    SPID_WORDCOUNT = 0x0000000F,
    SPID_CHARCOUNT = 0x00000010,
    SPID_THUMBNAIL = 0x00000011,
    SPID_APPNAME   = 0x00000012,
    SPID_SECURITY  = 0x00000013
};

enum docsum_pidsi {
    DSPID_CODEPAGE    = 0x00000001,
    DSPID_CATEGORY    = 0x00000002,
    DSPID_PRESFORMAT  = 0x00000003,
    DSPID_BYTECOUNT   = 0x00000004,
    DSPID_LINECOUNT   = 0x00000005,
    DSPID_PARCOUNT    = 0x00000006,
    DSPID_SLIDECOUNT  = 0x00000007,
    DSPID_NOTECOUNT   = 0x00000008,
    DSPID_HIDDENCOUNT = 0x00000009,
    DSPID_MMCLIPCOUNT = 0x0000000A,
    DSPID_SCALE       = 0x0000000B,
    DSPID_HEADINGPAIR = 0x0000000C, /* VT_VARIANT | VT_VECTOR */
    DSPID_DOCPARTS    = 0x0000000D, /* VT_VECTOR | VT_LPSTR */
    DSPID_MANAGER     = 0x0000000E,
    DSPID_COMPANY     = 0x0000000F,
    DSPID_LINKSDIRTY  = 0x00000010,
    DSPID_CCHWITHSPACES = 0x00000011,
    DSPID_SHAREDDOC   = 0x00000013, /* must be false */
    DSPID_LINKBASE    = 0x00000014, /* moved to user-defined */
    DSPID_HLINKS      = 0x00000015, /* moved to user-defined */
    DSPID_HYPERLINKSCHANGED = 0x00000016,
    DSPID_VERSION     = 0x00000017,
    DSPID_DIGSIG      = 0x00000018,
    DSPID_CONTENTTYPE   = 0x0000001A,
    DSPID_CONTENTSTATUS = 0x0000001B,
    DSPID_LANGUAGE      = 0x0000001C,
    DSPID_DOCVERSION    = 0x0000001D
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
    PT_BOOL    = 0x000B,
    PT_INT8v1  = 0x0010,
    PT_UINT8   = 0x0011,
    PT_UINT16  = 0x0012,
    PT_UINT32  = 0x0013,
    PT_INT64   = 0x0014,
    PT_UINT64  = 0x0015,
    PT_INT32v1  = 0x0016,
    PT_UINT32v1 = 0x0017,
    PT_LPSTR  = 0x001E,
    PT_LPWSTR = 0x001F,
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
#define OLE2_SUMMARY_ERROR_TOOSMALL      0x00000001
#define OLE2_SUMMARY_ERROR_OOB           0x00000002
#define OLE2_SUMMARY_ERROR_DATABUF       0x00000004
#define OLE2_SUMMARY_ERROR_INVALID_ENTRY 0x00000008
#define OLE2_SUMMARY_LIMIT_PROPS         0x00000010
#define OLE2_SUMMARY_FLAG_TIMEOUT        0x00000020
#define OLE2_SUMMARY_FLAG_CODEPAGE       0x00000040
#define OLE2_SUMMARY_FLAG_UNKNOWN_PROPID 0x00000080
#define OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE 0x00000100
#define OLE2_SUMMARY_FLAG_TRUNC_STR      0x00000200

#define OLE2_CODEPAGE_ERROR_NOTFOUND     0x00000400
#define OLE2_CODEPAGE_ERROR_UNINITED     0x00000800
#define OLE2_CODEPAGE_ERROR_INVALID      0x00001000
#define OLE2_CODEPAGE_ERROR_INCOMPLETE   0x00002000
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

/* string conversion */
struct codepage_entry {
    uint16_t codepage;
    const char *encoding;
};

#define NUMCODEPAGES sizeof(codepage_entries)/sizeof(struct codepage_entry)
/* MAINTAIN - the array in codepage value sorted order */
static const struct codepage_entry codepage_entries[] = {
    { 37,    "IBM037" },      /* IBM EBCDIC US-Canada */
    { 437,   "IBM437" },      /* OEM United States */
    { 500,   "IBM500" },      /* IBM EBCDIC International */
    { 708,   "ASMO-708" },    /* Arabic (ASMO 708) */
    { 709,   NULL },          /* Arabic (ASMO-449+, BCON V4) */
    { 710,   NULL },          /* Arabic - Transparent Arabic */
    { 720,   NULL },          /* Arabic (Transparent ASMO); Arabic (DOS) */
    { 737,   NULL },          /* OEM Greek (formerly 437G); Greek (DOS) */
    { 775,   "IBM775" },      /* OEM Baltic; Baltic (DOS) */
    { 850,   "IBM850" },      /* OEM Multilingual Latin 1; Western European (DOS) */
    { 852,   "IBM852" },      /* OEM Latin 2; Central European (DOS) */
    { 855,   "IBM855" },      /* OEM Cyrillic (primarily Russian) */
    { 857,   "IBM857" },      /* OEM Turkish; Turkish (DOS) */
    { 858,   NULL },          /* OEM Multilingual Latin 1 + Euro symbol */
    { 860,   "IBM860" },      /* OEM Portuguese; Portuguese (DOS) */
    { 861,   "IBM861" },      /* OEM Icelandic; Icelandic (DOS) */
    { 862,   NULL },          /* OEM Hebrew; Hebrew (DOS) */
    { 863,   "IBM863" },      /* OEM French Canadian; French Canadian (DOS) */
    { 864,   "IBM864" },      /* OEM Arabic; Arabic (864) */
    { 865,   "IBM865" },      /* OEM Nordic; Nordic (DOS) */
    { 866,   "CP866" },       /* OEM Russian; Cyrillic (DOS) */
    { 869,   "IBM869" },      /* OEM Modern Greek; Greek, Modern (DOS) */
    { 870,   "IBM870" },      /* IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2 */
    { 874,   "WINDOWS-874" }, /* ANSI/OEM Thai (ISO 8859-11); Thai (Windows) */
    { 875,   "CP875" },       /* IBM EBCDIC Greek Modern */
    { 932,   "SHIFT_JIS" },   /* ANSI/OEM Japanese; Japanese (Shift-JIS) */
    { 936,   "GB2312" },      /* ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312) */
    { 949,   NULL },          /* ANSI/OEM Korean (Unified Hangul Code) */
    { 950,   "BIG5" },        /* ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5) */
    { 1026,  "IBM1026" },     /* IBM EBCDIC Turkish (Latin 5) */
    { 1047,  NULL },          /* IBM EBCDIC Latin 1/Open System */
    { 1140,  NULL },          /* IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro) */
    { 1141,  NULL },          /* IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro) */
    { 1142,  NULL },          /* IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro) */
    { 1143,  NULL },          /* IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro) */
    { 1144,  NULL },          /* IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro) */
    { 1145,  NULL },          /* IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro) */
    { 1146,  NULL },          /* IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro) */
    { 1147,  NULL },          /* IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro) */
    { 1148,  NULL },          /* IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro) */
    { 1149,  NULL },          /* IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro) */
    { 1200,  "UTF-16LE" },    /* Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications */
    { 1201,  "UTF-16BE" },    /* Unicode UTF-16, big endian byte order; available only to managed applications */
    { 1250,  "WINDOWS-1250" }, /* ANSI Central European; Central European (Windows) */
    { 1251,  "WINDOWS-1251" }, /* ANSI Cyrillic; Cyrillic (Windows) */
    { 1252,  "WINDOWS-1252" }, /* ANSI Latin 1; Western European (Windows) */
    { 1253,  "WINDOWS-1253" }, /* ANSI Greek; Greek (Windows) */
    { 1254,  "WINDOWS-1254" }, /* ANSI Turkish; Turkish (Windows) */
    { 1255,  "WINDOWS-1255" }, /* ANSI Hebrew; Hebrew (Windows) */
    { 1256,  "WINDOWS-1256" }, /* ANSI Arabic; Arabic (Windows) */
    { 1257,  "WINDOWS-1257" }, /* ANSI Baltic; Baltic (Windows) */
    { 1258,  "WINDOWS-1258" }, /* ANSI/OEM Vietnamese; Vietnamese (Windows) */
    { 1361,  "JOHAB" },       /* Korean (Johab) */
    { 10000, "MACINTOSH" },   /* MAC Roman; Western European (Mac) */
    { 10001, NULL },          /* Japanese (Mac) */
    { 10002, NULL },          /* MAC Traditional Chinese (Big5); Chinese Traditional (Mac) */
    { 10003, NULL },          /* Korean (Mac) */
    { 10004, NULL },          /* Arabic (Mac) */
    { 10005, NULL },          /* Hebrew (Mac) */
    { 10006, NULL },          /* Greek (Mac) */
    { 10007, NULL },          /* Cyrillic (Mac) */
    { 10008, NULL },          /* MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac) */
    { 10010, NULL },          /* Romanian (Mac) */
    { 10017, NULL },          /* Ukrainian (Mac) */
    { 10021, NULL },          /* Thai (Mac) */
    { 10029, NULL },          /* MAC Latin 2; Central European (Mac) */
    { 10079, NULL },          /* Icelandic (Mac) */
    { 10081, NULL },          /* Turkish (Mac) */
    { 10082, NULL },          /* Croatian (Mac) */
    { 12000, "UTF-32LE" },    /* Unicode UTF-32, little endian byte order; available only to managed applications */
    { 12001, "UTF-32BE" },    /* Unicode UTF-32, big endian byte order; available only to managed applications */
    { 20000, NULL },          /* CNS Taiwan; Chinese Traditional (CNS) */
    { 20001, NULL },          /* TCA Taiwan */
    { 20002, NULL },          /* Eten Taiwan; Chinese Traditional (Eten) */
    { 20003, NULL },          /* IBM5550 Taiwan */
    { 20004, NULL },          /* TeleText Taiwan */
    { 20005, NULL },          /* Wang Taiwan */
    { 20105, NULL },          /* IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5) */
    { 20106, NULL },          /* IA5 German (7-bit) */
    { 20107, NULL },          /* IA5 Swedish (7-bit) */
    { 20108, NULL },          /* IA5 Norwegian (7-bit) */
    { 20127, "US-ASCII" },    /* US-ASCII (7-bit) */
    { 20261, NULL },          /* T.61 */
    { 20269, NULL },          /* ISO 6937 Non-Spacing Accent */
    { 20273, "IBM273" },      /* IBM EBCDIC Germany */
    { 20277, "IBM277" },      /* IBM EBCDIC Denmark-Norway */
    { 20278, "IBM278" },      /* IBM EBCDIC Finland-Sweden */
    { 20280, "IBM280" },      /* IBM EBCDIC Italy */
    { 20284, "IBM284" },      /* IBM EBCDIC Latin America-Spain */
    { 20285, "IBM285" },      /* IBM EBCDIC United Kingdom */
    { 20290, "IBM290" },      /* IBM EBCDIC Japanese Katakana Extended */
    { 20297, "IBM297" },      /* IBM EBCDIC France */
    { 20420, "IBM420" },      /* IBM EBCDIC Arabic */
    { 20423, "IBM423" },      /* IBM EBCDIC Greek */
    { 20424, "IBM424" },      /* IBM EBCDIC Hebrew */
    { 20833, NULL },          /* IBM EBCDIC Korean Extended */
    { 20838, NULL },          /* IBM EBCDIC Thai */
    { 20866, "KOI8-R" },      /* Russian (KOI8-R); Cyrillic (KOI8-R) */
    { 20871, "IBM871" },      /* IBM EBCDIC Icelandic */
    { 20880, "IBM880" },      /* IBM EBCDIC Cyrillic Russian */
    { 20905, "IBM905" },      /* IBM EBCDIC Turkish */
    { 20924, NULL },          /* IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) */
    { 20932, "EUC-JP" },      /* Japanese (JIS 0208-1990 and 0212-1990) */
    { 20936, NULL },          /* Simplified Chinese (GB2312); Chinese Simplified (GB2312-80) */
    { 20949, NULL },          /* Korean Wansung */
    { 21025, "CP1025" },      /* IBM EBCDIC Cyrillic Serbian-Bulgarian */
    { 21027, NULL },          /* (deprecated) */
    { 21866, "KOI8-U" },      /* Ukrainian (KOI8-U); Cyrillic (KOI8-U) */
    { 28591, "ISO-8859-1" },  /* ISO 8859-1 Latin 1; Western European (ISO) */
    { 28592, "ISO-8859-2" },  /* ISO 8859-2 Central European; Central European (ISO) */
    { 28593, "ISO-8859-3" },  /* ISO 8859-3 Latin 3 */
    { 28594, "ISO-8859-4" },  /* ISO 8859-4 Baltic */
    { 28595, "ISO-8859-5" },  /* ISO 8859-5 Cyrillic */
    { 28596, "ISO-8859-6" },  /* ISO 8859-6 Arabic */
    { 28597, "ISO-8859-7" },  /* ISO 8859-7 Greek */
    { 28598, "ISO-8859-8" },  /* ISO 8859-8 Hebrew; Hebrew (ISO-Visual) */
    { 28599, "ISO-8859-9" },  /* ISO 8859-9 Turkish */
    { 28603, "ISO-8859-13" }, /* ISO 8859-13 Estonian */
    { 28605, "ISO-8859-15" }, /* ISO 8859-15 Latin 9 */
    { 29001, NULL },          /* Europa 3 */
    { 38598, NULL },          /* ISO 8859-8 Hebrew; Hebrew (ISO-Logical) */
    { 50220, "ISO-2022-JP" },   /* ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS) (guess) */
    { 50221, "ISO-2022-JP-2" }, /* ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana) (guess) */
    { 50222, "ISO-2022-JP-3" }, /* ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI) (guess) */
    { 50225, "ISO-2022-KR" }, /* ISO 2022 Korean */
    { 50227, NULL },          /* ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022) */
    { 50229, NULL },          /* ISO 2022 Traditional Chinese */
    { 50930, NULL },          /* EBCDIC Japanese (Katakana) Extended */
    { 50931, NULL },          /* EBCDIC US-Canada and Japanese */
    { 50933, NULL },          /* EBCDIC Korean Extended and Korean */
    { 50935, NULL },          /* EBCDIC Simplified Chinese Extended and Simplified Chinese */
    { 50936, NULL },          /* EBCDIC Simplified Chinese */
    { 50937, NULL },          /* EBCDIC US-Canada and Traditional Chinese */
    { 50939, NULL },          /* EBCDIC Japanese (Latin) Extended and Japanese */
    { 51932, "EUC-JP" },      /* EUC Japanese */
    { 51936, "EUC-CN" },      /* EUC Simplified Chinese; Chinese Simplified (EUC) */
    { 51949, "EUC-KR" },      /* EUC Korean */
    { 51950, NULL },          /* EUC Traditional Chinese */
    { 52936, NULL },          /* HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ) */
    { 54936, "GB18030" },     /* Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030) */
    { 57002, NULL },          /* ISCII Devanagari */
    { 57003, NULL },          /* ISCII Bengali */
    { 57004, NULL },          /* ISCII Tamil */
    { 57005, NULL },          /* ISCII Telugu */
    { 57006, NULL },          /* ISCII Assamese */
    { 57007, NULL },          /* ISCII Oriya */
    { 57008, NULL },          /* ISCII Kannada */
    { 57009, NULL },          /* ISCII Malayalam */
    { 57010, NULL },          /* ISCII Gujarati */
    { 57011, NULL },          /* ISCII Punjabi */
    { 65000, "UTF-7" },       /* Unicode (UTF-7) */
    { 65001, "UTF-8" }        /* Unicode (UTF-8) */
};

int cli_ole2_summary_json(cli_ctx *ctx, int fd, int mode);
#endif /* HAVE_JSON */

#endif /* __MSDOC_H_ */
