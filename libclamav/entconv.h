/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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

#ifndef _ENTITIES_H
#define _ENTITIES_H

#include "clamav-config.h"

#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav-types.h"
#include "hashtab.h"
#include "htmlnorm.h"

// clang-format off
#define UCS4_1234           "UCS-4BE"
#define UCS4_4321           "UCS-4LE"
#define UCS4_2143           "UCS4"
#define UCS4_3412           "UCS-4"
#define UTF16_BE            "UTF-16BE"
#define UTF16_LE            "UTF-16LE"
#define UTF8                "UTF-8"
#define UNDECIDED_32_1234   UCS4_1234
#define UNDECIDED_32_4321   UCS4_4321
#define UNDECIDED_32_2143   UCS4_2143
#define UNDECIDED_32_3412   UCS4_3412
#define UNDECIDED_16_BE     UTF16_BE
#define UNDECIDED_16_LE     UTF16_LE
#define UNDECIDED_8         "ISO-8859-1"

#define CODEPAGE_JAPANESE_SHIFT_JIS 932     /* Japanese Shift-JIS */
#define CODEPAGE_KOREAN_UNIFIED     949     /* Korean Unified Code */
#define CODEPAGE_UTF16_LE           1200    /* UTF16 Little Endian */
#define CODEPAGE_UTF16_BE           1201    /* UTF16 Big Endian */
#define CODEPAGE_US_7BIT_ASCII      20127   /* US-ASCII (7-bit)  */
#define CODEPAGE_ISO8859_1          28591   /* ISO 8859-1 Latin 1; Western European (ISO) */
#define CODEPAGE_UTF8               65001   /* UTF-8 */
// clang-format on

/* string conversion */
struct codepage_entry {
    uint16_t codepage;
    const char* encoding;
};

#define NUMCODEPAGES (sizeof(codepage_entries) / sizeof(struct codepage_entry))
/* MAINTAIN - the array in codepage value sorted order */
static const struct codepage_entry codepage_entries[] = {
    {37, "IBM037"},           /* IBM EBCDIC US-Canada */
    {437, "IBM437"},          /* OEM United States */
    {500, "IBM500"},          /* IBM EBCDIC International */
    {708, "ASMO-708"},        /* Arabic (ASMO 708) */
    {709, NULL},              /* Arabic (ASMO-449+, BCON V4) */
    {710, NULL},              /* Arabic - Transparent Arabic */
    {720, NULL},              /* Arabic (Transparent ASMO); Arabic (DOS) */
    {737, NULL},              /* OEM Greek (formerly 437G); Greek (DOS) */
    {775, "IBM775"},          /* OEM Baltic; Baltic (DOS) */
    {850, "IBM850"},          /* OEM Multilingual Latin 1; Western European (DOS) */
    {852, "IBM852"},          /* OEM Latin 2; Central European (DOS) */
    {855, "IBM855"},          /* OEM Cyrillic (primarily Russian) */
    {857, "IBM857"},          /* OEM Turkish; Turkish (DOS) */
    {858, NULL},              /* OEM Multilingual Latin 1 + Euro symbol */
    {860, "IBM860"},          /* OEM Portuguese; Portuguese (DOS) */
    {861, "IBM861"},          /* OEM Icelandic; Icelandic (DOS) */
    {862, NULL},              /* OEM Hebrew; Hebrew (DOS) */
    {863, "IBM863"},          /* OEM French Canadian; French Canadian (DOS) */
    {864, "IBM864"},          /* OEM Arabic; Arabic (864) */
    {865, "IBM865"},          /* OEM Nordic; Nordic (DOS) */
    {866, "CP866"},           /* OEM Russian; Cyrillic (DOS) */
    {869, "IBM869"},          /* OEM Modern Greek; Greek, Modern (DOS) */
    {870, "IBM870"},          /* IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2 */
    {874, "WINDOWS-874"},     /* ANSI/OEM Thai (ISO 8859-11); Thai (Windows) */
    {875, "CP875"},           /* IBM EBCDIC Greek Modern */
    {932, "SHIFT_JIS"},       /* ANSI/OEM Japanese; Japanese (Shift-JIS) */
    {936, "GB2312"},          /* ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312) */
    {949, "CP949"},           /* ANSI/OEM Korean (Unified Hangul Code) */
    {950, "BIG5"},            /* ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5) */
    {1026, "IBM1026"},        /* IBM EBCDIC Turkish (Latin 5) */
    {1047, NULL},             /* IBM EBCDIC Latin 1/Open System */
    {1140, NULL},             /* IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro) */
    {1141, NULL},             /* IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro) */
    {1142, NULL},             /* IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro) */
    {1143, NULL},             /* IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro) */
    {1144, NULL},             /* IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro) */
    {1145, NULL},             /* IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro) */
    {1146, NULL},             /* IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro) */
    {1147, NULL},             /* IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro) */
    {1148, NULL},             /* IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro) */
    {1149, NULL},             /* IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro) */
    {1200, "UTF-16LE"},       /* Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications */
    {1201, "UTF-16BE"},       /* Unicode UTF-16, big endian byte order; available only to managed applications */
    {1250, "WINDOWS-1250"},   /* ANSI Central European; Central European (Windows) */
    {1251, "WINDOWS-1251"},   /* ANSI Cyrillic; Cyrillic (Windows) */
    {1252, "WINDOWS-1252"},   /* ANSI Latin 1; Western European (Windows) */
    {1253, "WINDOWS-1253"},   /* ANSI Greek; Greek (Windows) */
    {1254, "WINDOWS-1254"},   /* ANSI Turkish; Turkish (Windows) */
    {1255, "WINDOWS-1255"},   /* ANSI Hebrew; Hebrew (Windows) */
    {1256, "WINDOWS-1256"},   /* ANSI Arabic; Arabic (Windows) */
    {1257, "WINDOWS-1257"},   /* ANSI Baltic; Baltic (Windows) */
    {1258, "WINDOWS-1258"},   /* ANSI/OEM Vietnamese; Vietnamese (Windows) */
    {1361, "JOHAB"},          /* Korean (Johab) */
    {10000, "MACINTOSH"},     /* MAC Roman; Western European (Mac) */
    {10001, NULL},            /* Japanese (Mac) */
    {10002, NULL},            /* MAC Traditional Chinese (Big5); Chinese Traditional (Mac) */
    {10003, NULL},            /* Korean (Mac) */
    {10004, NULL},            /* Arabic (Mac) */
    {10005, NULL},            /* Hebrew (Mac) */
    {10006, NULL},            /* Greek (Mac) */
    {10007, NULL},            /* Cyrillic (Mac) */
    {10008, NULL},            /* MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac) */
    {10010, NULL},            /* Romanian (Mac) */
    {10017, NULL},            /* Ukrainian (Mac) */
    {10021, NULL},            /* Thai (Mac) */
    {10029, NULL},            /* MAC Latin 2; Central European (Mac) */
    {10079, NULL},            /* Icelandic (Mac) */
    {10081, NULL},            /* Turkish (Mac) */
    {10082, NULL},            /* Croatian (Mac) */
    {12000, "UTF-32LE"},      /* Unicode UTF-32, little endian byte order; available only to managed applications */
    {12001, "UTF-32BE"},      /* Unicode UTF-32, big endian byte order; available only to managed applications */
    {20000, NULL},            /* CNS Taiwan; Chinese Traditional (CNS) */
    {20001, NULL},            /* TCA Taiwan */
    {20002, NULL},            /* Eten Taiwan; Chinese Traditional (Eten) */
    {20003, NULL},            /* IBM5550 Taiwan */
    {20004, NULL},            /* TeleText Taiwan */
    {20005, NULL},            /* Wang Taiwan */
    {20105, NULL},            /* IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5) */
    {20106, NULL},            /* IA5 German (7-bit) */
    {20107, NULL},            /* IA5 Swedish (7-bit) */
    {20108, NULL},            /* IA5 Norwegian (7-bit) */
    {20127, "US-ASCII"},      /* US-ASCII (7-bit) */
    {20261, NULL},            /* T.61 */
    {20269, NULL},            /* ISO 6937 Non-Spacing Accent */
    {20273, "IBM273"},        /* IBM EBCDIC Germany */
    {20277, "IBM277"},        /* IBM EBCDIC Denmark-Norway */
    {20278, "IBM278"},        /* IBM EBCDIC Finland-Sweden */
    {20280, "IBM280"},        /* IBM EBCDIC Italy */
    {20284, "IBM284"},        /* IBM EBCDIC Latin America-Spain */
    {20285, "IBM285"},        /* IBM EBCDIC United Kingdom */
    {20290, "IBM290"},        /* IBM EBCDIC Japanese Katakana Extended */
    {20297, "IBM297"},        /* IBM EBCDIC France */
    {20420, "IBM420"},        /* IBM EBCDIC Arabic */
    {20423, "IBM423"},        /* IBM EBCDIC Greek */
    {20424, "IBM424"},        /* IBM EBCDIC Hebrew */
    {20833, NULL},            /* IBM EBCDIC Korean Extended */
    {20838, NULL},            /* IBM EBCDIC Thai */
    {20866, "KOI8-R"},        /* Russian (KOI8-R); Cyrillic (KOI8-R) */
    {20871, "IBM871"},        /* IBM EBCDIC Icelandic */
    {20880, "IBM880"},        /* IBM EBCDIC Cyrillic Russian */
    {20905, "IBM905"},        /* IBM EBCDIC Turkish */
    {20924, NULL},            /* IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) */
    {20932, "EUC-JP"},        /* Japanese (JIS 0208-1990 and 0212-1990) */
    {20936, NULL},            /* Simplified Chinese (GB2312); Chinese Simplified (GB2312-80) */
    {20949, NULL},            /* Korean Wansung */
    {21025, "CP1025"},        /* IBM EBCDIC Cyrillic Serbian-Bulgarian */
    {21027, NULL},            /* (deprecated) */
    {21866, "KOI8-U"},        /* Ukrainian (KOI8-U); Cyrillic (KOI8-U) */
    {28591, "ISO-8859-1"},    /* ISO 8859-1 Latin 1; Western European (ISO) */
    {28592, "ISO-8859-2"},    /* ISO 8859-2 Central European; Central European (ISO) */
    {28593, "ISO-8859-3"},    /* ISO 8859-3 Latin 3 */
    {28594, "ISO-8859-4"},    /* ISO 8859-4 Baltic */
    {28595, "ISO-8859-5"},    /* ISO 8859-5 Cyrillic */
    {28596, "ISO-8859-6"},    /* ISO 8859-6 Arabic */
    {28597, "ISO-8859-7"},    /* ISO 8859-7 Greek */
    {28598, "ISO-8859-8"},    /* ISO 8859-8 Hebrew; Hebrew (ISO-Visual) */
    {28599, "ISO-8859-9"},    /* ISO 8859-9 Turkish */
    {28603, "ISO-8859-13"},   /* ISO 8859-13 Estonian */
    {28605, "ISO-8859-15"},   /* ISO 8859-15 Latin 9 */
    {29001, NULL},            /* Europa 3 */
    {38598, NULL},            /* ISO 8859-8 Hebrew; Hebrew (ISO-Logical) */
    {50220, "ISO-2022-JP"},   /* ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS) (guess) */
    {50221, "ISO-2022-JP-2"}, /* ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana) (guess) */
    {50222, "ISO-2022-JP-3"}, /* ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI) (guess) */
    {50225, "ISO-2022-KR"},   /* ISO 2022 Korean */
    {50227, NULL},            /* ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022) */
    {50229, NULL},            /* ISO 2022 Traditional Chinese */
    {50930, NULL},            /* EBCDIC Japanese (Katakana) Extended */
    {50931, NULL},            /* EBCDIC US-Canada and Japanese */
    {50933, NULL},            /* EBCDIC Korean Extended and Korean */
    {50935, NULL},            /* EBCDIC Simplified Chinese Extended and Simplified Chinese */
    {50936, NULL},            /* EBCDIC Simplified Chinese */
    {50937, NULL},            /* EBCDIC US-Canada and Traditional Chinese */
    {50939, NULL},            /* EBCDIC Japanese (Latin) Extended and Japanese */
    {51932, "EUC-JP"},        /* EUC Japanese */
    {51936, "EUC-CN"},        /* EUC Simplified Chinese; Chinese Simplified (EUC) */
    {51949, "EUC-KR"},        /* EUC Korean */
    {51950, NULL},            /* EUC Traditional Chinese */
    {52936, NULL},            /* HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ) */
    {54936, "GB18030"},       /* Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030) */
    {57002, NULL},            /* ISCII Devanagari */
    {57003, NULL},            /* ISCII Bengali */
    {57004, NULL},            /* ISCII Tamil */
    {57005, NULL},            /* ISCII Telugu */
    {57006, NULL},            /* ISCII Assamese */
    {57007, NULL},            /* ISCII Oriya */
    {57008, NULL},            /* ISCII Kannada */
    {57009, NULL},            /* ISCII Malayalam */
    {57010, NULL},            /* ISCII Gujarati */
    {57011, NULL},            /* ISCII Punjabi */
    {65000, "UTF-7"},         /* Unicode (UTF-7) */
    {65001, "UTF-8"}          /* Unicode (UTF-8) */
};

#define MAX_ENTITY_SIZE 22

struct entity_conv {
    unsigned char entity_buff[MAX_ENTITY_SIZE + 2];
};

typedef enum encodings {
    E_UCS4,
    E_UTF16,
    E_UCS4_1234,
    E_UCS4_4321,
    E_UCS4_2143,
    E_UCS4_3412,
    E_UTF16_BE,
    E_UTF16_LE,
    E_UTF8,
    E_UNKNOWN,
    E_OTHER
} encoding_t;

unsigned char* u16_normalize_tobuffer(uint16_t u16, unsigned char* dst, size_t dst_size);
const char* entity_norm(struct entity_conv* conv, const unsigned char* entity);
const char* encoding_detect_bom(const unsigned char* bom, const size_t length);
int encoding_normalize_toascii(const m_area_t* in_m_area, const char* initial_encoding, m_area_t* out_m_area);

/**
 * @brief Convert string to UTF-8, given Windows codepage.
 *
 * @param in                string buffer
 * @param in_size           length of string buffer in bytes
 * @param codepage          Windows code page https://docs.microsoft.com/en-us/windows/desktop/Intl/code-page-identifiers)
 * @param[out] out          pointer to receive malloc'ed utf-8 buffer.
 * @param[out] out_size     pointer to receive size of utf-8 buffer, not including null terminating character.
 * @return cl_error_t       CL_SUCCESS if success. CL_BREAK if unable to because iconv is unavailable.  Other error code if outright failure.
 */
cl_error_t cli_codepage_to_utf8(char* in, size_t in_size, uint16_t codepage, char** out, size_t* out_size);

char* cli_utf16toascii(const char* str, unsigned int length);

char* cli_utf16_to_utf8(const char* utf16, size_t length, encoding_t type);

int cli_isutf8(const char* buf, unsigned int len);

#endif
