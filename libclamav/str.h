/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Nigel Horne, Török Edvin
 * 
 *  Acknowledgements: cli_strcasestr() contains a public domain code from:
 *                    http://unixpapa.com/incnote/string.html
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

#ifndef __STR_H
#define __STR_H

#include <ctype.h>
#include <sys/types.h>
#include <limits.h>

#include "clamav.h"
#include "clamav.h"

#define SIZE_T_CHARLEN ( (sizeof(size_t) * CHAR_BIT + 2) / 3 + 1 )

#ifdef HAVE_STRCASESTR
#define cli_strcasestr strcasestr
#else
const char *cli_strcasestr(const char *haystack, const char *needle);
#endif

#if defined(HAVE_STRNDUP) && !defined(HAVE_STRNI)
#define cli_strndup strndup
#else
char *cli_strndup(const char *s, size_t n);
#endif

#if defined(HAVE_STRNLEN) && !defined(HAVE_STRNI)
#define cli_strnlen strnlen
#else
size_t cli_strnlen(const char *s, size_t n);
#endif

#if defined(HAVE_STRNSTR) && !defined(HAVE_STRNI)
#define cli_strnstr strnstr
#else
char *cli_strnstr(const char *s, const char *find, size_t slen);
#endif

#include <stdio.h>
#define cli_nocase(val) tolower(val)
#define cli_nocasei(val) toupper(val)

int cli_strbcasestr(const char *haystack, const char *needle);
int cli_chomp(char *string);
char *cli_strtok(const char *line, int field, const char *delim);
int cli_realhex2ui(const char *hex, uint16_t *ptr, unsigned int len);
uint16_t *cli_hex2ui(const char *hex);
int  cli_hex2str_to(const char *hex, char *ptr, size_t len);
char *cli_hex2str(const char *hex);
int cli_hex2num(const char *hex);
int cli_xtoi(const char *hex);
char *cli_str2hex(const char *string, unsigned int len);
char *cli_utf16toascii(const char *str, unsigned int length);
char *cli_strtokbuf(const char *input, int fieldno, const char *delim, char *output);
const char *cli_memstr(const char *haystack, size_t hs, const char *needle, size_t ns);
char *cli_strrcpy(char *dest, const char *source);
size_t cli_strtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens);
size_t cli_ldbtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens, int token_skip);
long cli_strntol(const char* nptr, size_t n, char** endptr, register int base);
unsigned long cli_strntoul(const char* nptr, size_t n, char** endptr, register int base);
cl_error_t cli_strntol_wrap(const char *buf, size_t buf_size, int fail_at_nondigit, int base, long *result);
cl_error_t cli_strntoul_wrap(const char *buf, size_t buf_size, int fail_at_nondigit, int base, unsigned long *result);
int cli_isnumber(const char *str);
char *cli_unescape(const char *str);
struct text_buffer;
int  cli_textbuffer_append_normalize(struct text_buffer *buf, const char *str, size_t len);
int cli_hexnibbles(char *str, int len);

typedef enum {
    UTF16_BE, /* Force big endian */
    UTF16_LE, /* Force little endian */
    UTF16_BOM /* Use BOM if available otherwise assume big endian */
} utf16_type;
char *cli_utf16_to_utf8(const char *utf16, size_t length, utf16_type type);

int cli_isutf8(const char *buf, unsigned int len);

size_t cli_strlcat(char *dst, const char *src, size_t sz); /* libclamav/strlcat.c */

/**
 * @brief   Get the file basename including extension from a file path.
 * 
 * Caller is responsible for freeing filebase.
 * An empty string will be returned if the caller inputs a directory with a trailing slash (no file).
 * 
 * @param filepath      The filepath in question.
 * @param[out] filebase An allocated string containing the file basename.
 * @return cl_error_t   CL_SUCCESS, CL_EARG, CL_EFORMAT, or CL_EMEM
 */
cl_error_t cli_basename(const char *filepath, size_t filepath_len, char **filebase);

#endif
