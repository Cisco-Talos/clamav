/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#define SIZE_T_CHARLEN ((sizeof(size_t) * CHAR_BIT + 2) / 3 + 1)

#ifdef HAVE_STRCASESTR
#define CLI_STRCASESTR strcasestr
#else
#define CLI_STRCASESTR __cli_strcasestr
#endif

#if defined(HAVE_STRNDUP) && !defined(HAVE_STRNI)
#define CLI_STRNDUP strndup
#else
#define CLI_STRNDUP __cli_strndup
#endif

#if defined(HAVE_STRNLEN) && !defined(HAVE_STRNI)
#define CLI_STRNLEN strnlen
#else
#define CLI_STRNLEN __cli_strnlen
#endif

#if defined(HAVE_STRNSTR) && !defined(HAVE_STRNI)
#define CLI_STRNSTR strnstr
#else
#define CLI_STRNSTR __cli_strnstr
#endif

#include <stdio.h>
#define CLI_NOCASE(val) tolower(val)
#define CLI_NOCASEI(val) toupper(val)

/* Custom implementations for systems that do not include these functions. */
const char *__cli_strcasestr(const char *haystack, const char *needle);
char *__cli_strndup(const char *s, size_t n);
size_t __cli_strnlen(const char *s, size_t n);
char *__cli_strnstr(const char *s, const char *find, size_t slen);

/* Custom string-manipulation functions */
int cli_strbcasestr(const char *haystack, const char *needle);
int cli_chomp(char *string);
char *cli_strtok(const char *line, int field, const char *delim);
int cli_realhex2ui(const char *hex, uint16_t *ptr, unsigned int len);
uint16_t *cli_hex2ui(const char *hex);
int cli_hex2str_to(const char *hex, char *ptr, size_t len);
char *cli_hex2str(const char *hex);
int cli_hex2num(const char *hex);
int cli_xtoi(const char *hex);
char *cli_str2hex(const char *string, unsigned int len);
char *cli_strtokbuf(const char *input, int fieldno, const char *delim, char *output);
const char *cli_memstr(const char *haystack, size_t hs, const char *needle, size_t ns);
char *cli_strrcpy(char *dest, const char *source);
size_t cli_strtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens);
size_t cli_ldbtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens, size_t token_skip);
long cli_strntol(const char *nptr, size_t n, char **endptr, register int base);
unsigned long cli_strntoul(const char *nptr, size_t n, char **endptr, register int base);
cl_error_t cli_strntol_wrap(const char *buf, size_t buf_size, int fail_at_nondigit, int base, long *result);
cl_error_t cli_strntoul_wrap(const char *buf, size_t buf_size, int fail_at_nondigit, int base, unsigned long *result);
int cli_isnumber(const char *str);
char *cli_unescape(const char *str);
struct text_buffer;
int cli_textbuffer_append_normalize(struct text_buffer *buf, const char *str, size_t len);
int cli_hexnibbles(char *str, int len);

size_t cli_strlcat(char *dst, const char *src, size_t sz); /* libclamav/strlcat.c */

/**
 * @brief Get the file basename including extension from a file path.
 *
 * Will treat both '/' and '\' as path separators.
 *
 * Caller is responsible for freeing filebase.
 * An empty string will be returned if the caller inputs a directory with a trailing slash (no file).
 *
 * @param filepath      The filepath in question.
 * @param[out] filebase An allocated string containing the file basename.
 * @param posix_support_backslash_pathsep Whether to treat backslashes as path separators on Linux/Unix systems.
 *
 * @return cl_error_t   CL_SUCCESS, CL_EARG, CL_EFORMAT, or CL_EMEM
 */
cl_error_t cli_basename(
    const char *filepath,
    size_t filepath_len,
    char **filebase,
    bool posix_support_backslash_pathsep);

/**
 * @brief Convert a hex string to an appropriately sized byte array.
 *
 * @param hexstr   The input hex string (not null-terminated, length must be even).
 * @param hexlen   The length of the hex string.
 * @param outbuf   The output buffer (must be at least hexlen/2 bytes).
 * @return CL_SUCCESS on success, CL_EFORMAT on error.
 */
cl_error_t cli_hexstr_to_bytes(const char *hexstr, size_t hexlen, uint8_t *outbuf);

#endif
