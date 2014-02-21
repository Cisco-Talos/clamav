/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Nigel Horne, Török Edvin
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "cltypes.h"
#include "jsparse/textbuf.h"

static const int hex_chars[256] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
};

static inline int cli_hex2int(const char c)
{
	return hex_chars[(const unsigned char)c];
}


int cli_realhex2ui(const char *hex, uint16_t *ptr, unsigned int len) {
	uint16_t val;
	unsigned int i;
	int c;

    for(i = 0; i < len; i += 2) {
	val = 0;

	if(hex[i] == '?' && hex[i + 1] == '?') {
	    val |= CLI_MATCH_IGNORE;

	} else if(hex[i + 1] == '?') {
	    if((c = cli_hex2int(hex[i])) >= 0) {
		val = c << 4;
	    } else {
		return 0;
	    }
	    val |= CLI_MATCH_NIBBLE_HIGH;

	} else if(hex[i] == '?') {
	    if((c = cli_hex2int(hex[i + 1])) >= 0) {
		val = c;
	    } else {
		return 0;
	    }
	    val |= CLI_MATCH_NIBBLE_LOW;

	} else if(hex[i] == '(') {
	    val |= CLI_MATCH_SPECIAL;

	} else {
	    if((c = cli_hex2int(hex[i])) >= 0) {
		val = c;
		if((c = cli_hex2int(hex[i+1])) >= 0) {
		    val = (val << 4) + c;
		} else {
		    return 0;
		}
	    } else {
		return 0;
	    }
	}

	*ptr++ = val;
    }
    return 1;
}

uint16_t *cli_hex2ui(const char *hex)
{
	uint16_t *str;
	unsigned int len;

    len = strlen(hex);

    if(len % 2 != 0) {
	cli_errmsg("cli_hex2ui(): Malformed hexstring: %s (length: %u)\n", hex, len);
	return NULL;
    }

    str = cli_calloc((len / 2) + 1, sizeof(uint16_t));
    if(!str)
	return NULL;

    if(cli_realhex2ui(hex, str, len))
        return str;
    
    free(str);
    return NULL;
}

char *cli_hex2str(const char *hex)
{
    char *str;
    size_t len;

    len = strlen(hex);

    if(len % 2 != 0) {
	cli_errmsg("cli_hex2str(): Malformed hexstring: %s (length: %u)\n", hex, (unsigned)len);
	return NULL;
    }

    str = cli_calloc((len / 2) + 1, sizeof(char));
    if(!str)
	return NULL;

    if (cli_hex2str_to(hex, str, len) == -1) {
	free(str);
	return NULL;
    }
    return str;
}

int cli_hex2str_to(const char *hex, char *ptr, size_t len)
{
    size_t i;
    int c;
    char val;

    for(i = 0; i < len; i += 2) {
	if((c = cli_hex2int(hex[i])) >= 0) {
	    val = c;
	    if((c = cli_hex2int(hex[i+1])) >= 0) {
		val = (val << 4) + c;
	    } else {
		return -1;
	    }
	} else {
	    return -1;
	}

	*ptr++ = val;
    }

    return 0;
}

int cli_hex2num(const char *hex)
{
	int hexval, ret = 0, len, i;


    len = strlen(hex);

    if(len % 2 != 0) {
	cli_errmsg("cli_hex2num(): Malformed hexstring: %s (length: %d)\n", hex, len);
	return -1;
    }

    for(i = 0; i < len; i++) {
	if((hexval = cli_hex2int(hex[i])) < 0)
	    break;
	ret = (ret << 4) | hexval;
    }

    return ret;
}

char *cli_str2hex(const char *string, unsigned int len)
{
	char *hexstr;
	char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		       'a', 'b', 'c', 'd', 'e', 'f' };
	unsigned int i, j;

    if((hexstr = (char *) cli_calloc(2 * len + 1, sizeof(char))) == NULL)
	return NULL;

    for(i = 0, j = 0; i < len; i++, j += 2) {
	hexstr[j] = HEX[(string[i] >> 4) & 0xf];
	hexstr[j + 1] = HEX[string[i] & 0xf];
    }

    return hexstr;
}

char *cli_utf16toascii(const char *str, unsigned int length)
{
	char *decoded;
	unsigned int i, j;


    if(length < 2) {
	cli_dbgmsg("cli_utf16toascii: length < 2\n");
	return NULL;
    }

    if(length % 2)
	length--;

    if(!(decoded = cli_calloc(length / 2 + 1, sizeof(char))))
	return NULL;

    for(i = 0, j = 0; i < length; i += 2, j++) {
       decoded[j] = str[i + 1] << 4;
       decoded[j] += str[i];
    }

    return decoded;
}

int cli_strbcasestr(const char *haystack, const char *needle)
{
	const char *pt =  haystack;
	int i, j;

    i = strlen(haystack);
    j = strlen(needle);

    if(i < j)
	return 0;

    pt += i - j;

    return !strcasecmp(pt, needle);
}

/*
 * Remove trailing NL and CR characters from the end of the given string.
 * Return the new length of the string (ala strlen)
 */
int
cli_chomp(char *string)
{
	int l;

	if(string == NULL)
		return -1;

	l  = strlen(string);

	if(l == 0)
		return 0;

	--l;

	while((l >= 0) && ((string[l] == '\n') || (string[l] == '\r')))
		string[l--] = '\0';

	return l + 1;
}

/*
 * char *cli_strok(const char *line, int fieldno, char *delim)
 * Return a copy of field <fieldno> from the string <line>, where
 * fields are delimited by any char from <delim>, or NULL if <line>
 * doesn't have <fieldno> fields or not enough memory is available.
 * The caller has to free() the result afterwards.
 */
char *cli_strtok(const char *line, int fieldno, const char *delim)
{
    int counter = 0, i, j;
    char *buffer = NULL;


    /* step to arg # <fieldno> */
    for (i=0; line[i] && counter != fieldno; i++) {
	if (strchr(delim, line[i])) {
	    counter++;
	    while(line[i+1] && strchr(delim, line[i+1])) {
		i++;
	    }
	}
    }
    if (!line[i]) {
	/* end of buffer before field reached */
	return NULL;
    }

    for (j=i; line[j]; j++) {
	if (strchr(delim, line[j])) {
	    break;
	}
    }
    if (i == j) {
	return NULL;
    }
    buffer = cli_malloc(j-i+1);
    if(!buffer) {
        cli_errmsg("cli_strtok: Unable to allocate memory for buffer\n");
        return NULL;
    }
    strncpy(buffer, line+i, j-i);
    buffer[j-i] = '\0';

    return buffer;
}

/*
 * Like cli_strtok, but this puts the output into a given argument, rather
 * than allocating fresh memory
 * Returns NULL for error, or a pointer to output
 * njh@bandsman.co.uk
 */
char *cli_strtokbuf(const char *input, int fieldno, const char *delim, char *output)
{
    int counter = 0, i, j;

    /* step to arg # <fieldno> */
    for (i=0; input[i] && counter != fieldno; i++) {
	if (strchr(delim, input[i])) {
	    counter++;
	    while(input[i+1] && strchr(delim, input[i+1])) {
		i++;
	    }
	}
    }
    if (input[i] == '\0') {
	/* end of buffer before field reached */
	return NULL;
    }

    for (j=i; input[j]; j++) {
	if (strchr(delim, input[j])) {
	    break;
	}
    }
    if (i == j) {
	return NULL;
    }
    strncpy(output, input+i, j-i);
    output[j-i] = '\0';

    return output;
}

const char *cli_memstr(const char *haystack, unsigned int hs, const char *needle, unsigned int ns)
{
	unsigned int i, s1, s2;

    if(!hs || !ns || hs < ns)
	return NULL;

    if(needle == haystack)
	return haystack;

    if(ns == 1)
	return memchr(haystack, needle[0], hs);

    if(needle[0] == needle[1]) {
	s1 = 2;
	s2 = 1;
    } else {
	s1 = 1;
	s2 = 2;
    }
    for(i = 0; i <= hs - ns; ) {
	if(needle[1] != haystack[i + 1]) {
	    i += s1;
	} else {
	    if((needle[0] == haystack[i]) && !memcmp(needle + 2, haystack + i + 2, ns - 2))
		return &haystack[i];
	    i += s2;
	}
    }

    return NULL;
}

char *cli_strrcpy(char *dest, const char *source) /* by NJH */
{

    if(!dest || !source) {
	cli_errmsg("cli_strrcpy: NULL argument\n");
	return NULL;
    }

    while((*dest++ = *source++));

    return --dest;
}

#ifndef HAVE_STRCASESTR
const char* cli_strcasestr(const char* a, const char *b)
{
	size_t l;
	char f[3];
	const size_t strlen_a = strlen(a);
	const size_t strlen_b = strlen(b);

	f[0] = tolower(*b);
	f[1] = toupper(*b);
	f[2] = '\0';
	for (l = strcspn(a, f); l != strlen_a; l += strcspn(a + l + 1, f) + 1)
		if (strncasecmp(a + l, b, strlen_b) == 0)
			return(a + l);
	return(NULL);
}
#endif

size_t cli_strtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens)
{
	size_t tokens_found, i;


    for(tokens_found = 0; tokens_found < token_count; ) {
	tokens[tokens_found++] = buffer;
	buffer = strchr(buffer, delim);
	if(buffer) {
	    *buffer++ = '\0';
	} else {
	    i = tokens_found;
	    while(i < token_count)
		tokens[i++] = NULL;

	    return tokens_found;
	}
    }
    return tokens_found;
}

int cli_isnumber(const char *str)
{
    while(*str)
	if(!strchr("0123456789", *str++))
	    return 0;

    return 1;
}

/* encodes the unicode character as utf-8 */
static inline size_t output_utf8(uint16_t u, unsigned char* dst)
{
	if(!u) {
		*dst = 0x1; /* don't add \0, add \1 instead */
		return 1;
	}
	if(u < 0x80) {
		*dst = u&0xff;
		return 1;
	}
	if(u < 0x800) {
		*dst++ = 0xc0 | (u>>6);   /* 110yyyyy */
		*dst = 0x80 | (u & 0x3f); /* 10zzzzzz */
		return 2;
	}
	/* u < 0x10000 because we only handle utf-16,
	 * values in range 0xd800 - 0xdfff aren't valid, but we don't check for
	 * that*/
	*dst++ = 0xe0 | (u>>12);        /* 1110xxxx */
	*dst++ = 0x80 | ((u>>6)&0x3f); /* 10yyyyyy */
	*dst = 0x80 | (u & 0x3f);      /* 10zzzzzz */
	return 3;
}

/* javascript-like unescape() function */
char *cli_unescape(const char *str)
{
	char *R;
	size_t k, i=0;
	const size_t len = strlen(str);
	/* unescaped string is at most as long as original,
	 * it will usually be shorter */
	R = cli_malloc(len + 1);
	if(!R) {
        cli_errmsg("cli_unescape: Unable to allocate memory for string\n");
		return NULL;
    }
	for(k=0;k < len;k++) {
		unsigned char c = str[k];
		if (str[k] == '%') {
			if(k+5 >= len || str[k+1] != 'u' || !isxdigit(str[k+2]) || !isxdigit(str[k+3])
						|| !isxdigit(str[k+4]) || !isxdigit(str[k+5])) {
				if(k+2 < len && isxdigit(str[k+1]) && isxdigit(str[k+2])) {
					c = (cli_hex2int(str[k+1])<<4) | cli_hex2int(str[k+2]);
					k += 2;
				}
			} else {
				uint16_t u = (cli_hex2int(str[k+2])<<12) | (cli_hex2int(str[k+3])<<8) |
					(cli_hex2int(str[k+4])<<4) | cli_hex2int(str[k+5]);
				i += output_utf8(u, (unsigned char*)&R[i]);
				k += 5;
				continue;
			}
		}
		if(!c) c = 1; /* don't add \0 */
		R[i++] = c;
	}
	R[i++] = '\0';
	R = cli_realloc2(R, i);
	return R;
}

/* handle javascript's escape sequences inside strings */
int cli_textbuffer_append_normalize(struct text_buffer *buf, const char *str, size_t len)
{
	size_t i;
	for(i=0;i < len;i++) {
		char c = str[i];
		if (c == '\\' && i+1 < len) {
			i++;
			switch (str[i]) {
				case '0':
					c = 0;
					break;
				case 'b':
					c = 8;
					break;
				case 't':
					c = 9;
					break;
				case 'n':
					c = 10;
					break;
				case 'v':
					c = 11;
					break;
				case 'f':
					c = 12;
					break;
				case 'r':
					c=13;
					break;
				case 'x':
					if(i+2 < len)
						c = (cli_hex2int(str[i+1])<<4)|cli_hex2int(str[i+2]);
					i += 2;
					break;
				case 'u':
					if(i+4 < len) {
						uint16_t u = (cli_hex2int(str[i+1])<<12) | (cli_hex2int(str[i+2])<<8) |
							(cli_hex2int(str[i+3])<<4) | cli_hex2int(str[i+4]);
						if(textbuffer_ensure_capacity(buf, 4) == -1)
							return -1;
						buf->pos += output_utf8(u, (unsigned char*)&buf->data[buf->pos]);
						i += 4;
						continue;
					}
					break;
				default:
					c = str[i];
					break;
			}
		}
		if(!c) c = 1; /* we don't insert \0 */
		if(textbuffer_putc(buf, c) == -1)
			return -1;
	}
	return 0;
}

int cli_hexnibbles(char *str, int len)
{
    int i;
    for(i=0; i<len; i++) {
	int c = cli_hex2int(str[i]);
	if(c<0) return 1;
	str[i] = c;
    }
    return 0;
}

char *cli_utf16_to_utf8(const char *utf16, size_t length, utf16_type type)
{
    /* utf8 -
     * 4 bytes for utf16 high+low surrogate (4 bytes input)
     * 3 bytes for utf16 otherwise (2 bytes input) */
    size_t i, j;
    size_t needed = length * 3/2 + 2;
    char *s2;

    if (length < 2)
	return cli_strdup("");
    if (length % 2) {
	cli_warnmsg("utf16 length is not multiple of two: %lu\n", (long)length);
	length--;
    }

    s2 = cli_malloc(needed);
    if (!s2)
	return NULL;

    i = 0;

    if((utf16[0] == '\xff' && utf16[1] == '\xfe') || (utf16[0] == '\xfe' && utf16[1] == '\xff')) {
	i += 2;
	if(type == UTF16_BOM)
	    type = (utf16[0] == '\xff') ? UTF16_LE : UTF16_BE;
    } else if(type == UTF16_BOM)
	type = UTF16_BE;

    for (j=0;i<length && j<needed;i += 2) {
	uint16_t c = cli_readint16(&utf16[i]);
	if(type == UTF16_BE)
	    c = cbswap16(c);
	if (c < 0x80) {
	    s2[j++] = c;
	} else if (c < 0x800) {
	    s2[j] = 0xc0 | (c >>6);
	    s2[j+1] = 0x80 | (c&0x3f);
	    j += 2;
	} else if (c < 0xd800 || c >= 0xe000) {
	    s2[j] = 0xe0 | (c >> 12);
	    s2[j+1] = 0x80 | ((c >> 6) & 0x3f);
	    s2[j+2] = 0x80 | (c & 0x3f);
	    j += 3;
	} else if (c < 0xdc00 && i+3 < length) {
	    uint16_t c2;
	    /* UTF16 high+low surrogate */
	    c = c - 0xd800 + 0x40;
	    c2 = i+3 < length ? cli_readint16(&utf16[i+2]) : 0;
	    c2 -= 0xdc00;
	    s2[j] = 0xf0 | (c >> 8);
	    s2[j+1] = 0x80 | ((c >> 2) & 0x3f);
	    s2[j+2] = 0x80 | ((c&3) << 4) | (c2 >> 6);
	    s2[j+3] = 0x80 | (c2 & 0x3f);
	    j += 4;
	    i += 2;
	} else {
	    cli_dbgmsg("UTF16 surrogate encountered at wrong pos\n");
	    /* invalid char */
	    s2[j++] = 0xef;
	    s2[j++] = 0xbf;
	    s2[j++] = 0xbd;
	}
    }
    if (j >= needed)
	j = needed-1;
    s2[j] = '\0';
    return s2;
}
