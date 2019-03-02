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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include <sys/types.h>

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "jsparse/textbuf.h"
#include "platform.h"

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

int cli_xtoi(const char *hex)
{
    int len, val, i;
    char * hexbuf;

    len = strlen(hex);

    if(len % 2 == 0)
        return cli_hex2num(hex);
        
    hexbuf = cli_calloc(len+2, sizeof(char));
    if (hexbuf == NULL) {
        cli_errmsg("cli_xtoi(): cli_malloc fails.\n");
        return -1;
    }
    
    for(i = 0; i < len; i++)
        hexbuf[i+1] = hex[i];
    val = cli_hex2num(hexbuf);
    free(hexbuf);
    return val;
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
        decoded[j] = ((unsigned char) str[i + 1]) << 4;
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

const char *cli_memstr(const char *haystack, size_t hs, const char *needle, size_t ns)
{
	size_t i, s1, s2;

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

#if !defined(HAVE_STRNLEN) || defined(HAVE_STRNI)
size_t cli_strnlen(const char *s, size_t n)
{
    size_t i = 0;
    for(; (i < n) && s[i] != '\0'; ++i);
    return i;
}
#endif

#if !defined(HAVE_STRNDUP) || defined(HAVE_STRNI)
char *cli_strndup(const char *s, size_t n)
{
    char *alloc;
    size_t len;

    if(!s) {
        return NULL;
    }

    len = cli_strnlen(s, n);
    alloc = malloc(len+1);

    if(!alloc) {
        return NULL;
    } else
        memcpy(alloc, s, len);

    alloc[len] = '\0';
    return alloc;
}
#endif

#if !defined(HAVE_STRNSTR) || defined(HAVE_STRNI)
/*
 * @brief Find the first occurrence of find in s.
 *
 * The search is limited to the first slen characters of s.
 *
 * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
 * Copyright (c) 1990, 1993
 * The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * @param s      haystack
 * @param find   needle
 * @param slen   haystack length
 * @return char* Address of the needle, if found, else NULL.
 */
char *cli_strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
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

/**
 * @brief The strntol() function converts the string in str to a long value.
 * Modifications made to validate the length of the string for non-null term strings.
 *
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * @param nptr          Pointer to start of string.
 * @param n             Max length of buffer in bytes.
 * @param[out] endptr   [optional] If endptr is not NULL, strtol() stores the address
 *                      of the first invalid character in *endptr. If there were no digits
 *                      at all, however, strtol() stores the
 *                      original value of str in *endptr. 
 * 	                     Nota Bene:  If the buffer is non-null terminated and the number
 *                       comprises the entire buffer, endptr will point past the end of
 *                       the buffer, and the caller should check if endptr >= nptr + n.
 *                      
 * @param int           The conversion is done according to the given base, which must be
 *                      between 2 and 36 inclusive, or be the special value 0.
 * @return long         The signed long value.
 */
long cli_strntol(const char* nptr, size_t n, char** endptr, register int base)
{
    register const char* s = nptr;
    register unsigned long acc = 0;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any = 0, cutlim;

    if (0 == n) {
        goto done;
    }
    /*
	 * Skip white space and pick up leading +/- sign if any.
	 * If base is 0, allow 0x for hex and 0 for octal, else
	 * assume decimal; if base is already 16, allow 0x.
	 */
    do {
        c = *s;
    } while (isspace(c) && (++s < nptr + n));

    if (s >= nptr + n) {
        goto done;
    }

    if (c == '-') {
        neg = 1;
        c = *s++;
        if (s >= nptr + n) {
            goto done;
        }
    } else if (c == '+') {
        c = *s++;
        if (s >= nptr + n) {
            goto done;
        }
    }

    if (base == 0 || base == 16) {
        if (c == '0' && (s + 1 < nptr + n) && (*(s+1) == 'x' || *(s+1) == 'X')) {
            if (s + 2 >= nptr + n) {
                goto done;
            }
            c = s[1];
            s += 2;
            base = 16;
        }
    }

    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
	 * Compute the cutoff value between legal numbers and illegal
	 * numbers.  That is the largest legal value, divided by the
	 * base.  An input number that is greater than this value, if
	 * followed by a legal input character, is too big.  One that
	 * is equal to this value may be valid or not; the limit
	 * between valid and invalid numbers is then based on the last
	 * digit.  For instance, if the range for longs is
	 * [-2147483648..2147483647] and the input base is 10,
	 * cutoff will be set to 214748364 and cutlim to either
	 * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
	 * a value > 214748364, or equal but the next digit is > 7 (or 8),
	 * the number is too big, and we will return a range error.
	 *
	 * Set any if any `digits' consumed; make it negative to indicate
	 * overflow.
	 */
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0; s < nptr + n; s++) {
        c = *s;

        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
        errno = ERANGE;
    } else if (neg)
        acc = -acc;

done:
    if (endptr != 0)
        *endptr = (char*)(any ? s : nptr);
    return (acc);
}

/**
 * @brief The strntoul() function converts the string in str to an unsigned long value.
 * Modifications made to validate the length of the string for non-null term strings.
 *
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * @param nptr          Pointer to start of string.
 * @param n             Max length of buffer in bytes.
 * @param[out] endptr   [optional] If endptr is not NULL, strtol() stores the address
 *                      of the first invalid character in *endptr. If there were no digits
 *                      at all, however, strtol() stores the
 *                      original value of str in *endptr. 
 * 	                     Nota Bene:  If the buffer is non-null terminated and the number
 *                       comprises the entire buffer, endptr will point past the end of
 *                       the buffer, and the caller should check if endptr >= nptr + n.
 *                      
 * @param int           The conversion is done according to the given base, which must be
 *                      between 2 and 36 inclusive, or be the special value 0.
 * @return unsigned long The unsigned long value.
 */
unsigned long
cli_strntoul(const char* nptr, size_t n, char** endptr, register int base)
{
    register const char* s = nptr;
    register unsigned long acc = 0;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any = 0, cutlim;

    /*
	 * See cli_strntol for comments as to the logic used.
	 */
    do {
        c = *s;
    } while (isspace(c) && (++s < nptr + n));

    if (s >= nptr + n) {
        goto done;
    }

    if (c == '-') {
        neg = 1;
        c = *s++;
        if (s >= nptr + n) {
            goto done;
        }
    } else if (c == '+') {
        c = *s++;
        if (s >= nptr + n) {
            goto done;
        }
    }

    if (base == 0 || base == 16) {
        if (c == '0' && (s + 1 < nptr + n) && (*(s+1) == 'x' || *(s+1) == 'X')) {
            if (s + 2 >= nptr + n) {
                goto done;
            }
            c = s[1];
            s += 2;
            base = 16;
        }
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
    cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
    for (acc = 0, any = 0; s < nptr + n; s++) {
        c = *s;

        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = ULONG_MAX;
        errno = ERANGE;
    } else if (neg)
        acc = -acc;

done:
    if (endptr != 0)
        *endptr = (char*)(any ? s : nptr);
    return (acc);
}

/**
 * @brief 	cli_strntol_wrap() converts the string in str to a long value.
 * 
 * Wrapper for cli_strntol() that provides incentive to check for failure.
 * 
 * @param buf               Pointer to start of string. 
 * @param buf_size 			Max length of buffer to convert to integer.
 * @param fail_at_nondigit  If 1, fail out if the a non-digit character is found before the end of the buffer.
 *                          If 0, non-digit character represents end of number and is not a failure.
 * @param base              The conversion is done according to the given base, which must be
 *                          between 2 and 36 inclusive, or be the special value 0.
 * @param[out] result 	    Long integer value of ascii number.
 * @return CL_SUCCESS       Success
 * @return CL_EPARSE        Failure
 */
cl_error_t cli_strntol_wrap(const char *buf, size_t buf_size, int fail_at_nondigit, int base, long *result)
{
    char *endptr = NULL;
    long num;

    if (buf_size == 0 || !buf || !result) {
        /* invalid parameter */
        return CL_EPARSE;
    }
    errno = 0;
    num = cli_strntol(buf, buf_size, &endptr, base);
    if ((num == LONG_MIN || num == LONG_MAX) && errno == ERANGE) {
        /* under- or overflow */
        return CL_EPARSE;
    }
    if (endptr == buf) {
        /* no digits */
        return CL_EPARSE;
    }
    if (fail_at_nondigit && (endptr < (buf + buf_size)) && (*endptr != '\0')) {
        /* non-digit encountered */
        return CL_EPARSE;
    }
    /* success */
    *result = num;
    return CL_SUCCESS;
}

/**
 * @brief 	cli_strntoul_wrap() converts the string in str to a long value.
 * 
 * Wrapper for cli_strntoul() that provides incentive to check for failure.
 * 
 * @param buf               Pointer to start of string. 
 * @param buf_size 			Max length of buffer to convert to integer.
 * @param fail_at_nondigit  If 1, fail out if the a non-digit character is found before the end of the buffer.
 *                          If 0, non-digit character represents end of number and is not a failure.
 * @param base              The conversion is done according to the given base, which must be
 *                          between 2 and 36 inclusive, or be the special value 0.
 * @param[out] result 	    Unsigned long integer value of ascii number.
 * @return CL_SUCCESS       Success
 * @return CL_EPARSE        Failure
 */
cl_error_t cli_strntoul_wrap(const char *buf, size_t buf_size, int fail_at_nondigit, int base, unsigned long *result)
{
    char *endptr = NULL;
    long num;

    if (buf_size == 0 || !buf || !result) {
        /* invalid parameter */
        return CL_EPARSE;
    }
    errno = 0;
    num = cli_strntoul(buf, buf_size, &endptr, base);
    if (num == ULONG_MAX && errno == ERANGE) {
        /* under- or overflow */
        return CL_EPARSE;
    }
    if (endptr == buf) {
        /* no digits */
        return CL_EPARSE;
    }
    if (fail_at_nondigit && (endptr < (buf + buf_size)) && (*endptr != '\0')) {
        /* non-digit encountered */
        return CL_EPARSE;
    }
    /* success */
    *result = num;
    return CL_SUCCESS;
}

size_t cli_ldbtokenize(char *buffer, const char delim, const size_t token_count, const char **tokens, int token_skip)
{
    size_t tokens_found, i;
    int within_pcre = 0;

    for(tokens_found = 0; tokens_found < token_count; ) {
        tokens[tokens_found++] = buffer;

        while (*buffer != '\0') {
            if (!within_pcre && (*buffer == delim))
                break;
            else if ((tokens_found > token_skip) && (*(buffer-1) != '\\') && (*buffer == '/'))
                within_pcre = !within_pcre;
            buffer++;
        }

        if(*buffer != '\0') {
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
                    c = ((cli_hex2int(str[k + 1]) < 0 ? 0 : cli_hex2int(str[k + 1])) << 4) | cli_hex2int(str[k + 2]);
					k += 2;
				}
			} else {
                uint16_t u = ((cli_hex2int(str[k + 2]) < 0 ? 0 : cli_hex2int(str[k + 2])) << 12) |
                             ((cli_hex2int(str[k + 3]) < 0 ? 0 : cli_hex2int(str[k + 3])) << 8)  |
                             ((cli_hex2int(str[k + 4]) < 0 ? 0 : cli_hex2int(str[k + 4])) << 4)  |
                               cli_hex2int(str[k + 5]);
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
                        c = ((cli_hex2int(str[i + 1]) < 0 ? 0 : cli_hex2int(str[i + 1])) << 4) | cli_hex2int(str[i + 2]);
					i += 2;
					break;
				case 'u':
					if(i+4 < len) {
                        uint16_t u = ((cli_hex2int(str[i + 1]) < 0 ? 0 : cli_hex2int(str[i + 1])) << 12) |
                                     ((cli_hex2int(str[i + 2]) < 0 ? 0 : cli_hex2int(str[i + 2])) << 8)  |
                                     ((cli_hex2int(str[i + 3]) < 0 ? 0 : cli_hex2int(str[i + 3])) << 4)  | 
                                       cli_hex2int(str[i + 4]);
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

int cli_isutf8(const char *buf, unsigned int len)
{
	unsigned int i, j;

    for(i = 0; i < len; i++) {
        if((buf[i] & 0x80) == 0) {  /* 0xxxxxxx is plain ASCII */
            continue;
        } else if((buf[i] & 0x40) == 0) { /* 10xxxxxx never 1st byte */
            return 0;
        } else {
            unsigned int following;

            if((buf[i] & 0x20) == 0) {		/* 110xxxxx */
                /* c = buf[i] & 0x1f; */
                following = 1;
            } else if((buf[i] & 0x10) == 0) {	/* 1110xxxx */
                /* c = buf[i] & 0x0f; */
                following = 2;
            } else if((buf[i] & 0x08) == 0) {	/* 11110xxx */
                /* c = buf[i] & 0x07; */
                following = 3;
            } else if((buf[i] & 0x04) == 0) {	/* 111110xx */
                /* c = buf[i] & 0x03; */
                following = 4;
            } else if((buf[i] & 0x02) == 0) {	/* 1111110x */
                /* c = buf[i] & 0x01; */
                following = 5;
            } else {
                return 0;
            }

            for(j = 0; j < following; j++) {
                if(++i >= len)
                    return 0;

                if((buf[i] & 0x80) == 0 || (buf[i] & 0x40))
                    return 0;

                /* c = (c << 6) + (buf[i] & 0x3f); */
            }
        }
    }

    return 1;
}

cl_error_t cli_basename(const char *filepath, size_t filepath_len, char **filebase)
{
    cl_error_t status = CL_EARG;
    const char *index = NULL;
    
    if (NULL == filepath || NULL == filebase || filepath_len == 0) {
        cli_dbgmsg("cli_basename: Invalid arguments.\n");
        goto done;
    }

    index = filepath + filepath_len - 1;

    while (index > filepath) {
        if (index[0] == PATHSEP[0]) break;
        index--;
    }
    if ((index != filepath) || (index[0] == PATHSEP[0]))
        index++;

    if (0 == cli_strnlen(index, filepath_len - (index - filepath))) {
        cli_dbgmsg("cli_basename: Provided path does not include a file name.\n");
        status = CL_EFORMAT;
        goto done;
    }

    *filebase = cli_strndup(index, filepath_len - (index - filepath));
    if (NULL == *filebase) {
        cli_errmsg("cli_basename: Failed to allocate memory for file basename.\n");
        status = CL_EMEM;
        goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}
