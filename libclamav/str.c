/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "clamav.h"
#include "others.h"
#include "defaults.h"

static int cli_hex2int(int c)
{
	int l = tolower(c);

    if (!isascii(l))
    	return -1;
    if (isdigit(l))
	return l - '0';
    if ((l >= 'a') && (l <= 'f'))
	return l + 10 - 'a';

    cli_errmsg("hex2int() translation problem (%d)\n", l);
    return -1;
}

short int *cli_hex2si(const char *hex)
{
	short int *str, *ptr, val, c;
	int i, len;


    len = strlen(hex);

    if(len % 2 != 0) {
	cli_errmsg("cli_hex2si(): Malformed hexstring: %s (length: %d)\n", hex, len);
	return NULL;
    }

    str = cli_calloc((len / 2) + 1, sizeof(short int));
    if(!str)
	return NULL;

    ptr = str;

    for(i = 0; i < len; i += 2) {
	if(hex[i] == '?') {
	    val = CLI_IGN;
	} else if(hex[i] == '@') {
	    val = CLI_ALT;
	} else {
	    if((c = cli_hex2int(hex[i])) >= 0) {
		val = c;
		if((c = cli_hex2int(hex[i+1])) >= 0) {
		    val = (val << 4) + c;
		} else {
		    free(str);
		    return NULL;
		}
	    } else {
		free(str);
		return NULL;
	    }
	}
	*ptr++ = val;
    }

    return str;
}

char *cli_hex2str(const char *hex)
{
	char *str, *ptr, val, c;
	int i, len;


    len = strlen(hex);

    if(len % 2 != 0) {
	cli_errmsg("cli_hex2str(): Malformed hexstring: %s (length: %d)\n", hex, len);
	return NULL;
    }

    str = cli_calloc((len / 2) + 1, sizeof(char));
    if(!str)
	return NULL;

    ptr = str;

    for(i = 0; i < len; i += 2) {
	if((c = cli_hex2int(hex[i])) >= 0) {
	    val = c;
	    if((c = cli_hex2int(hex[i+1])) >= 0) {
		val = (val << 4) + c;
	    } else {
		free(str);
		return NULL;
	    }
	} else {
	    free(str);
	    return NULL;
	}

	*ptr++ = val;
    }

    return str;
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

int cli_strbcasestr(const char *haystack, const char *needle)
{
	char *pt = (char *) haystack;
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
    buffer = malloc(j-i+1);
    if(!buffer)
	return NULL;
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

const char *cli_memstr(const char *haystack, int hs, const char *needle, int ns)
{
	const char *pt, *hay;
	int n;


    if(hs < ns)
	return NULL;

    if(haystack == needle)
	return haystack;

    if(!memcmp(haystack, needle, ns))
	return haystack;

    pt = hay = haystack;
    n = hs;

    while((pt = memchr(hay, needle[0], n)) != NULL) {
	n -= (int) (pt - hay);
	if(n < ns)
	    break;

	if(!memcmp(pt, needle, ns))
	    return pt;

	if(hay == pt) {
	    n--;
	    hay++;
	} else {
	    hay = pt;
	}
    }

    return NULL;
}
