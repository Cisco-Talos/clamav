/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

short int *cl_hex2str(const char *hex)
{
	short int *str, *ptr, val, c;
	int i, len;

    len = strlen(hex);

    /* additional check - hex strings are parity length here */
    if(len % 2 != 0) {
	cli_errmsg("cl_hex2str(): Malformed hexstring: %s (length: %d)\n", hex, len);
	return NULL;
    }

    str = cli_calloc((len / 2) + 1, sizeof(short int));
    if(!str)
	return NULL;

    ptr = str;

    for(i = 0; i < len; i += 2) {
	if(hex[i] == '?') {
	    val = CLI_IGN;
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

char *cl_str2hex(const char *string, unsigned int len)
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

void cli_chomp(char *string)
{
	size_t l = strlen(string);


    if(l == 0)
	return;

    --l;
    if((string[l] == '\n') || (string[l] == '\r')) {
	string[l] = '\0';

	if(l > 0) {
	    --l;
	    if(string[l] == '\r')
		string[l] = '\0';
	}
    }
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
    strncpy(buffer, line+i, j-i);
    buffer[j-i] = '\0';

    return buffer;
}


