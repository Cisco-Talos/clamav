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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "clamav.h"
#include "others.h"
#include "defaults.h"

int cli_hex2int(int c)
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
	int i, j;

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
	int l = strlen(string);

    if(string[l - 1] == 10 || string[l - 1] == 13)
	string[l - 1] = 0;

    l = strlen(string);
    if(string[l - 1] == '\r')
	string[l - 1] = 0;
}

char *cli_tok(const char *line, int field, char delimiter)
{
        int length, counter = 0, i, j = 0;
        char *buffer;


    if(!(length = strlen(line)))
	return NULL;

    buffer = (char *) cli_calloc(length, sizeof(char));

    for(i = 0; i < length; i++) {
        if(line[i] == delimiter) {
            counter++;
            if(counter == field) {
		break;
	    } else {
		memset(buffer, 0, length);
		j = 0;
	    }
        } else {
            buffer[j++] = line[i];
        }
    }

    cli_chomp(buffer); /* preventive */

    if((length = strlen(buffer)))
	return (char *) cli_realloc(buffer, strlen(buffer) + 1);
    else {
	free(buffer);
	return NULL;
    }
}
