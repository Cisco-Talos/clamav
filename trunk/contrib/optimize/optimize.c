/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MINLENGTH 40 /* only optimize signatures longer than MINLENGT */
#define FILEBUFF 16384
#define ANALYZE 6 /* only analyze first ANALYZE characters */

int hex2int(int c)
{
	int l = tolower(c);

    if (!isascii(l))
    	return -1;
    if (isdigit(l))
	return l - '0';
    if ((l >= 'a') && (l <= 'f'))
	return l + 10 - 'a';

    return -1;
}

char *hex2str(const char *hex, int howmany)
{
	short int val, c;
	int i, len;
	char *str, *ptr;

    len = strlen(hex);

    /* additional check - hex strings are parity length here */
    if(len % 2 != 0) {
	printf("hex2str(): Malformed hexstring: %s (length: %d)\n", hex, len);
	return NULL;
    }

    str = calloc((howmany / 2) + 1, sizeof(char));
    if(!str)
	return NULL;

    ptr = str;

    if(howmany > len)
	howmany = len;

    for(i = 0; i < howmany; i += 2) {
	if(hex[i] == '?') {
	    printf("Can't optimize polymorphic signature.\n");
	    free(str);
	    return NULL;
	} else {
	    if((c = hex2int(hex[i])) >= 0) {
		val = c;
		if((c = hex2int(hex[i+1])) >= 0) {
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

void chomp(char *string)
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

int main(int argc, char **argv)
{
	int line = 0, found, i, nodes = 0, optimized = 0, optimal = 0;
	unsigned char c1, c2;
	char *buffer, *start, *pt, **prefix, *sig;
	FILE *in, *out;


    if(argc != 3) {
	printf("%s input_db output_db\n", argv[0]);
	exit(1);
    }

    if((in = fopen(argv[1], "rb")) == NULL) {
	printf("Can't open input database %s\n", argv[1]);
	exit(1);
    }

    if((out = fopen(argv[2], "wb")) == NULL) {
	printf("Can't open output database %s\n", argv[1]);
	exit(1);
    }

    prefix = (char **) calloc(256, sizeof(char *));
    for(i = 0; i < 256; i++)
	prefix[i] = (char *) calloc(256, sizeof(char));

    if(!(buffer = (char *) malloc(FILEBUFF))) {
	exit(1);
    }

    memset(buffer, 0, FILEBUFF);

    while(fgets(buffer, FILEBUFF, in)) {

	line++;
	chomp(buffer);

	pt = strchr(buffer, '=');
	if(!pt) {
	    printf("Malformed pattern line %d.\n", line);
	    free(buffer);
	    exit(1);
	}

	start = buffer;
	*pt++ = 0;

	if(*pt == '=')
	    continue;

	if(strlen(pt) < MINLENGTH) {
	    fprintf(out, "%s=%s\n", start, pt);
	    continue;
	}

	sig = hex2str(pt, 2 * ANALYZE);

	if(!sig) {
	    printf("Can't decode signature %d\n", line);
	    exit(1);
	}

	found = -1;

	for(i = 0; i < ANALYZE - 1; i++) {
	    c1 = ((unsigned char) sig[i]) & 0xff;
	    c2 = ((unsigned char) sig[i + 1]) & 0xff;

	    if(prefix[c1][c2]) {
		found = i;
		break;
	    }
	}

	if(found < 0) {
	    printf("Can't optimize signature %d\n", line);
	    prefix[c1][c2] = 1;
	    nodes++;
	} else if(found == 0) {
	    printf("Signature %d is already optimal.\n", line);
	    optimal++;
	} else {
	    pt = pt + 2 * found;
	    printf("Signature %d optimized (new start at %d byte)\n", line, found);
	    optimized++;
	}

	fprintf(out, "%s=%s\n", start, pt);
    }

    fclose(in);
    fclose(out);

    free(buffer);
    for(i = 0; i < 256; i++)
	free(prefix[i]);
    free(prefix);

    printf("Nodes: %d, Optimal: %d, Signatures optimized: %d\n", nodes, optimal, optimized);
    exit(0);
}
