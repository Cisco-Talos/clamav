/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Author: aCaB <acab@clamav.net>
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "libclamav/regex/regex.h"
#include "shared/output.h"
#include "whitelist.h"

struct WHLST {
    regex_t preg;
    struct WHLST *next;
};

struct WHLST *wfrom = NULL;
struct WHLST *wto = NULL;

int skipauth = 0;
regex_t authreg;

void whitelist_free(void) {
    struct WHLST *w;
    while(wfrom) {
	w = wfrom->next;
	cli_regfree(&wfrom->preg);
	free(wfrom);
	wfrom = w;
    }
    while(wto) {
	w = wto->next;
	cli_regfree(&wto->preg);
	free(wto);
	wto = w;
    }
}

int whitelist_init(const char *fname) {
    char buf[2048];
    FILE *f;
    struct WHLST *w;

    if(!(f = fopen(fname, "r"))) {
	logg("!Cannot open whitelist file '%s'\n", fname);
	return 1;
    }

    while(fgets(buf, sizeof(buf), f) != NULL) {
	struct WHLST **addto = &wto;
	char *ptr = buf;
	int len;

	if(*buf == '#' || *buf == ':' || *buf == '!')
	    continue;

	if(!strncasecmp("From:", buf, 5)) {
	    ptr+=5;
	    addto = &wfrom;
	} else if (!strncasecmp("To:", buf, 3))
	    ptr+=3;

	len = strlen(ptr) - 1;
	for(;len>=0; len--) {
	    if(ptr[len] != '\n' && ptr[len] != '\r') break;
	    ptr[len] = '\0';
	}
	if(!len) continue;
	if (!(w = (struct WHLST *)malloc(sizeof(*w)))) {
	    logg("!Out of memory loading whitelist file\n");
	    whitelist_free();
	    fclose(f);
	    return 1;
	}
	w->next = (*addto);
	(*addto) = w;
	if (cli_regcomp(&w->preg, ptr, REG_ICASE|REG_NOSUB)) {
	    logg("!Failed to compile regex '%s' in whitelist file\n", ptr);
	    whitelist_free();
	    fclose(f);
	    return 1;
	}
    }
    fclose(f);
    return 0;
}


int whitelisted(const char *addr, int from) {
    struct WHLST *w;

    if(from) w = wfrom;
    else w = wto;

    while(w) {
	if(!cli_regexec(&w->preg, addr, 0, NULL, 0))
	    return 1;
	w = w->next;
    }
    return 0;
}


int smtpauth_init(const char *r) {
    char *regex = NULL;

    if(!strncmp(r, "file:", 5)) {
	char buf[2048];
	FILE *f = fopen(r+5, "r");
	int rxsize = 0, rxavail = 0, rxused=0;

	if(!f) {
	    logg("!Cannot open whitelist file '%s'\n", r+5);
	    return 1;
	}
	while(fgets(buf, sizeof(buf), f) != NULL) {
	    int len;
	    char *ptr;

	    if(*buf == '#' || *buf == ':' || *buf == '!')
		continue;
	    len = strlen(buf) - 1;
	    for(;len>=0; len--) {
		if(buf[len] != '\n' && buf[len] != '\r') break;
		buf[len] = '\0';
	    }
	    if(len<=0) continue;
	    if(len*3+1 > rxavail) {
		ptr = regex;
		regex = realloc(regex, rxsize + 2048);
		if(!regex) {
		    logg("!Cannot allocate memory for SkipAuthenticated file\n");
		    fclose(f);
		    return 1;
		}
		rxavail = 2048;
		rxsize += 2048;
		if(!ptr) {
		    regex[0] = '^';
		    regex[1] = '(';
		    rxavail -= 2;
		    rxused = 2;
		}
	    }
	    ptr = buf;
	    while(*ptr) {
		if((*ptr>='A' && *ptr<='Z') || (*ptr>='a' && *ptr<='z') || (*ptr>='0' && *ptr<='9') || *ptr=='@') {
		    regex[rxused] = *ptr;
		    rxused++;
		    rxavail--;
		} else {
		    regex[rxused] = '[';
		    regex[rxused+1] = *ptr;
		    regex[rxused+2] = ']';
		    rxused += 3;
		    rxavail -= 3;
		}
		ptr++;
	    }
	    regex[rxused++] = '|';
	    rxavail--;
	}
	if(rxavail < 4 && !(regex = realloc(regex, rxsize + 4))) {
	    logg("!Cannot allocate memory for SkipAuthenticated file\n");
	    fclose(f);
	    return 1;
	}
	regex[rxused-1] = ')';
	regex[rxused] = '$';
	regex[rxused+1] = '\0';
	r = regex;
	fclose(f);
    }

    if(cli_regcomp(&authreg, r, REG_ICASE|REG_NOSUB|REG_EXTENDED)) {
	logg("!Failed to compile regex '%s' for SkipAuthenticated\n", r);
	if(regex) free(regex);
	return 1;
    }
    if(regex) free(regex);
    skipauth = 1;
    return 0;
}


int smtpauthed(const char *login) {
    if(skipauth && !cli_regexec(&authreg, login, 0, NULL, 0))
	return 1;
    return 0;
}


/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */
