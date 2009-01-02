/*
 *  Copyright (C)2008 Sourcefire, Inc.
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
#include <regex.h>

#include "shared/output.h"
#include "whitelist.h"

struct WHLST {
    regex_t preg;
    struct WHLST *next;
};

struct WHLST *wfrom = NULL;
struct WHLST *wto = NULL;

void whitelist_free(void) {
    struct WHLST *w;
    while(wfrom) {
	w = wfrom->next;
	regfree(&wfrom->preg);
	free(wfrom);
	wfrom = w;
    }
    while(wto) {
	w = wto->next;
	regfree(&wto->preg);
	free(wto);
	wto = w;
    }
}

int whitelist_init(const char *fname) {
    char buf[2048];
    FILE *f;
    struct WHLST *w;

    if(!(f = fopen(fname, "r"))) {
	logg("!Cannot open whitelist file\n");
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
	    logg("!Out of memory loading whitelist\n");
	    whitelist_free();
	    return 1;
	}
	w->next = (*addto);
	(*addto) = w;
	if (regcomp(&w->preg, ptr, REG_ICASE|REG_NOSUB)) {
	    logg("!Failed to compile regex '%s'\n", ptr);
	    whitelist_free();
	    return 1;
	}
    }
    return 0;
}


int whitelisted(const char *addr, int from) {
    struct WHLST *w;

    if(from) w = wfrom;
    else w = wto;

    while(w) {
	if(!regexec(&w->preg, addr, 0, NULL, 0))
	    return 1;
	w = w->next;
    }
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
