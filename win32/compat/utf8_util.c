/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#include "utf8_util.h"

char *cli_strdup_to_utf8(const char *s) {
    char *r = cli_to_utf8_maybe_alloc(s);
    if(!r) return NULL;
    if(r == s) return strdup(r);
    return r;
}

#define MAYBE_FREE_W do { if(wdup != tmpw) free(wdup); } while (0)
#define MAYBE_FREE_U do { if(utf8 != tmpu) free(utf8); } while (0)
char *cli_to_utf8_maybe_alloc(const char *s) {
    int len = strlen(s) + 1;
    wchar_t tmpw[1024], *wdup;
    char tmpu[1024], *utf8;

    if(len >= sizeof(tmpw) / sizeof(*tmpw)) {
	wdup = (wchar_t *)malloc(len * sizeof(wchar_t));
	if(!wdup) return NULL;
    } else
	wdup = tmpw;

    /* Check if already UTF8 first... */
    if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, wdup, len)) {
	/* XP acts funny on MB_ERR_INVALID_CHARS, so we translate back and compare
	   On Vista+ the flag is honored and there is no such overhead */
	int ulen;
	if((ulen = WideCharToMultiByte(CP_UTF8, 0, wdup, -1, NULL, 0, NULL, NULL))) {
	    if(ulen > sizeof(tmpu)) {
		utf8 = (char *)malloc(ulen);
		if(!utf8) {
		    MAYBE_FREE_W;
		    return NULL;
		}
	    } else
		utf8 = tmpu;
	    if(WideCharToMultiByte(CP_UTF8, 0, wdup, -1, utf8, ulen, NULL, NULL) && !strcmp(s, utf8)) {
		    MAYBE_FREE_W;
		    MAYBE_FREE_U;
		    return s;
	    }
	    MAYBE_FREE_U;
	}
	/* We should never land here */
    }

    /* ... then assume ANSI */
    if(MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, s, -1, wdup, len)) {
	if((len = WideCharToMultiByte(CP_UTF8, 0, wdup, -1, NULL, 0, NULL, NULL))) {
	    if((utf8 = (char *)malloc(len))) {
		if(WideCharToMultiByte(CP_UTF8, 0, wdup, -1, utf8, len, NULL, NULL)) {
		    MAYBE_FREE_W;
		    return utf8;
		}
		free(utf8);
	    }
	}
    }
    MAYBE_FREE_W;
    return NULL;
}

