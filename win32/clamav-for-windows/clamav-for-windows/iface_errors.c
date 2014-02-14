/*
 * Copyright (C) 2010 Sourcefire, Inc.
 * Authors: aCaB <acab@clamav.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "clamav.h"
#include "clscanapi.h"
#include "iface_errors.h"
#include "shared/output.h"

wchar_t **clerrors;

int init_errors(void) {
    int i;

    logg("*in init_errors\n");
    clerrors = calloc(CL_ELAST_ERROR, sizeof(*clerrors));
    if(!clerrors) {
	logg("!init_errors: failed to allocate the error array, aborting\n");
	return 1;
    }
    for(i=0; i<CL_ELAST_ERROR; i++) {
	const char *cerr = cl_strerror(i);
	wchar_t *werr;
	int len;

	if(!cerr)
	    continue;
	len = strlen(cerr)+1;
	werr = (wchar_t *)malloc(len * sizeof(wchar_t));
	if(!werr) {
	    free_errors();
	    logg("!init_errors: failed to allocate string buffer, aborting\n");
	    return 1;
	}
	if(!MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, cerr, -1, werr, len)) {
	    free_errors();
	    logg("!init_errors: failed to convert ascii error <%s> to wide, aborting\n", cerr);
	    return 1;
	}
	logg("*init_errors: error %d is %S\n", i, werr);
	clerrors[i] = werr;
    }
    return 0;
}


void free_errors(void) {
    int i;
    for(i=0; i<CL_ELAST_ERROR; i++)
	if(clerrors[i])
	    free(clerrors[i]);
    free(clerrors);
}

CLAMAPI const wchar_t * Scan_GetErrorMsg(int errorCode) {
    if(errorCode>=0 && errorCode<CL_ELAST_ERROR && clerrors[errorCode])
	return clerrors[errorCode];
    logg("^Scan_GetErrorMsg called with invalid errorCode %d\n", errorCode);
    return L"GetErrorMsg called with an invalid error code";
}
