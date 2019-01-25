/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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

#include <string.h>
#include "w32_errno.h"

char *w32_strerror(int errnum) {
    size_t i;
    for(i=0; i<sizeof(w32_errnos) / sizeof(w32_errnos[0]); i++) {
	if(w32_errnos[i].err == errnum)
	    return w32_errnos[i].strerr;
    }
    return "Unknown error";
}

int w32_strerror_r(int errnum, char *buf, size_t buflen) {
    strncpy(buf, w32_strerror(errnum), buflen);
    if(buflen) buf[buflen-1] = '\0';
    return 0;
}
