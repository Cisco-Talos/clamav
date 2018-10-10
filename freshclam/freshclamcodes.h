/*
 *  Copyright (C) 2012 Sourcefire Inc.
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

#ifndef __FRESHCLAMCODES_H
#define __FRESHCLAMCODES_H

typedef enum fc_error_tag {
    FC_SUCCESS          = 0,
    FC_UPTODATE         = 1,

    FCE_INIT            = 40,
    FCE_CHECKS          = 41,
    FCE_PRIVATEMIRROR   = 45,

    FCE_DIRECTORY       = 50,
    FCE_CONNECTION      = 52,
    FCE_EMPTYFILE       = 53,
    FCE_BADCVD          = 54,
    FCE_FILE            = 55,
/* TESTFAIL is also 55, consider moving to new value */
    FCE_TESTFAIL        = 55,
    FCE_CONFIG          = 56,
    FCE_DBDIRACCESS     = 57,
    FCE_FAILEDGET       = 58,
    FCE_MIRRORNOTSYNC   = 59,

    FCE_USERINFO        = 60,
    FCE_USERORGROUP     = 61,
    FCE_LOGGING         = 62,

    FCE_FAILEDUPDATE    = 70,
    FCE_MEM             = 75,
    FCE_ARG             = 76,
    FCE_OPEN            = 77
} fc_error_t;

#endif
