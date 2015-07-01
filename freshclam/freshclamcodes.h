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

#define FC_UPTODATE        1

#define FCE_INIT          40
#define FCE_CHECKS        41
#define FCE_PRIVATEMIRROR 45

#define FCE_DIRECTORY     50
#define FCE_CONNECTION    52
#define FCE_EMPTYFILE     53
#define FCE_BADCVD        54
#define FCE_FILE          55
/* TESTFAIL is also 55, consider moving to new value */
#define FCE_TESTFAIL      55
#define FCE_CONFIG        56
#define FCE_DBDIRACCESS   57
#define FCE_FAILEDGET     58
#define FCE_MIRRORNOTSYNC 59

#define FCE_USERINFO      60
#define FCE_USERORGROUP   61
#define FCE_LOGGING       62

#define FCE_FAILEDUPDATE  70
#define FCE_MEM           75

#endif
