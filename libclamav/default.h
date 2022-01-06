/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __DEFAULT_H
#define __DEFAULT_H

// clang-format off

#define CLI_DEFAULT_AC_MINDEPTH  2
#define CLI_DEFAULT_AC_MAXDEPTH  3
#define CLI_DEFAULT_AC_TRACKLEN  8

#define CLI_DEFAULT_LSIG_BUFSIZE 32768
#define CLI_DEFAULT_DBIO_BUFSIZE CLI_DEFAULT_LSIG_BUFSIZE + 1

#define CLI_DEFAULT_BM_OFFMODE_FSIZE 262144

#define CLI_DEFAULT_TIMELIMIT     (1000 * 60 * 2)       // 2 minutes
#define CLI_DEFAULT_MAXSCANSIZE   (1024 * 1024 * 100)   // 100 MB
#define CLI_DEFAULT_MAXFILESIZE   (1024 * 1024 * 25)    // 25 MB
#define CLI_DEFAULT_MAXRECLEVEL   17
#define CLI_DEFAULT_MAXFILES      10000
#define CLI_DEFAULT_MIN_CC_COUNT  3
#define CLI_DEFAULT_MIN_SSN_COUNT 3

#define CLI_DEFAULT_MAXEMBEDDEDPE      10485760
#define CLI_DEFAULT_MAXHTMLNORMALIZE   10485760
#define CLI_DEFAULT_MAXHTMLNOTAGS      2097152
#define CLI_DEFAULT_MAXSCRIPTNORMALIZE 5242880
#define CLI_DEFAULT_MAXZIPTYPERCG      1048576
#define CLI_DEFAULT_MAXICONSPE         100
#define CLI_DEFAULT_MAXRECHWP3         16

#define CLI_DEFAULT_MAXPARTITIONS 50

/* TODO - set better defaults */
#define CLI_DEFAULT_PCRE_MATCH_LIMIT    100000
#define CLI_DEFAULT_PCRE_RECMATCH_LIMIT 2000
#define CLI_DEFAULT_PCRE_MAX_FILESIZE   26214400

// clang-format on

#endif
