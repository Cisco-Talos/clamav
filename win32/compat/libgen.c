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
#include "libgen.h"

/* 
Note: an exact implementation of is not really possible, but this is good enough for us

*path*				*dirname*		    *basename*

"C:"				"C:"			    ""
"C:\"				"C:"			    ""
"C:\\"				"C:"			    ""
"C:file"			"C:file"		    ""
"C:file\"			"C:file"		    ""
"C:\file"			"C:"			    "file"
"C:\file\"			"C:"			    "file"
"C:\path\file"			"C:\path"		    "file"
"C:\path\file\"			"C:\path"		    "file"

"\\net"				"\\net"			    ""
"\\net\"			"\\net"			    ""
"\\net\share"			"\\net"			    "share"
"\\net\share\"			"\\net"			    "share"
"\\net\share\file"		"\\net\share"		    "file"
"\\net\share\file\"		"\\net\share"		    "file"
"\\net\share\path\file"	"\\net\share\path"	    "file"
"\\net\share\path\file\"	"\\net\share\path"	    "file"

"\\?\C:"			"\\?\C:"		    ""
"\\?\C:\"			"\\?\C:"		    ""
"\\?\C:\\"			"\\?\C:"		    ""
"\\?\C:\file"			"\\?\C:"		    "file"
"\\?\C:\file\"			"\\?\C:"		    "file"
"\\?\C:\path\file"		"\\?\C:\path"		    "file"
"\\?\C:\path\file\"		"\\?\C:\path"		    "file"

"\"				""			    ""
"\\"				""			    ""
"\file"				""			    "file"
"\file\"			""			    "file"
"\path\file"			"\path"			    "file"
"\path\file\"			"\path"			    "file"

"."				"."			    ""
".\"				"."			    ""
".."				".."			    ""
"..\"				".."			    ""
"file"				"."			    "file"
"file\"				"."			    "file"
"path\file"			"path"			    "file"
"path\file\"			"path"			    "file"

"\\.\PhysicalDrive0"		"\\.\PhysicalDrive0"	    ""
"\\.\PhysicalDrive0\other"	"\\.\PhysicalDrive0"	    "other"

""				"."			    ""
NULL				"."			    ""


Hopefully I didn't miss anything...

*/


static void splitpath(char *path, char **dir, char **base) {
    char *startpath, *endpath;
    int len;
    if(!path || !(len = strlen(path))) {
	*dir = ".";
	*base = "";
	return;
    }

    endpath = &path[len-1];
    while(endpath >= path && *endpath == '\\') {
	*endpath = '\0';
	endpath--;
    }
    if(endpath < path) {
	*dir = "";
	*base = "";
	return;
    }
    len = endpath-path + 1;
    if(len > 2 && path[0] == '\\' && path[1] == '\\') {
	if(len > 4 && (path[2] == '.' || path[2] == '?') && path[3] == '\\')
	    startpath = strchr(path + 4, '\\');
	else 
	    startpath = strchr(path + 2, '\\');

	if(!startpath) {
	    *dir = path;
	    *base = "";
	    return;
	}
	startpath ++;
    } else startpath = path;
    endpath = strrchr(startpath, '\\');
    if(!endpath) {
        if(startpath == path) {
	    if(!strcmp(path, ".") || !strcmp(path, "..") || (len >= 2 && ((*path >= 'a' && *path <= 'z') || (*path >= 'A' && *path <= 'Z')) && path[1] == ':')) {
		*dir = path;
		*base = "";
		return;
	    }
	    *dir = ".";
	    *base = path;
	    return;
	}
	*base = startpath;
	endpath = startpath - 1;
	startpath = path;
    } else {
	*base = endpath + 1;
    }
    *dir = path;

    while(endpath >= startpath && *endpath == '\\') {
	    *endpath = '\0';
	    endpath--;
    }
}

char *dirname(char *path) {
    char *dir, *base;
    splitpath(path, &dir, &base);
    return dir;
}

char *basename(char *path) {
    char *dir, *base;
    splitpath(path, &dir, &base);
    return base;
}
