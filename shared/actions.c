/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Author: aCaB
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
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/actions.h"

void (*action)(const char *) = NULL;
unsigned int notmoved = 0, notremoved = 0;

static char *actarget;
static int targlen;



static int getdest(const char *fullpath, char **newname) {
    char *tmps, *filename;
    int fd, i;

    tmps = strdup(fullpath);
    if(!tmps) {
        *newname=NULL;
        return -1;
    }
    filename = basename(tmps);

    if(!(*newname = (char *)malloc(targlen + strlen(filename) + 6))) {
	free(tmps);
	return -1;
    }
    sprintf(*newname, "%s"PATHSEP"%s", actarget, filename);
    for(i=1; i<1000; i++) {
	fd = open(*newname, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if(fd >= 0) {
	    free(tmps);
	    return fd;
	}
	if(errno != EEXIST) break;
	sprintf(*newname, "%s"PATHSEP"%s.%03u", actarget, filename, i);
    }
    free(tmps);
    free(*newname);
    *newname = NULL;
    return -1;
}

static void action_move(const char *filename) {
    char *nuname;
    int fd = getdest(filename, &nuname), copied = 0;

    if(fd<0 || (rename(filename, nuname) && (copied=1) && filecopy(filename, nuname))) {
	logg("!Can't move file %s\n", filename);
	notmoved++;
	if(nuname) unlink(nuname);
    } else {
	if(copied && unlink(filename))
	    logg("!Can't unlink '%s': %s\n", filename, strerror(errno));
	else
	    logg("~%s: moved to '%s'\n", filename, nuname);
    }

    if(fd>=0) close(fd);
    if(nuname) free(nuname);
}

static void action_copy(const char *filename) {
    char *nuname;
    int fd = getdest(filename, &nuname);

    if(fd < 0 || filecopy(filename, nuname)) {
	logg("!Can't copy file '%s'\n", filename);
	notmoved++;
	if(nuname) unlink(nuname);
    } else
	logg("~%s: copied to '%s'\n", filename, nuname);

    if(fd>=0) close(fd);
    if(nuname) free(nuname);
}

static void action_remove(const char *filename) {
    if(unlink(filename)) {
	logg("!Can't remove file '%s'.\n", filename);
	notremoved++;
    } else {
	logg("~%s: Removed.\n", filename);
    }
}

static int isdir(void) {
    STATBUF sb;
    if(CLAMSTAT(actarget, &sb) || !S_ISDIR(sb.st_mode)) {
	logg("!'%s' doesn't exist or is not a directory\n", actarget);
	return 0;
    }
    return 1;
}

int actsetup(const struct optstruct *opts) {
    int move = optget(opts, "move")->enabled;
    if(move || optget(opts, "copy")->enabled) {
	actarget = optget(opts, move ? "move" : "copy")->strarg;
	if(!isdir()) return 1;
	action = move ? action_move : action_copy;
	targlen = strlen(actarget);
    } else if(optget(opts, "remove")->enabled)
	action = action_remove;
    return 0;
}
