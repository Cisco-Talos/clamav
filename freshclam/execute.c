/*
 *  By Per Jessen <per@computer.org> with changes by the ClamAV team
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>

#include "output.h"
#include "optparser.h"
#include "execute.h"

#define MAX_CHILDREN 5

int g_active_children;

void execute(const char *type, const char *text, int bDaemonized)
{
    int ret;

    if (!bDaemonized) {
        if (sscanf(text, "EXIT_%d", &ret) == 1) {
            logg(LOGG_DEBUG, "%s: EXIT_%d\n", type, ret);
            exit(ret);
        }
        if (system(text) == -1)
            logg(LOGG_INFO, "%s: system(%s) failed\n", type, text);

        return;
    }

#ifdef _WIN32
    if (system(text) == -1) {
        logg(LOGG_WARNING, "%s: couldn't execute \"%s\".\n", type, text);
        return;
    }
#else
    if (g_active_children < MAX_CHILDREN) {
        pid_t pid;
        switch (pid = fork()) {
            case 0:
                if (-1 == system(text)) {
                    logg(LOGG_WARNING, "%s: couldn't execute \"%s\".\n", type, text);
                }
                exit(0);
            case -1:
                logg(LOGG_WARNING, "%s::fork() failed, %s.\n", type, strerror(errno));
                break;
            default:
                g_active_children++;
        }
    } else {
        logg(LOGG_WARNING, "%s: already %d processes active.\n", type, g_active_children);
    }
#endif
}
