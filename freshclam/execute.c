/*
 *  By Per Jessen <per@computer.org>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "defaults.h"
#include "freshclam.h"
#include "output.h"

int active_children;

void execute( const char *type, const char *text )
{
	pid_t pid;

	if ( active_children<CL_MAX_CHILDREN )
	switch( pid=fork() ) {
	case 0:
		if ( -1==system(text) )
		{
		mprintf("@%s: couldn't execute \"%s\".\n", type, text);
		}
		exit(0);
	case -1:
		mprintf("@%s::fork() failed, %s.\n", type, strerror(errno));
		break;
	default:
		active_children++;
	}
	else
	{
		mprintf("@%s: already %d processes active.\n", type, active_children);
	}
}
