/*
 *  Copyright (C) 2005 Nigel Horne <njh@bandsman.co.uk>
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

static	char	const	rcsid[] = "$Id: tnef.c,v 1.4 2005/03/25 15:54:59 nigelhorne Exp $";

#include "tnef.h"
#include "clamav.h"

int
cli_tnef(const char *dir, int desc)
{
	cli_warnmsg("TNEF not scanned yet - virus samples are welcome\n");

	return CL_CLEAN;
}
