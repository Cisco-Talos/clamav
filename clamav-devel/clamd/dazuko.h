/* Dazuko. Allow file access control for 3rd-party applications.
   Copyright (C) 2002 H+BEDV Datentechnik GmbH
   Written by Martin Ritter <mritter@antivir.de>
              John Ogness <jogness@antivir.de>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifdef CLAMUKO

#ifndef DAZUKO_H
#define DAZUKO_H

//#define VERSION				"1.1.0"
#define	DEVICE_NAME			"dazuko"
#define DAZUKO_FILENAME_MAX_LENGTH	4095

/* ioctl values */
#define	IOCTL_SET_OPTION	0
#define	IOCTL_GET_AN_ACCESS	1
#define	IOCTL_RETURN_ACCESS	2

/* event types */
#define	ON_OPEN			1
#define	ON_CLOSE		2
#define	ON_EXEC 		4

struct access_t
{
	int	deny;		/* set to deny file access */
	int	event;		/* ON_OPEN, etc */
	int	o_flags;	/* access flags */
	int	o_mode;		/* access mode */
	int	uid;		/* user id */
	int	pid;		/* user process id */
	char	filename[DAZUKO_FILENAME_MAX_LENGTH];	/* accessed file */
};

/* various set option commands */
#define SET_ACCESS_MASK		0
#define ADD_INCLUDE_PATH	1
#define ADD_EXCLUDE_PATH	2
#define REMOVE_ALL_PATHS	4

#endif
#endif
