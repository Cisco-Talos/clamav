#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CLAMUKO
/* DazukoXP Interface. Interace with Dazuko for file access control.
   Written by John Ogness <jogness@antivir.de>

   Copyright (c) 2002, 2003, 2004 H+BEDV Datentechnik GmbH
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. Neither the name of Dazuko nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef DAZUKOIO_XP_H
#define DAZUKOIO_XP_H

/* various requests */
#define SET_ACCESS_MASK		0
#define ADD_INCLUDE_PATH	1
#define ADD_EXCLUDE_PATH	2
#define REGISTER		3
#define REMOVE_ALL_PATHS	4
#define UNREGISTER		5
#define GET_AN_ACCESS		6
#define RETURN_AN_ACCESS	7

/* this is just a large number to "guarentee"
   to contain the full filename */
#define DAZUKO_FILENAME_MAX_LENGTH	6144

/* this is the hard-limit file length restriction from
   the 1.x series */
#define DAZUKO_FILENAME_MAX_LENGTH_COMPAT12	4095

struct dazuko_request
{
	char	type[2];
	int	buffer_size;
	char	*buffer;
	int	reply_buffer_size;
	char	*reply_buffer;
	int	reply_buffer_size_used;
};

struct dazuko_id
{
	int	device;
	int	dev_major;
	int	id;
	int	write_mode;
};

/* compat12 ioctls */

#define	IOCTL_SET_OPTION	0
#define	IOCTL_GET_AN_ACCESS	1
#define	IOCTL_RETURN_ACCESS	2

/* compat12 structures */

struct access_compat12
{
	int	deny;		/* set to deny file access */
	int	event;		/* ON_OPEN, etc */
	int	o_flags;	/* access flags */
	int	o_mode;		/* access mode */
	int	uid;		/* user id */
	int	pid;		/* user process id */
	char	filename[DAZUKO_FILENAME_MAX_LENGTH_COMPAT12];	/* accessed file */
};

struct option_compat12
{
	int	command;
	int	buffer_length;
	char	buffer[DAZUKO_FILENAME_MAX_LENGTH_COMPAT12];
};

#endif
#endif
