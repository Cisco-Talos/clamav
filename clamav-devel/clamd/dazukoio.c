/* Dazuko Interface. Interace with Dazuko for file access control.
   Copyright (C) 2002 H+BEDV Datentechnik GmbH
   Written by John Ogness <jogness@antivir.de>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CLAMUKO

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "dazukoio.h"

int	_DAZUKO_DEVICE;
int	_DAZUKO_DEV_MAJOR;

int dazukoRegister(void)
{
	char	buffer[10];

	_DAZUKO_DEVICE = open("/dev/dazuko", 0);
	if (_DAZUKO_DEVICE < 0)
		return -1;

	bzero(buffer, sizeof(buffer));
	if (read(_DAZUKO_DEVICE, buffer, sizeof(buffer)-1) < 1)
	{
		close(_DAZUKO_DEVICE);
		return -1;
	}
	_DAZUKO_DEV_MAJOR = atoi(buffer);

	return 0;
}

int dazukoSetAccessMask(unsigned long accessMask)
{
	struct option_t	opt;

	bzero(&opt, sizeof(opt));

	opt.command = SET_ACCESS_MASK;
	opt.buffer[0] = (char)accessMask;
	opt.buffer_length = 1;

	if (ioctl(_DAZUKO_DEVICE, _IOW(_DAZUKO_DEV_MAJOR, IOCTL_SET_OPTION, void *), &opt) != 0)
		return -1;

	return 0;
}

int dazuko_set_path(const char *path, int command)
{
	struct option_t	opt;

	if (path == NULL)
		return -1;

	bzero(&opt, sizeof(opt));

	opt.command = command;
	strncpy(opt.buffer, path, sizeof(opt.buffer) - 1);
	opt.buffer_length = strlen(opt.buffer) + 1;

	if (ioctl(_DAZUKO_DEVICE, _IOW(_DAZUKO_DEV_MAJOR, IOCTL_SET_OPTION, void *), &opt) != 0)
		return -1;

	return 0;
}

int dazukoAddIncludePath(const char *path)
{
	return dazuko_set_path(path, ADD_INCLUDE_PATH);
}

int dazukoAddExcludePath(const char *path)
{
	return dazuko_set_path(path, ADD_EXCLUDE_PATH);
}

int dazukoRemoveAllPaths(void)
{
	struct option_t	opt;

	bzero(&opt, sizeof(opt));

	opt.command = REMOVE_ALL_PATHS;
	opt.buffer_length = 0;

	if (ioctl(_DAZUKO_DEVICE, _IOW(_DAZUKO_DEV_MAJOR, IOCTL_SET_OPTION, void *), &opt) != 0)
		return -1;

	return 0;

}

int dazukoGetAccess(struct access_t *acc)
{
	if (acc == NULL)
		return -1;

	bzero(acc, sizeof(struct access_t));

	if (ioctl(_DAZUKO_DEVICE, _IOR(_DAZUKO_DEV_MAJOR, IOCTL_GET_AN_ACCESS, struct access_t *), acc) != 0)
		return -1;

	return 0;
}

int dazukoReturnAccess(struct access_t *acc)
{
	if (acc == NULL)
		return -1;

	if (ioctl(_DAZUKO_DEVICE, _IOW(_DAZUKO_DEV_MAJOR, IOCTL_RETURN_ACCESS, struct access_t *), acc) != 0)
		return -1;

	return 0;
}

int dazukoUnregister(void)
{
	return close(_DAZUKO_DEVICE);
}

#endif
