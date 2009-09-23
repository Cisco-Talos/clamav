/* userspace library to interface with dazukofs

   Copyright (C) 2008-2009 John Ogness
     Author: John Ogness <dazukocode@ogness.net>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "dazukofs.h"

struct dazukofs_handle
{
	int dev_fd;
	unsigned long event_id;
	char *group_name;
};

#define DAZUKOFS_ALLOWED_GROUPCHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
static int check_group_name(const char *gname)
{
	size_t len = strlen(gname);
	const char *p;

	if (len > 20)
		return -1;

	for (p = gname; *p; p++) {
		if (strchr(DAZUKOFS_ALLOWED_GROUPCHARS, *p) == NULL)
			return -1;
	}

	return 0;
}

dazukofs_handle_t dazukofs_open(const char *gname, int flags)
{
	struct dazukofs_handle *hndl = NULL;
	char key[25];
	char buf[256];
	char *p;
	int gid;
	int fd;

	if (check_group_name(gname) != 0)
		goto error_out;

	fd = open("/dev/dazukofs.ctrl", O_RDWR);
	if (fd == -1) {
		/* try to read at least
		 * (maybe the group already exists) */
		fd = open("/dev/dazukofs.ctrl", O_RDONLY);
		if (fd == -1)
			goto error_out;
	} else {
		memset(buf, 0, sizeof(buf));

		if (flags & DAZUKOFS_TRACK_GROUP)
			snprintf(buf, sizeof(buf) - 1, "addtrack=%s", gname);
		else
			snprintf(buf, sizeof(buf) - 1, "add=%s", gname);

		if (write(fd, buf, strlen(buf)) == -1)
			goto error_out_close;

		lseek(fd, 0, SEEK_SET);
	}

	memset(buf, 0, sizeof(buf));
	if (read(fd, buf, sizeof(buf)-1) == -1)
		goto error_out_close;

	memset(key, 0, sizeof(key));
	snprintf(key, sizeof(key) - 1, ":%s\n", gname);

	p = strstr(buf, key);
	if (!p || p == buf)
		goto error_out_close;

	p--;
	gid = *p - '0';
	if (gid < 0 || gid > 9)
		goto error_out_close;

	hndl = malloc(sizeof(struct dazukofs_handle));
	if (!hndl)
		goto error_out_close;
	memset(hndl, 0, sizeof(struct dazukofs_handle));

	hndl->group_name = strdup(gname);
	if (!hndl->group_name)
		goto error_out_free;

	memset(key, 0, sizeof(key));
	snprintf(key, sizeof(key) - 1, "/dev/dazukofs.%d", gid);

	hndl->dev_fd = open(key, O_RDWR);
	if (hndl->dev_fd == -1)
		goto error_out_free;

	close(fd);

	return hndl;

error_out_free:
	if (hndl->group_name)
		free(hndl->group_name);
	free(hndl);
	hndl = NULL;
error_out_close:
	close(fd);
error_out:
	return hndl;
}

int dazukofs_close(dazukofs_handle_t hndl, int flags)
{
	char buf[48];
	int fd;
	int ret = -1;

	if (flags & DAZUKOFS_REMOVE_GROUP) {
		fd = open("/dev/dazukofs.ctrl", O_WRONLY);
		if (fd == -1)
			goto error_out;

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1, "del=%s", hndl->group_name);

		if (write(fd, buf, strlen(buf)) == -1) {
			close(fd);
			goto error_out;
		}

		close(fd);
	}

	ret = close(hndl->dev_fd);
	if (ret != 0)
		goto error_out;

	free(hndl->group_name);
	free(hndl);

	return 0;

error_out:
	return ret;
}

int dazukofs_get_access(dazukofs_handle_t hndl, struct dazukofs_access *acc)
{
	char buf[48];
	char *p;
	int err = -1;

	memset(buf, 0, sizeof(buf));
	if (read(hndl->dev_fd, buf, sizeof(buf)-1) == -1)
		goto out;

	p = strstr(buf, "id=");
	if (!p)
		goto out;
	p += 3;
	hndl->event_id = strtoul(p, &p, 10);

	p = strstr(p, "fd=");
	if (!p)
		goto out;
	p += 3;
	acc->fd = (int)strtol(p, &p, 10);

	p = strstr(p, "pid=");
	if (!p)
		goto out;
	p += 4;
	acc->pid = strtoul(p, NULL, 10);

	acc->deny = 0;

	err = 0;
out:
	return err;
}

int dazukofs_return_access(dazukofs_handle_t hndl, struct dazukofs_access *acc)
{
	char buf[48];
	int err = -1;

	if (close(acc->fd) != 0)
		goto out;
	snprintf(buf, sizeof(buf)-1, "id=%lu r=%d", hndl->event_id,
		 acc->deny ? 1 : 0);
	buf[sizeof(buf)-1] = 0;

	if (write(hndl->dev_fd, buf, strlen(buf)) == -1)
		goto out;
	lseek(hndl->dev_fd, 0, SEEK_SET);
	err = 0;
out:
	return err;
}

int dazukofs_get_filename(struct dazukofs_access *acc, char *buf, size_t bufsiz)
{
	char proc[48];
	int ret;

	memset(proc, 0, sizeof(proc));
	snprintf(proc, sizeof(proc) - 1, "/proc/self/fd/%d", acc->fd);
	ret = readlink(proc, buf, bufsiz - 1);
	buf[bufsiz - 1] = 0;
	if (ret > 0)
		buf[ret] = 0;

	return ret;
}
