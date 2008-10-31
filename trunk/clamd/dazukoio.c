#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CLAMUKO
/* Dazuko Interface. Interace with Dazuko for file access control.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <unistd.h>
#include "dazukoio_xp.h"
#include "dazukoio.h"

#if !defined(NO_COMPAT12)
#include "dazukoio_compat12.h"
#endif

#define ITOA_SIZE	32

dazuko_id_t	*_GLOBAL_DAZUKO = NULL;

#if !defined(NO_COMPAT12)
char		_GLOBAL_DAZUKO_COMPAT12 = 0;
#endif

static inline char char_to_hex(char c)
{
	/* ugly, but fast */

	switch (c)
	{
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a': case 'A': return 10;
		case 'b': case 'B': return 11;
		case 'c': case 'C': return 12;
		case 'd': case 'D': return 13;
		case 'e': case 'E': return 14;
		case 'f': case 'F': return 15;
	}

	return 0;
}

static void unescape_string(char *string)
{
	char	*p;

	for (p=string ; *p ; p++)
	{
		/* check if we have \x */
		if ((*p == '\\') && (*(p+1) == 'x'))
		{
			/* this is not cheap, but it should not occur often */

			/* check if we have two more values following \x */
			if (*(p+2) && *(p+3))
			{
				*p = char_to_hex(*(p+2));
				*p <<= 4;
				*p |= char_to_hex(*(p+3));

				memmove(p + 1, p + 4, strlen(p+4) + 1);
			}
		}
	}
}

static int get_value(const char *key, const char *string, char *buffer, size_t buffer_size)
{
	const char	*p1;
	const char	*p2;
	size_t		size;

	if (buffer == NULL || buffer_size < 1)
		return -1;

	buffer[0] = 0;

	if (key == NULL || string == NULL)
		return -1;

	p1 = strstr(string, key);
	if (p1 == NULL)
		return -1;

	p1 += strlen(key);

	for (p2=p1 ; *p2 && *p2!='\n' ; p2++)
		continue;

	size = p2 - p1;
	if (size >= buffer_size)
		size = buffer_size - 1;

	memcpy(buffer, p1, size);

	buffer[size] = 0;

	return 0;
}

int dazukoRegister(const char *groupName, const char *mode)
{
	return dazukoRegister_TS(&_GLOBAL_DAZUKO, groupName, mode);
}

int dazukoRegister_TS(dazuko_id_t **dazuko_id, const char *groupName, const char *mode)
{
	struct dazuko_request	*request;
	char			buffer[ITOA_SIZE];
	char			regMode[3];
	dazuko_id_t		*temp_id;
	ssize_t			size;
	int			write_mode = 0;
#if !defined(NO_COMPAT12)
	int			compat12_ret;
#endif

	if (dazuko_id == NULL)
		return -1;

	/* set default group name if one was not given */
	if (groupName == NULL)
		groupName = "_GENERIC";

	/* set default mode if one was not given */
	if (mode == NULL)
		mode = "r";

	if (strcasecmp(mode, "r") == 0)
	{
		strncpy(regMode, "R", sizeof(regMode));
		regMode[sizeof(regMode)-1]='\0';
		write_mode = 0;
	}
	else if (strcasecmp(mode, "r+") == 0 || strcasecmp(mode, "rw") == 0)
	{
		strncpy(regMode, "RW", sizeof(regMode));
		regMode[sizeof(regMode)-1]='\0';
		write_mode = 1;
	}
	else
	{
		return -1;
	}
	regMode[sizeof(regMode) - 1] = 0;

#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
	{
		compat12_ret = dazukoRegister_TS_compat12_wrapper(dazuko_id, groupName);

		if (compat12_ret == 0)
			(*dazuko_id)->write_mode = write_mode;

		return compat12_ret;
	}
#endif

	/* create temporary id */
	temp_id = (dazuko_id_t *)malloc(sizeof(*temp_id));
	if (temp_id == NULL)
		return -1;

	memset(temp_id, 0, sizeof(*temp_id));

	/* open device */
	temp_id->device = open("/dev/dazuko", O_RDWR);
	if (temp_id->device < 0)
	{
		free(temp_id);
		return -1;
	}

	/* read device major number */
	memset(buffer, 0, sizeof(buffer));
	if (read(temp_id->device, buffer, sizeof(buffer)-1) < 1)
	{
		close(temp_id->device);
		free(temp_id);
		return -1;
	}

	temp_id->dev_major = atoi(buffer);
	if (temp_id->dev_major < 0)
	{
		close(temp_id->device);
		free(temp_id);
		return -1;
	}

	request = (struct dazuko_request *)malloc(sizeof(*request));
	if (request == NULL)
	{
		close(temp_id->device);
		free(temp_id);
		return -1;
	}

	memset(request, 0, sizeof(*request));

	request->type[0] = REGISTER;

	size = 1 + 2 + 1 + strlen(regMode); /* \nRM=mode */
	size += 1 + 2 + 1 + strlen(groupName); /* \nGN=groupName */
	size += 1; /* \0 */

	request->buffer = (char *)malloc(size);
	if (request->buffer == NULL)
	{
		close(temp_id->device);
		free(temp_id);
		free(request);
		return -1;
	}
	snprintf(request->buffer, size, "\nRM=%s\nGN=%s", regMode, groupName);
	request->buffer[size - 1] = 0;

	request->buffer_size = strlen(request->buffer) + 1;

	size = 4096;
	request->reply_buffer = (char *)malloc(size);
	if (request->reply_buffer == NULL)
	{
		close(temp_id->device);
		free(temp_id);
		free(request->buffer);
		free(request);
		return -1;
	}
	memset(request->reply_buffer, 0, size);
	request->reply_buffer_size = size;

	snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
	buffer[sizeof(buffer)-1] = 0;
	size = strlen(buffer) + 1;

	if (write(temp_id->device, buffer, size) != size)
	{
		close(temp_id->device);
		free(temp_id);
		free(request->buffer);
		free(request->reply_buffer);
		free(request);

#if !defined(NO_COMPAT12)
		/* we try compat12 mode */
		compat12_ret = dazukoRegister_TS_compat12_wrapper(dazuko_id, groupName);
		if (compat12_ret == 0)
		{
			(*dazuko_id)->write_mode = write_mode;
			_GLOBAL_DAZUKO_COMPAT12 = 1;
		}

		return compat12_ret;
#else
		return -1;
#endif
	}

	if (get_value("\nID=", request->reply_buffer, buffer, sizeof(buffer)) != 0)
	{
		close(temp_id->device);
		free(temp_id);
		free(request->buffer);
		free(request->reply_buffer);
		free(request);

#if !defined(NO_COMPAT12)
		/* we try compat12 mode */
		compat12_ret = dazukoRegister_TS_compat12_wrapper(dazuko_id, groupName);
		if (compat12_ret == 0)
		{
			(*dazuko_id)->write_mode = write_mode;
			_GLOBAL_DAZUKO_COMPAT12 = 1;
		}

		return compat12_ret;
#else
		return -1;
#endif
	}

	temp_id->id = atoi(buffer);

	if (temp_id->id < 0)
	{
		close(temp_id->device);
		free(temp_id);
		free(request->buffer);
		free(request->reply_buffer);
		free(request);

		return -1;
	}

	temp_id->write_mode = write_mode;

	free(request->buffer);
	free(request->reply_buffer);
	free(request);

	*dazuko_id = temp_id;

	return 0;
}

int dazukoSetAccessMask(unsigned long accessMask)
{
	return dazukoSetAccessMask_TS(_GLOBAL_DAZUKO, accessMask);
}

int dazukoSetAccessMask_TS(dazuko_id_t *dazuko_id, unsigned long accessMask)
{
	struct dazuko_request	*request;
	ssize_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
		return dazukoSetAccessMask_TS_compat12(dazuko_id, accessMask);
#endif

	if (dazuko_id->device < 0 || dazuko_id->dev_major < 0 || dazuko_id->id < 0)
		return -1;

	request = (struct dazuko_request *)malloc(sizeof(*request));
	if (request == NULL)
		return -1;

	memset(request, 0, sizeof(*request));

	request->type[0] = SET_ACCESS_MASK;

	size = 1 + 2 + 1 + ITOA_SIZE; /* \nID=id */
	size += 1 + 2 + 1 + ITOA_SIZE; /* \nAM=accessMask */
	size += 1; /* \0 */

	request->buffer = (char *)malloc(size);
	if (request->buffer == NULL)
	{
		free(request);
		return -1;
	}
	snprintf(request->buffer, size, "\nID=%d\nAM=%lu", dazuko_id->id, accessMask);
	request->buffer[size - 1] = 0;

	request->buffer_size = strlen(request->buffer) + 1;

	snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
	buffer[sizeof(buffer)-1] = 0;
	size = strlen(buffer) + 1;

	if (write(dazuko_id->device, buffer, size) != size)
	{
		free(request->buffer);
		free(request);
		return -1;
	}

	free(request->buffer);
	free(request);

	return 0;
}

static int dazuko_set_path(dazuko_id_t *dazuko_id, const char *path, int type)
{
	struct dazuko_request	*request;
	ssize_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

	if (dazuko_id->device < 0 || dazuko_id->dev_major < 0 || dazuko_id->id < 0)
		return -1;

	if (path == NULL)
		return -1;

	request = (struct dazuko_request *)malloc(sizeof(*request));
	if (request == NULL)
		return -1;

	memset(request, 0, sizeof(*request));

	request->type[0] = type;

	size = 1 + 2 + 1 + ITOA_SIZE; /* \nID=id */
	size += 1 + 2 + 1 + strlen(path); /* \nPT=path */
	size += 1; /* \0 */

	request->buffer = (char *)malloc(size);
	if (request->buffer == NULL)
	{
		free(request);
		return -1;
	}
	snprintf(request->buffer, size, "\nID=%d\nPT=%s", dazuko_id->id, path);
	request->buffer[size - 1] = 0;

	request->buffer_size = strlen(request->buffer) + 1;

	snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
	buffer[sizeof(buffer)-1] = 0;
	size = strlen(buffer) + 1;

	if (write(dazuko_id->device, buffer, size) != size)
	{
		free(request->buffer);
		free(request);
		return -1;
	}

	free(request->buffer);
	free(request);

	return 0;
}

int dazukoAddIncludePath(const char *path)
{
	return dazukoAddIncludePath_TS(_GLOBAL_DAZUKO, path);
}

int dazukoAddIncludePath_TS(dazuko_id_t *dazuko_id, const char *path)
{
#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
		return dazukoAddIncludePath_TS_compat12(dazuko_id, path);
#endif

	return dazuko_set_path(dazuko_id, path, ADD_INCLUDE_PATH);
}

int dazukoAddExcludePath(const char *path)
{
	return dazukoAddExcludePath_TS(_GLOBAL_DAZUKO, path);
}

int dazukoAddExcludePath_TS(dazuko_id_t *dazuko_id, const char *path)
{
#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
		return dazukoAddExcludePath_TS_compat12(dazuko_id, path);
#endif

	return dazuko_set_path(dazuko_id, path, ADD_EXCLUDE_PATH);
}

int dazukoRemoveAllPaths(void)
{
	return dazukoRemoveAllPaths_TS(_GLOBAL_DAZUKO);
}

int dazukoRemoveAllPaths_TS(dazuko_id_t *dazuko_id)
{
	struct dazuko_request	*request;
	ssize_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
		return dazukoRemoveAllPaths_TS_compat12(dazuko_id);
#endif

	if (dazuko_id->device < 0 || dazuko_id->dev_major < 0 || dazuko_id->id < 0)
		return -1;

	request = (struct dazuko_request *)malloc(sizeof(*request));
	if (request == NULL)
		return -1;

	memset(request, 0, sizeof(*request));

	request->type[0] = REMOVE_ALL_PATHS;

	size = 1 + 2 + 1 + ITOA_SIZE; /* \nID=id */
	size += 1; /* \0 */

	request->buffer = (char *)malloc(size);
	if (request->buffer == NULL)
	{
		free(request);
		return -1;
	}
	snprintf(request->buffer, size, "\nID=%d", dazuko_id->id);
	request->buffer[size - 1] = 0;

	request->buffer_size = strlen(request->buffer) + 1;

	snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
	buffer[sizeof(buffer)-1] = 0;
	size = strlen(buffer) + 1;

	if (write(dazuko_id->device, buffer, size) != size)
	{
		free(request->buffer);
		free(request);
		return -1;
	}

	free(request->buffer);
	free(request);

	return 0;
}

int dazukoGetAccess(struct dazuko_access **acc)
{
	return dazukoGetAccess_TS(_GLOBAL_DAZUKO, acc);
}

int dazukoGetAccess_TS(dazuko_id_t *dazuko_id, struct dazuko_access **acc)
{
	struct dazuko_request	*request;
	struct dazuko_access	*temp_acc;
	ssize_t			size;
	size_t			filename_size;
	char			buffer[ITOA_SIZE];
#if !defined(NO_COMPAT12)
	int			compat12_ret;
#endif

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
	{
		compat12_ret = dazukoGetAccess_TS_compat12_wrapper(dazuko_id, acc);

		if (compat12_ret == 0 && !(dazuko_id->write_mode))
		{
			/* we are in read_only mode so we return the access immediately */

			dazukoReturnAccess_TS_compat12_wrapper(dazuko_id, acc, 1, 0);

			/* this could be dangerous, we do not check if the return was successfull! */
		}

		return compat12_ret;
	}
#endif

	if (dazuko_id->device < 0 || dazuko_id->dev_major < 0 || dazuko_id->id < 0)
		return -1;

	if (acc == NULL)
		return -1;

	request = (struct dazuko_request *)malloc(sizeof(*request));
	if (request == NULL)
		return -1;

	memset(request, 0, sizeof(*request));

	request->type[0] = GET_AN_ACCESS;

	size = 1 + 2 + 1 + ITOA_SIZE; /* \nID=id */
	size += 1; /* \0 */

	request->buffer = (char *)malloc(size);
	if (request->buffer == NULL)
	{
		free(request);
		return -1;
	}
	snprintf(request->buffer, size, "\nID=%d", dazuko_id->id);
	request->buffer[size - 1] = 0;

	request->buffer_size = strlen(request->buffer) + 1;

	size = 1 + 2 + 1 + DAZUKO_FILENAME_MAX_LENGTH; /* \nFN=filename */
	size += 1024; /* miscellaneous access attributes */
	size += 1; /* \0 */
	request->reply_buffer = (char *)malloc(size);
	if (request->reply_buffer == NULL)
	{
		free(request->buffer);
		free(request);
		return -1;
	}
	memset(request->reply_buffer, 0, size);
	request->reply_buffer_size = size;

	temp_acc = (struct dazuko_access *)malloc(sizeof(*temp_acc));
	if (temp_acc == NULL)
	{
		free(request->reply_buffer);
		free(request->buffer);
		free(request);
		return -1;
	}

	memset(temp_acc, 0, sizeof(*temp_acc));

	filename_size = DAZUKO_FILENAME_MAX_LENGTH + 1;
	temp_acc->filename = (char *)malloc(filename_size);
	if (temp_acc->filename == NULL)
	{
		free(temp_acc);
		free(request->reply_buffer);
		free(request->buffer);
		free(request);
		return -1;
	}

	snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
	buffer[sizeof(buffer)-1] = 0;
	size = strlen(buffer) + 1;

	if (write(dazuko_id->device, buffer, size) != size)
	{
		free(temp_acc->filename);
		free(temp_acc);
		free(request->reply_buffer);
		free(request->buffer);
		free(request);
		return -1;
	}

	if (request->reply_buffer_size_used > 0)
	{
		if (get_value("\nFN=", request->reply_buffer, temp_acc->filename, filename_size) == 0)
		{
			temp_acc->set_filename = 1;
			unescape_string(temp_acc->filename);
		}

		if (get_value("\nEV=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->event = atoi(buffer);
			temp_acc->set_event = 1;
		}

		if (get_value("\nFL=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->flags = atoi(buffer);
			temp_acc->set_flags = 1;
		}

		if (get_value("\nMD=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->mode = atoi(buffer);
			temp_acc->set_mode = 1;
		}

		if (get_value("\nUI=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->uid = atoi(buffer);
			temp_acc->set_uid = 1;
		}

		if (get_value("\nPI=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->pid = atoi(buffer);
			temp_acc->set_pid = 1;
		}

		if (get_value("\nFS=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_size = atol(buffer);
			temp_acc->set_file_size = 1;
		}

		if (get_value("\nFU=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_uid = atoi(buffer);
			temp_acc->set_file_uid = 1;
		}

		if (get_value("\nFG=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_gid = atoi(buffer);
			temp_acc->set_file_gid = 1;
		}

		if (get_value("\nDT=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_device = atoi(buffer);
			temp_acc->set_file_device = 1;
		}
	}

	free(request->reply_buffer);
	free(request->buffer);
	free(request);

	*acc = temp_acc;

	return 0;
}

int dazukoReturnAccess(struct dazuko_access **acc)
{
	return dazukoReturnAccess_TS(_GLOBAL_DAZUKO, acc);
}

int dazukoReturnAccess_TS(dazuko_id_t *dazuko_id, struct dazuko_access **acc)
{
	struct dazuko_request	*request;
	ssize_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
		return dazukoReturnAccess_TS_compat12_wrapper(dazuko_id, acc, dazuko_id->write_mode, 1);
#endif

	if (dazuko_id->device < 0 || dazuko_id->dev_major < 0 || dazuko_id->id < 0)
		return -1;

	if (acc == NULL)
		return -1;

	if (*acc == NULL)
		return -1;

	if (dazuko_id->write_mode)
	{
		request = (struct dazuko_request *)malloc(sizeof(*request));
		if (request == NULL)
			return -1;

		memset(request, 0, sizeof(*request));

		request->type[0] = RETURN_AN_ACCESS;

		size = 1 + 2 + 1 + ITOA_SIZE; /* \nID=id */
		size += 1 + 2 + 1 + ITOA_SIZE; /* \nDN=deny */
		size += 1; /* \0 */

		request->buffer = (char *)malloc(size);
		if (request->buffer == NULL)
		{
			free(request);
			return -1;
		}
		snprintf(request->buffer, size, "\nID=%d\nDN=%d", dazuko_id->id, (*acc)->deny == 0 ? 0 : 1);
		request->buffer[size - 1] = 0;

		request->buffer_size = strlen(request->buffer) + 1;

		snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
		buffer[sizeof(buffer)-1] = 0;
		size = strlen(buffer) + 1;

		if (write(dazuko_id->device, buffer, size) != size)
		{
			/* there could be big problems if this happens */

			if ((*acc)->filename != NULL)
				free((*acc)->filename);
			free(*acc);
			*acc = NULL;
			free(request->buffer);
			free(request);
			return -1;
		}

		free(request->buffer);
		free(request);
	}

	if ((*acc)->filename != NULL)
		free((*acc)->filename);
	free(*acc);
	*acc = NULL;

	return 0;
}

int dazukoUnregister(void)
{
	return dazukoUnregister_TS(&_GLOBAL_DAZUKO);
}

int dazukoUnregister_TS(dazuko_id_t **dazuko_id)
{
	struct dazuko_request	*request;
	ssize_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT12)
	if (_GLOBAL_DAZUKO_COMPAT12)
		return dazukoUnregister_TS_compat12_wrapper(dazuko_id);
#endif

	if (*dazuko_id == NULL)
		return -1;

	if ((*dazuko_id)->device < 0)
		return -1;

	if ((*dazuko_id)->dev_major >= 0 && (*dazuko_id)->id >= 0)
	{
		request = (struct dazuko_request *)malloc(sizeof(*request));
		if (request == NULL)
			return -1;

		memset(request, 0, sizeof(*request));

		request->type[0] = UNREGISTER;

		size = 1 + 2 + 1 + ITOA_SIZE; /* \nID=id */
		size += 1; /* \0 */

		request->buffer = (char *)malloc(size);
		if (request->buffer == NULL)
		{
			free(request);
			return -1;
		}
		snprintf(request->buffer, size, "\nID=%d", (*dazuko_id)->id);
		request->buffer[size - 1] = 0;

		request->buffer_size = strlen(request->buffer) + 1;

		snprintf(buffer, sizeof(buffer), "\nRA=%lu", (unsigned long)request);
		buffer[sizeof(buffer)-1] = 0;
		size = strlen(buffer) + 1;

		if (write((*dazuko_id)->device, buffer, size) != size)
		{
			/* there could be big problems if this happens */

			close((*dazuko_id)->device);
			free(*dazuko_id);
			*dazuko_id = NULL;
			free(request->buffer);
			free(request);
			return -1;
		}

		free(request->buffer);
		free(request);
	}

	close((*dazuko_id)->device);
	free(*dazuko_id);
	*dazuko_id = NULL;

	return 0;
}
#endif
