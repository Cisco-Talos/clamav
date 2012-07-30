/*
 * Copyright (C) 2010 Sourcefire, Inc.
 * Authors: aCaB <acab@clamav.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

#ifndef _CLUPDATE_H
#define _CLUPDATE_H

/* Possible states during update */
typedef enum _AV_UPD_STATE
{
	UPD_CHECK,
	UPD_NEWER_FOUND,
	UPD_NONE,
	UPD_DOWNLOAD_BEGIN,
	UPD_DOWNLOAD_COMPLETE,
	UPD_PAUSE,
	UPD_ABORT,
	UPD_DONE,
	UPD_INSTALL_BEGIN,
	UPD_INSTALL_COMPLETE,
	UPD_FILE_BEGIN,
	UPD_FILE_COMPLETE,
	UPD_FILE_PROGRESS,
	UPD_STOP, /* Used by external module to stop the update */
}AV_UPD_STATE;

#define AV_UPD_FILE_NAME_MAX   16

typedef struct _AV_UPD_STATUS
{
	int state;				/* AV_UPD_STATE */
	int status;				/* 0 -> Success, anything else failure */
	int totalFiles;				/* incase there update happens with multiple files */
	int percentDownloaded;			/* file downloaded in % */
	WCHAR fileName[AV_UPD_FILE_NAME_MAX];	/* the current filename */
	DWORD pid;
}AV_UPD_STATUS, *PAV_UPD_STATUS;

#endif /* _CLUPDATE_H */
