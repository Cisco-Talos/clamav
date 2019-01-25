/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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

#ifndef __BLOB_H
#define __BLOB_H

/*
 * Resizable chunk of memory
 */
typedef struct blob {
	char	*name;	/* filename */
	unsigned	char	*data;	/* the stuff itself */
	off_t	len;	/* number of bytes of data so far */
	off_t	size;	/* number of bytes allocated to data so far */
	int	isClosed;
#ifdef	CL_DEBUG
	object_type	magic;	/* verify that this is a blob */
#endif
} blob;

blob	*blobCreate(void);
void	blobDestroy(blob *b);
void	blobArrayDestroy(blob *b[], int n);
void	*blobToMem(blob *b);
void	blobSetFilename(blob *b, const char *dir, const char *filename);
int	blobAddData(blob *b, const unsigned char *data, size_t len);
unsigned char *blobGetData(const blob *b);
size_t	blobGetDataSize(const blob *b);
void	blobClose(blob *b);
int	blobcmp(const blob *b1, const blob *b2);
int	blobGrow(blob *b, size_t len);

/*
 * Like a blob, but associated with a file stored in the temporary directory
 */
typedef	struct fileblob {
	FILE	*fp;
	int	fd;
	blob	b;	/*
			 * b.name is the name of the attachment as stored in the
			 * email, not the full path name of the temporary file
			 */
	char	*fullname;	/* full pathname of the file */
	cli_ctx	*ctx;	/* When set we can scan the blob, otherwise NULL */
	unsigned	long	bytes_scanned;
	unsigned	int	isNotEmpty : 1;
	unsigned	int	isInfected : 1;
} fileblob;

fileblob	*fileblobCreate(void);
int	fileblobScanAndDestroy(fileblob *fb);
void	fileblobDestructiveDestroy(fileblob *fb);
void	fileblobDestroy(fileblob *fb);
void	fileblobSetFilename(fileblob *fb, const char *dir, const char *filename);
void    fileblobPartialSet(fileblob *fb, const char *fullname, const char *arg);
const	char	*fileblobGetFilename(const fileblob *fb);
void	fileblobSetCTX(fileblob *fb, cli_ctx *ctx);
int	fileblobAddData(fileblob *fb, const unsigned char *data, size_t len);
int	fileblobScan(const fileblob *fb);
int	fileblobInfected(const fileblob *fb);
void	sanitiseName(char *name);

#endif /*_BLOB_H*/
