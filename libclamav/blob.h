/*
 *  Copyright (C) 2002 Nigel Horne <njh@bandsman.co.uk>
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
 *
 * $LOG$
 */

#ifndef __BLOB_H
#define __BLOB_H

/*
 * Resizable chunk of memory
 */
typedef struct blob {
	char	*name;	/* filename */
	unsigned	char	*data;	/* the stuff itself */
	unsigned	long	len;	/* number of bytes of data so far */
	unsigned	long	size;	/* number of bytes allocated to data so far */
	int	isClosed;
#ifdef	CL_DEBUG
	object_type	magic;	/* verify that this is a blob */
#endif
} blob;

blob	*blobCreate(void);
void	blobDestroy(blob *b);
void	blobArrayDestroy(blob *b[], int n);
void	blobSetFilename(blob *b, const char *dir, const char *filename);
const	char	*blobGetFilename(const blob *b);
void	blobAddData(blob *b, const unsigned char *data, size_t len);
unsigned char *blobGetData(const blob *b);
unsigned	long	blobGetDataSize(const blob *b);
void	blobClose(blob *b);
int	blobcmp(const blob *b1, const blob *b2);
void	blobGrow(blob *b, size_t len);

/*
 * Like a blob, but associated with a file
 */
typedef	struct fileblob {
	FILE	*fp;
	blob	b;
} fileblob;

fileblob	*fileblobCreate(void);
void	fileblobDestroy(fileblob *fb);
void	fileblobSetFilename(fileblob *fb, const char *dir, const char *filename);
const	char	*fileblobGetFilename(const fileblob *fb);
void	fileblobAddData(fileblob *fb, const unsigned char *data, size_t len);
void	sanitiseName(char *name);

#endif /*_BLOB_H*/
