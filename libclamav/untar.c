/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 * 
 *  Summary: Extract files compressed with TAR compression format.
 * 
 *  Acknowledgements: ClamAV untar code is based on a public domain minitar utility
 *                    by Charles G. Waldman.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>	/* for NAME_MAX */
#endif

#include "clamav.h"
#include "others.h"
#include "untar.h"
#include "mbox.h"
#include "blob.h"
#include "scanners.h"
#include "matcher.h"

#define TARHEADERSIZE 512
/* BLOCKSIZE must be >= TARHEADERSIZE */
#define BLOCKSIZE TARHEADERSIZE
#define TARSIZEOFFSET 124
#define TARSIZELEN 12
#define TARCHECKSUMOFFSET 148
#define TARCHECKSUMLEN 8
#define TARFILETYPEOFFSET 156

static int
octal(const char *str)
{
	int ret;

	if(sscanf(str, "%o", (unsigned int *)&ret) != 1)
		return -1;
	return ret;
}

/**
 * Retrieve checksum values from a tar header block.
 * @param header Header data block, padded with zeroes to reach BLOCKSIZE
 * @return int value of checksum, -1 (from octal()) if bad value
 */
static int
getchecksum(const char *header)
{
	char ochecksum[TARCHECKSUMLEN + 1];
	int checksum = -1;

	strncpy(ochecksum, header+TARCHECKSUMOFFSET, TARCHECKSUMLEN);
	ochecksum[TARCHECKSUMLEN] = '\0';
	checksum = octal(ochecksum);
	return checksum;
}

/**
 * Calculate checksum values for tar header blocks.
 * @param header Header data block, padded with zeroes to reach BLOCKSIZE
 * @param targetsum Check value to match (as int not octal!)
 * @return 0 if checksum matches target, -1 if not
 */
static int
testchecksum(const char *header, int targetsum)
{
	const unsigned char *posix;	
	const signed char *legacy;
	int posix_sum = 0, legacy_sum = 0;
	int i;

	// targetsum -1 represents an error from octal()
	if (targetsum == -1) {
		return -1;
	}

	/* Build checksums. POSIX is unsigned; some legacy tars use signed. */
	posix = (unsigned char *)header;
	legacy = (signed char *)header;
	for (i = 0; i < BLOCKSIZE; i++ ) {
		if ((i >= TARCHECKSUMOFFSET) && (i < TARCHECKSUMOFFSET + TARCHECKSUMLEN)) {
			/* Use ascii value of space in place of checksum value */
			posix_sum += 32;
			legacy_sum += 32;
		}
		else {
			posix_sum += posix[i];
			legacy_sum += legacy[i];
		}
	}

	if ((targetsum == posix_sum) || (targetsum == legacy_sum)) {
		return 0;
	}
	return -1;
}

int
cli_untar(const char *dir, unsigned int posix, cli_ctx *ctx)
{
	int size = 0, ret, fout=-1;
	int in_block = 0;
	int last_header_bad = 0;
	int limitnear = 0;
	unsigned int files = 0;
	char fullname[NAME_MAX + 1];
	size_t pos = 0;
	size_t currsize = 0;
        char zero[BLOCKSIZE];
	unsigned int num_viruses = 0; 

	cli_dbgmsg("In untar(%s)\n", dir);
        memset(zero, 0, sizeof(zero));

	for(;;) {
	        const char *block;
		size_t nread;

		block = fmap_need_off_once_len(*ctx->fmap, pos, BLOCKSIZE, &nread); 
		cli_dbgmsg("cli_untar: pos = %lu\n", (unsigned long)pos);

		if(!in_block && !nread)
			break;

                if (!nread)
                    block = zero;

		if(!block) {
			if(fout>=0)
				close(fout);
			cli_errmsg("cli_untar: block read error\n");
			return CL_EREAD;
		}
		pos += nread;

		if(!in_block) {
			char type;
			int directory, skipEntry = 0;
			int checksum = -1;
			char magic[7], name[101], osize[TARSIZELEN + 1];
			currsize = 0;

			if(fout>=0) {
				lseek(fout, 0, SEEK_SET);
				ret = cli_magic_scandesc(fout, fullname, ctx);
				close(fout);
				if (!ctx->engine->keeptmp)
					if (cli_unlink(fullname)) return CL_EUNLINK;
				if (ret==CL_VIRUS) {
				    if (!SCAN_ALLMATCHES)
					return CL_VIRUS;
				    else
					num_viruses++;
				}
				fout = -1;
			}

			if(block[0] == '\0')	/* We're done */
				break;
			if((ret=cli_checklimits("cli_untar", ctx, 0, 0, 0))!=CL_CLEAN)
				return ret;

			if (nread < TARHEADERSIZE) {
				return CL_CLEAN;
			}

			checksum = getchecksum(block);
			cli_dbgmsg("cli_untar: Candidate checksum = %d, [%o in octal]\n", checksum, checksum);
			if(testchecksum(block, checksum) != 0) {
				// If checksum is bad, dump and look for next header block
				cli_dbgmsg("cli_untar: Invalid checksum in tar header. Skip to next...\n");
				if (last_header_bad == 0) {
					last_header_bad++;
					cli_dbgmsg("cli_untar: Invalid checksum found inside archive!\n");
				}
				continue;
			} else {
				last_header_bad = 0;
				cli_dbgmsg("cli_untar: Checksum %d is valid.\n", checksum);
			}

			if(posix) {
				strncpy(magic, block+257, 5);
				magic[5] = '\0';
				if(strcmp(magic, "ustar") != 0) {
					cli_dbgmsg("cli_untar: Incorrect magic string '%s' in tar header\n", magic);
					return CL_EFORMAT;
				}
			}

			type = block[TARFILETYPEOFFSET];

			switch(type) {
				default:
					cli_dbgmsg("cli_untar: unknown type flag %c\n", type);
				case '0':	/* plain file */
				case '\0':	/* plain file */
				case '7':	/* contiguous file */
				case 'M':	/* continuation of a file from another volume; might as well scan it. */
					files++;
					directory = 0;
					break;
				case '1':	/* Link to already archived file */
				case '5':	/* directory */
				case '2':	/* sym link */
				case '3':	/* char device */
				case '4':	/* block device */
				case '6':	/* fifo special */
				case 'V':	/* Volume header */
					directory = 1;
					break;
				case 'K':
				case 'L':
					/* GNU extension - ././@LongLink
					 * Discard the blocks with the extended filename,
					 * the last header will contain parts of it anyway
					 */
				case 'N': 	/* Old GNU format way of storing long filenames. */
				case 'A':	/* Solaris ACL */
				case 'E':	/* Solaris Extended attribute s*/
				case 'I':	/* Inode only */
				case 'g':	/* Global extended header */
				case 'x': 	/* Extended attributes */
				case 'X':	/* Extended attributes (POSIX) */
					directory = 0;
					skipEntry = 1;
					break;
			}

			if(directory) {
				in_block = 0;
				continue;
			}

			strncpy(osize, block+TARSIZEOFFSET, TARSIZELEN);
			osize[TARSIZELEN] = '\0';
			size = octal(osize);
			if(size < 0) {
				cli_dbgmsg("cli_untar: Invalid size in tar header\n");
				skipEntry++;
			} else {
				cli_dbgmsg("cli_untar: size = %d\n", size);
				ret = cli_checklimits("cli_untar", ctx, size, 0, 0);
				switch(ret) {
					case CL_EMAXFILES: // Scan no more files 
						skipEntry++;
						limitnear = 0;
						break;
					case CL_EMAXSIZE: // Either single file limit or total byte limit would be exceeded
						cli_dbgmsg("cli_untar: would exceed limit, will try up to max");
						limitnear = 1;
						break;
					default: // Ok based on reported content size
						limitnear = 0;
						break;
				}
			}

			if(skipEntry) {
				const int nskip = (size % BLOCKSIZE || !size) ? size + BLOCKSIZE - (size % BLOCKSIZE) : size;

				if(nskip < 0) {
					cli_dbgmsg("cli_untar: got negative skip size, giving up\n");
					return CL_CLEAN;
				}
				cli_dbgmsg("cli_untar: skipping entry\n");
				pos += nskip;
				continue;
			}

			strncpy(name, block, 100);
			name[100] = '\0';
			if(cli_matchmeta(ctx, name, size, size, 0, files, 0, NULL) == CL_VIRUS) {
			    if (!SCAN_ALLMATCHES)
				return CL_VIRUS;
			    else
				num_viruses++;
			}

			snprintf(fullname, sizeof(fullname)-1, "%s"PATHSEP"tar%02u", dir, files);
			fullname[sizeof(fullname)-1] = '\0';
			fout = open(fullname, O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);

			if(fout < 0) {
				char err[128];
				cli_errmsg("cli_untar: Can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
				return CL_ETMPFILE;
			}

			cli_dbgmsg("cli_untar: extracting to %s\n", fullname);

			in_block = 1;
		} else { /* write or continue writing file contents */
                        int nbytes, nwritten;
                        int skipwrite = 0;
                        char err[128];

			nbytes = size>512? 512:size;
                        if (nread && nread < (size_t)nbytes)
                            nbytes = nread;

			if (limitnear > 0) {
				currsize += nbytes;
				cli_dbgmsg("cli_untar: Approaching limit...\n");
				if (cli_checklimits("cli_untar", ctx, (unsigned long)currsize, 0, 0) != CL_SUCCESS) {
					// Limit would be exceeded by this file, suppress writing beyond limit
					// Need to keep reading to get to end of file chunk
					skipwrite++;
				}
			}

			if (skipwrite == 0) {
				nwritten = (int)cli_writen(fout, block, (size_t)nbytes);

				if(nwritten != nbytes) {
					cli_errmsg("cli_untar: only wrote %d bytes to file %s (out of disc space?): %s\n",
						nwritten, fullname, cli_strerror(errno, err, sizeof(err)));
					close(fout);
					return CL_EWRITE;
				}
			}
			size -= nbytes;
			if ((size != 0) && (nread == 0)) {
				// Truncated tar file, so end file content like tar behavior
				cli_dbgmsg("cli_untar: No bytes read! Forcing end of file content.\n");
				size = 0;
			}
		}
		if (size == 0)
			in_block = 0;
        }
	if(fout>=0) {
		lseek(fout, 0, SEEK_SET);
		ret = cli_magic_scandesc(fout, fullname, ctx);
		close(fout);
		if (!ctx->engine->keeptmp)
			if (cli_unlink(fullname)) return CL_EUNLINK;
		if (ret==CL_VIRUS)
			return CL_VIRUS;
	}
	if (num_viruses)
	    return CL_VIRUS;
	return CL_CLEAN;
}
