/*
 *  Copyright (C) 2005 - 2006 Tomasz Kojm <tkojm@clamav.net>
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

#if HAVE_MMAP

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <zlib.h>

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "sis.h"

#define BLOCKMAX		    (options & CL_SCAN_BLOCKMAX)

#if WORDS_BIGENDIAN == 0
#define EC16(v)	(v)
#define EC32(v) (v)
#else
static inline uint16_t EC16(uint16_t v)
{
    return ((v >> 8) + (v << 8));
}

static inline uint32_t EC32(uint32_t v)
{
    return ((v >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | (v << 24));
}
#endif

extern short cli_leavetemps_flag;

static char *langcodes[] = {
    "",   "EN", "FR", "GE", "SP", "IT", "SW", "DA", "NO", "FI", "AM",
    "SF", "SG", "PO", "TU", "IC", "RU", "HU", "DU", "BL", "AU", "BG",
    "AS", "NZ", "IF", "CS", "SK", "PL", "SL", "TC", "HK", "ZH", "JA",
    "TH", "AF", "SQ", "AH", "AR", "HY", "TL", "BE", "BN", "BG", "MY",
    "CA", "HR", "CE", "IE", "SF", "ET", "FA", "CF", "GD", "KA", "EL",
    "CG", "GU", "HE", "HI", "IN", "GA", "SZ", "KN", "KK", "KM", "KO",
    "LO", "LV", "LT", "MK", "MS", "ML", "MR", "MO", "MN", "NN", "BP",
    "PA", "RO", "SR", "SI", "SO", "OS", "LS", "SH", "FS", "TA", "TE",
    "BO", "TI", "CT", "TK", "UK", "UR", "",   "VI", "CY", "ZU"
};

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define SIS_MAX_NAME 512
#define SIS_MAX_SIZE 134217728

static char *sis_utf16_decode(const char *str, uint32_t length)
{
	char *decoded;
	int i, j;


    if(!length || length % 2) {
	cli_warnmsg("SIS: sis_utf16_decode: Broken filename (length == %d)\n", length);
	return NULL;
    }

    if(!(decoded = cli_calloc(length / 2 + 1, sizeof(char))))
	return NULL;

    for(i = 0, j = 0; i < length; i += 2, j++) {
       decoded[j] = str[i + 1] << 4;
       decoded[j] += str[i];
       if(decoded[j] == '%')
	   decoded[j] = '_';
    }

    return decoded;
}

static int sis_extract_simple(int fd, char *mfile, uint32_t length, uint32_t offset, uint16_t nlangs, uint8_t compressed, const char *dir, const char **virname, const struct cl_limits *limits, unsigned int options)
{
	const char *typedir = NULL;
	char *sname = NULL, *dname = NULL, *subdir, *fname, *buff;
	int desc, i;
	uint8_t get_dname = 1;
	uint32_t namelen, nameoff, filelen, fileoff;
	struct stat sb;
	uLong osize = 0;
	uLongf csize = 0;


    if(offset + 24 + 8 * nlangs >= length) {
	cli_errmsg("SIS: sis_extract_simple: Broken file record\n");
	return CL_EFORMAT;
    }

    switch(cli_readint32(mfile + offset)) {
	case 0x00:
	    cli_dbgmsg("SIS: File type: Standard file\n");
	    typedir = "standard";
	    break;
	case 0x01:
	    cli_dbgmsg("SIS: File type: Text file\n");
	    typedir = "text";
	    get_dname = 0;
	    break;
	case 0x02:
	    cli_dbgmsg("SIS: File type: Component file\n");
	    typedir = "component";
	    break;
	case 0x03:
	    cli_dbgmsg("SIS: File type: Run file\n");
	    typedir = "run";
	    switch(cli_readint32(mfile + offset + 4)) {
		case 0x0000:
		    cli_dbgmsg("SIS:    * During installation only\n");
		    break;
		case 0x0001:
		    cli_dbgmsg("SIS:    * During removal only\n");
		    break;
		case 0x0002:
		    cli_dbgmsg("SIS:    * During installation and removal\n");
		    break;
		case 0x0100:
		    cli_dbgmsg("SIS:    * Ends when installation finished\n");
		    break;
		case 0x0200:
		    cli_dbgmsg("SIS:    * Waits until closed before continuing\n");
		    break;
		default:
		    cli_warnmsg("SIS: sis_extract_simple: Unknown value in file details\n");
	    }
	    break;
	case 0x04:
	    cli_dbgmsg("SIS: File type: Null file\n");
	    return CL_CLEAN;
	    break;
	case 0x05:
	    cli_dbgmsg("SIS: File type: MIME file\n");
	    return CL_CLEAN;
	    break;
	default:
	    cli_warnmsg("SIS: Unknown file type in file record\n");
    }

    /* Source name */
    namelen = (uint32_t) cli_readint32(mfile + offset + 8);
    if(namelen > SIS_MAX_NAME) {
	cli_warnmsg("SIS: sis_extract_simple: Source name too long and will not be decoded\n");
    } else {
	nameoff = cli_readint32(mfile + offset + 12);
	if(nameoff >= length ||  nameoff + namelen >= length) {
	    cli_errmsg("SIS: sis_extract_simple: Broken source name data\n");
	    return CL_EFORMAT;
	}

	if((sname = sis_utf16_decode(mfile + nameoff, namelen)))
	    cli_dbgmsg("SIS: Source name: %s\n", sname);
	else
	    cli_warnmsg("SIS: Source name not decoded\n");
    }

    /* Destination name */
    if(get_dname) {
	namelen = (uint32_t) cli_readint32(mfile + offset + 16);
	if(namelen > SIS_MAX_NAME) {
	    cli_warnmsg("SIS: sis_extract_simple: Destination name too long and will not be decoded\n");
	} else {
	    nameoff = cli_readint32(mfile + offset + 20);
	    if(nameoff >= length || nameoff + namelen >= length) {
		cli_errmsg("SIS: sis_extract_simple: Broken destination name data\n");
		if(sname)
		    free(sname);
		return CL_EFORMAT;
	    }

	    if((dname = sis_utf16_decode(mfile + nameoff, namelen)))
		cli_dbgmsg("SIS: Destination name: %s\n", dname);
	    else
		cli_warnmsg("SIS: Destination name not decoded\n");
	}
    }

    if(!cli_leavetemps_flag) {
	if(sname)
	    free(sname);
	if(dname)
	    free(dname);
    }

    /* Files */
    if(typedir) {
	if(!(subdir = cli_malloc(strlen(dir) + strlen(typedir) + 2)))
	    return CL_EMEM;
	sprintf(subdir, "%s/%s", dir, typedir);
    } else {
	if(!(subdir = strdup(dir)))
	    return CL_EMEM;
    }

    if(stat(subdir, &sb) == -1) {
	if(mkdir(subdir, 0700) == -1) {
	    free(subdir);
	    return CL_EIO;
	}
    }

    for(i = 0; i < nlangs; i++) {
	filelen = cli_readint32(mfile + offset + 24 + 4 * i);
	fileoff = cli_readint32(mfile + offset + 24 + 4 * (i + 1));

	if(filelen >= length || fileoff >= length || filelen + fileoff > length) {
	    cli_errmsg("SIS: sis_extract_simple: Broken file data (filelen, fileoff)\n");
	    free(subdir);
	    return CL_EFORMAT;
	}

	if(!(fname = cli_gentemp(subdir))) {
	    free(subdir);
	    return CL_EMEM;
	}

	if(compressed) {
	    csize = (uLong) filelen;
	    filelen = cli_readint32(mfile + offset + 24 + 8 * (i + 1));
	    osize = (uLongf) filelen;

	    if(!osize) {
		cli_dbgmsg("SIS: Empty file, skipping\n");
		free(fname);
		continue;
	    }

	    cli_dbgmsg("SIS: Compressed size: %d\n", csize);
	    cli_dbgmsg("SIS: Original size: %d\n", osize);

	    if(limits && limits->maxfilesize && osize > limits->maxfilesize) {
		cli_dbgmsg("SIS: Size exceeded (%d, max: %ld)\n", osize, limits->maxfilesize);
		if(BLOCKMAX) {
		    *virname = "SIS.ExceededFileSize";
		    free(subdir);
		    free(fname);
		    return CL_VIRUS;
		}
		free(subdir);
		free(fname);
		return CL_EFORMAT;
	    }

	    if(!(buff = cli_malloc((size_t) osize))) {
		cli_errmsg("SIS: sis_extract_simple: Can't allocate decompression buffer\n");
		free(subdir);
		free(fname);
		return CL_EIO;
	    } 

	    if(uncompress((Bytef *) buff, &osize , (Bytef *) mfile + fileoff, csize) != Z_OK) {
		cli_errmsg("SIS: sis_extract_simple: File decompression failed\n");
		free(buff);
		free(subdir);
		free(fname);
		return CL_EIO;
	    }

	} else {
	    buff = mfile + fileoff;
	}

	if((desc = open(fname, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) == -1) {
	    cli_errmsg("SIS: sis_extract_simple: Can't create new file %s\n", fname);
	    free(subdir);
	    free(fname);
	    if(compressed)
		free(buff);
	    return CL_EIO;
	} 

	if(cli_writen(desc, buff, filelen) != filelen) {
	    cli_errmsg("SIS: sis_extract_simple: Can't write %d bytes to %s\n", filelen, fname);
	    free(subdir);
	    free(fname);
	    if(compressed)
		free(buff);
	    return CL_EIO;
	} else {
	    if(compressed)
		cli_dbgmsg("SIS: File decompressed into %s\n", fname);
	    else
		cli_dbgmsg("SIS: File saved into %s\n", fname);
	}

	if(close(desc) == -1) {
	    cli_errmsg("SIS: sis_extract_simple: Can't close descriptor %d\n", filelen, fname);
	    free(subdir);
	    free(fname);
	    if(compressed)
		free(buff);
	    return CL_EIO;
	} 

	free(fname);

	if(compressed)
	    free(buff);
    }

    free(subdir);
    return 0;
}

int cli_scansis(int desc, const char **virname, long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, unsigned int arec, unsigned int mrec)
{
	struct sis_file_hdr file_hdr;
	struct sis_file_hdr6 file_hdr6;
	uint8_t release = 0, compressed;
	uint16_t opts, nlangs, *langrecs, nfiles;
	uint32_t recp, frecord, n;
	size_t length;
	char *mfile = NULL, *langs, *dir;
	struct stat sb;
	int i, ret;


    if(fstat(desc, &sb) == -1) {
	cli_errmsg("SIS: fstat() failed\n");
	return CL_EIO;
    }

    if(sb.st_size < sizeof(struct sis_file_hdr)) {
	cli_dbgmsg("SIS: Broken or not a SIS file (too small)\n");
	return CL_CLEAN;
    }

    length = sb.st_size;

    if(length <= SIS_MAX_SIZE) {
	mfile = (char *) mmap(NULL, length, PROT_READ, MAP_PRIVATE, desc, 0);
	if(mfile == MAP_FAILED) {
	    cli_errmsg("SIS: mmap() failed\n");
	    return CL_EMEM;
	} else {
	    cli_dbgmsg("SIS: mmap'ed file\n");
	    memcpy(&file_hdr, mfile, sizeof(struct sis_file_hdr));
	}
    } else {
	cli_warnmsg("SIS: File too large (> %d)\n", SIS_MAX_SIZE);
	return CL_CLEAN;
    }

    if(EC32(file_hdr.uid3) != 0x10000419) {
	cli_dbgmsg("SIS: Not a SIS file\n");
	munmap(mfile, length);
	return CL_CLEAN;
    }

    switch(EC32(file_hdr.uid2)) {
	case 0x1000006d:
	    cli_dbgmsg("SIS: EPOC release 3, 4 or 5\n");
	    release = 3;
	    break;
	case 0x10003a12:
	    cli_dbgmsg("SIS: EPOC release 6\n");
	    release = 6;
	    break;
	default:
	    cli_warnmsg("SIS: Unknown value of UID 2 (EPOC release) -> not a real SIS file??\n");
	    munmap(mfile, length);
	    return CL_CLEAN;
    }

    /* TODO: Verify checksums (uid4 and checksum) */

    /* Languages */
    nlangs = EC16(file_hdr.nlangs);
    cli_dbgmsg("SIS: Number of languages: %d\n", nlangs);

    if(nlangs && nlangs < 100) {

	if(EC32(file_hdr.plangs) >= length || EC32(file_hdr.plangs) + nlangs * 2 >= sb.st_size) {
	    cli_errmsg("SIS: Broken file structure (language records)\n");
	    munmap(mfile, length);
	    return CL_EFORMAT;
	}

	if(!(langrecs = (uint16_t *) cli_malloc(nlangs * 2))) {
	    munmap(mfile, length);
	    return CL_EMEM;
	}

	memcpy(langrecs, mfile + EC32(file_hdr.plangs), nlangs * 2);

	if(!(langs = (char *) cli_calloc(nlangs * 3 + 1, sizeof(char)))) {
	    munmap(mfile, length);
	    free(langrecs);
	    return CL_EMEM;
	}

	for(i = 0; i < nlangs; i++) {
	    strncat(langs, langcodes[EC16(langrecs[i]) % 98], 2);
	    if(i != nlangs - 1)
		strncat(langs, " ", 1);
	}
	cli_dbgmsg("SIS: Supported languages: %s\n", langs);
	free(langrecs);
	free(langs);

    } else  {
	cli_errmsg("SIS: Incorrect number of languages (%d)\n", nlangs);
	munmap(mfile, length);
	return CL_EFORMAT;
    }

    cli_dbgmsg("SIS: Offset of languages records: %d\n", EC32(file_hdr.plangs));

    if(EC16(file_hdr.ilang))
	cli_dbgmsg("SIS: Installation language: %d\n", EC16(file_hdr.ilang));

    /* Requisites */
    cli_dbgmsg("SIS: Number of requisites: %d\n", EC16(file_hdr.nreqs));
    cli_dbgmsg("SIS: Offset of requisites records: %d\n", EC32(file_hdr.preqs));

    /* Options flags */
    opts = EC16(file_hdr.options);
    cli_dbgmsg("SIS: Options:\n");
    if(opts & 0x0001)
	cli_dbgmsg("SIS:    * File is in Unicode format\n");
    if(opts & 0x0002)
	cli_dbgmsg("SIS:    * File is distributable\n");
    if(opts & 0x0008) {
	cli_dbgmsg("SIS:    * Packed files are not compressed\n");
	compressed = 0;
    } else {
	cli_dbgmsg("SIS:    * Packed files are compressed\n");
	compressed = 1;
    }
    if(opts & 0x0010)
	cli_dbgmsg("SIS:    * File installation shuts down all applications\n");

    /* Type flags */
    switch(EC16(file_hdr.type)) {
	case 0x0000:
	    cli_dbgmsg("SIS: Type: Contains an application\n");
	    break;
	case 0x0001:
	    cli_dbgmsg("SIS: Type: Contains a shared/system component\n");
	    break;
	case 0x0002:
	    cli_dbgmsg("SIS: Type: Contains an optional (selectable) component\n");
	    break;
	case 0x0003:
	    cli_dbgmsg("SIS: Type: Configures an existing application or service\n");
	    break;
	case 0x0004:
	    cli_dbgmsg("SIS: Type: Patches an existing component\n");
	    break;
	case 0x0005:
	    cli_dbgmsg("SIS: Type: Upgrades an existing component\n");
	    break;
	default:
	    cli_warnmsg("SIS: Unknown value of type\n");
    } 

    cli_dbgmsg("SIS: Major version: %d\n", EC16(file_hdr.majorver));
    cli_dbgmsg("SIS: Minor version: %d\n", EC16(file_hdr.minorver));

    if(release == 6) {

	if(sizeof(struct sis_file_hdr) + sizeof(struct sis_file_hdr6) >= length) {
	    cli_errmsg("SIS: Broken file structure (language records)\n");
	    munmap(mfile, length);
	    return CL_EFORMAT;
	}

	memcpy(&file_hdr6, mfile + sizeof(struct sis_file_hdr), sizeof(struct sis_file_hdr6));
	cli_dbgmsg("SIS: Maximum space required: %d\n", EC32(file_hdr6.maxispace));
    }

    /* Files */
    nfiles = EC16(file_hdr.nfiles);

    if(limits && limits->maxfiles && nfiles > limits->maxfiles) {
	cli_dbgmsg("SIS: Files limit reached (max: %d)\n", limits->maxfiles);
	if(BLOCKMAX) {
	    *virname = "SIS.ExceededFilesLimit";
	    munmap(mfile, length);
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    cli_dbgmsg("SIS: Number of files: %d\n", nfiles);
    cli_dbgmsg("SIS: Offset of files records: %d\n", EC32(file_hdr.pfiles));

    if(!(dir = cli_gentempdir(NULL))) {
	cli_errmsg("SIS: Can't generate temporary directory\n");
	munmap(mfile, length);
	return CL_ETMPDIR;
    }

    if((frecord = EC32(file_hdr.pfiles)) >= length) {
	cli_errmsg("SIS: Broken file structure (frecord)\n");
	munmap(mfile, length);
	free(dir);
	return CL_EFORMAT;
    }

    for(i = 0; i < nfiles; i++) {

	cli_dbgmsg("SIS: -----\n");

	if(frecord + 4 >= length) {
	    cli_errmsg("SIS: Broken file structure (frecord)\n");
	    munmap(mfile, length);
	    if(!cli_leavetemps_flag)
		cli_rmdirs(dir);
	    free(dir);
	    return CL_EFORMAT;
	}

	switch(cli_readint32(mfile + frecord)) {
	    case 0x00000000:
		cli_dbgmsg("SIS: Simple file record\n");
		if((ret = sis_extract_simple(desc, mfile, sb.st_size, frecord + 4, nlangs, compressed, dir, virname, limits, options))) {
		    munmap(mfile, length);
		    if(!cli_leavetemps_flag)
			cli_rmdirs(dir);
		    free(dir);
		    return ret;
		}

		if(release == 6)
		    frecord += 32 + 12 * nlangs + 4;
		else
		    frecord += 28 + 4 * nlangs + 4;

		break;
	    case 0x00000001:
		cli_dbgmsg("SIS: Multiple languages file record\n");
		/* TODO: Pass language strings into sis_extract */
		if((ret = sis_extract_simple(desc, mfile, sb.st_size, frecord + 4, nlangs, compressed, dir, virname, limits, options))) {
		    munmap(mfile, length);
		    if(!cli_leavetemps_flag)
			cli_rmdirs(dir);
		    free(dir);
		    return ret;
		}

		if(release == 6)
		    frecord += 32 + 12 * nlangs + 4;
		else
		    frecord += 28 + 4 * nlangs + 4;

		break;
	    case 0x00000002:
		cli_dbgmsg("SIS: Options record\n");
		if(frecord + 8 >= length) {
		    munmap(mfile, length);
		    if(!cli_leavetemps_flag)
			cli_rmdirs(dir);
		    free(dir);
		    return CL_EFORMAT;
		}

		n = cli_readint32(mfile + frecord + 4);
		cli_dbgmsg("SIS: Number of options: %d\n", n);

		if(n > 128 || frecord + 8 * n * nlangs >= length) {
		    cli_errmsg("SIS: Incorrect number of options\n");
		    munmap(mfile, length);
		    if(!cli_leavetemps_flag)
			cli_rmdirs(dir);
		    free(dir);
		    return CL_EFORMAT;
		}

		frecord += 8 + 8 * n * nlangs + 16;

		break;
	    case 0x00000003:
	    case 0x00000004:
		cli_dbgmsg("SIS: If/ElseIf record\n");
		if(frecord + 8 >= length) {
		    munmap(mfile, length);
		    if(!cli_leavetemps_flag)
			cli_rmdirs(dir);
		    free(dir);
		    return CL_EFORMAT;
		}

		n = cli_readint32(mfile + frecord + 4);
		cli_dbgmsg("SIS: Size of conditional expression: %d\n", n);

		if(n >= length) {
		    cli_errmsg("SIS: Incorrect size of conditional expression\n");
		    munmap(mfile, length);
		    if(!cli_leavetemps_flag)
			cli_rmdirs(dir);
		    free(dir);
		    return CL_EFORMAT;
		}

		frecord += 8 + n;
		break;
	    case 0x00000005:
		cli_dbgmsg("SIS: Else record\n");
		frecord += 4;
		break;
	    case 0x00000006:
		cli_dbgmsg("SIS: EndIf record\n");
		frecord += 4;
		break;
	    default:
		cli_warnmsg("SIS: Unknown file record type\n");
	}
    }

    /* scan extracted files */
    cli_dbgmsg("SIS:  ****** Scanning extracted files ******\n");
    ret = cli_scandir(dir, virname, scanned, engine, limits, options, arec, mrec);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    munmap(mfile, length);

    return ret;
}

#else /* HAVE_MMAP */

#include "clamav.h"

int cli_scansis(int desc, const char **virname, long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, unsigned int arec, unsigned int mrec)
{
    cli_warnmsg("Support for SIS files not compiled in!\n");
    return CL_CLEAN;
}

#endif /* HAVE_MMAP */
