/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "md5.h"
#include "filetypes.h"
#include "matcher.h"
#include "pe.h"
#include "special.h"

#define MD5_BLOCKSIZE 4096

#define TARGET_TABLE_SIZE 6
static int targettab[TARGET_TABLE_SIZE] = { 0, CL_TYPE_MSEXE, CL_TYPE_MSOLE2, CL_TYPE_HTML, CL_TYPE_MAIL, CL_TYPE_GRAPHICS };


int cli_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_node *root, unsigned short ftype)
{
	int ret, *partcnt;
	unsigned long int *partoff;


    if((partcnt = (int *) cli_calloc(root->ac_partsigs + 1, sizeof(int))) == NULL) {
	cli_dbgmsg("cl_scanbuff(): unable to cli_calloc(%d, %d)\n", root->ac_partsigs + 1, sizeof(int));
	return CL_EMEM;
    }

    if((partoff = (unsigned long int *) cli_calloc(root->ac_partsigs + 1, sizeof(unsigned long int))) == NULL) {
	cli_dbgmsg("cl_scanbuff(): unable to cli_calloc(%d, %d)\n", root->ac_partsigs + 1, sizeof(unsigned long int));
	free(partcnt);
	return CL_EMEM;
    }

    if((ret = cli_bm_scanbuff(buffer, length, virname, root, 0, ftype, -1)) != CL_VIRUS)
	ret = cli_ac_scanbuff(buffer, length, virname, root, partcnt, 0, 0, partoff, ftype, -1);

    free(partcnt);
    free(partoff);
    return ret;
}

int cl_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_node *root)
{
    return cli_scanbuff(buffer, length, virname, root, 0);
}

static struct cli_md5_node *cli_vermd5(const unsigned char *md5, const struct cl_node *root)
{
	struct cli_md5_node *pt;


    if(!(pt = root->md5_hlist[md5[0] & 0xff]))
	return NULL;

    while(pt) {
	if(!memcmp(pt->md5, md5, 16))
	    return pt;

	pt = pt->next;
    }

    return NULL;
}

static long int cli_caloff(const char *offstr, int fd)
{
	struct cli_pe_info peinfo;
	long int offset = -1;
	int n;


    if(isdigit(offstr[0])) {
	return atoi(offstr);
    } if(!strncmp(offstr, "EP+", 3)) {
	if((n = lseek(fd, 0, SEEK_CUR)) == -1) {
	    cli_dbgmsg("Invalid descriptor\n");
	    return -1;
	}
	lseek(fd, 0, SEEK_SET);
	if(cli_peheader(fd, &peinfo)) {
	    lseek(fd, n, SEEK_SET);
	    return -1;
	}
	free(peinfo.section);
	lseek(fd, n, SEEK_SET);
	return peinfo.ep + atoi(offstr + 3);
    } else if(offstr[0] == 'S') {
	if((n = lseek(fd, 0, SEEK_CUR)) == -1) {
	    cli_dbgmsg("Invalid descriptor\n");
	    return -1;
	}
	lseek(fd, 0, SEEK_SET);
	if(cli_peheader(fd, &peinfo)) {
	    lseek(fd, n, SEEK_SET);
	    return -1;
	}
	lseek(fd, n, SEEK_SET);

	if(sscanf(offstr, "S%d+%ld", &n, &offset) != 2)
	    return -1;

	if(n >= peinfo.nsections) {
	    free(peinfo.section);
	    return -1;
	}

	offset += peinfo.section[n].raw;
	free(peinfo.section);
	return offset;
    } else if(!strncmp(offstr, "EOF-", 4)) {
	    struct stat sb;

	if(fstat(fd, &sb) == -1)
	    return -1;

	return sb.st_size - atoi(offstr + 4);
    }

    return -1;
}

int cli_validatesig(unsigned short target, unsigned short ftype, const char *offstr, unsigned long int fileoff, int desc, const char *virname)
{

    if(target) {
	if(target >= TARGET_TABLE_SIZE) {
	    cli_errmsg("Bad target in signature (%s)\n", virname);
	    return 0;
	} else if(ftype) {
	    if(targettab[target] != ftype) {
		cli_dbgmsg("Type: %d, expected: %d (%s)\n", ftype, targettab[target], virname);
		return 0;
	    }
	} 

    }

    if(offstr && desc != -1) {
	    long int off = cli_caloff(offstr, desc);

	if(off == -1) {
	    cli_dbgmsg("Bad offset in signature (%s)\n", virname);
	    return 0;
	}

	if(fileoff != off) {
	    cli_dbgmsg("Virus offset: %d, expected: %d (%s)\n", fileoff, off, virname);
	    return 0;
	}
    }

    if(ftype == CL_TYPE_GRAPHICS && virname && !strncmp(virname, "Exploit.JPEG.Comment", 20)) {
	    int old;

	if((old = lseek(desc, 0, SEEK_CUR)) == -1) {
	    cli_dbgmsg("Invalid descriptor\n");
	    return 0;
	}
	lseek(desc, 0, SEEK_SET);
	if(cli_check_jpeg_exploit(desc) != 1) {
	    cli_dbgmsg("Eliminated false positive match of Exploit.JPEG.Comment\n");
	    lseek(desc, old, SEEK_SET);
	    return 0;
	}
	lseek(desc, old, SEEK_SET);
    }

    return 1;
}

int cli_scandesc(int desc, const char **virname, long int *scanned, const struct cl_node *root, short otfrec, unsigned short ftype)
{
 	char *buffer, *buff, *endbl, *pt;
	int bytes, buffsize, length, ret, *partcnt, type = CL_CLEAN;
	unsigned long int *partoff, offset = 0;
	struct MD5Context ctx;
	unsigned char digest[16];
	struct cli_md5_node *md5_node;


    if(!root) {
	cli_errmsg("cli_scandesc: root == NULL\n");
	return CL_ENULLARG;
    }

    /* prepare the buffer */
    buffsize = root->maxpatlen + SCANBUFF;
    if(!(buffer = (char *) cli_calloc(buffsize, sizeof(char)))) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%d)\n", buffsize);
	return CL_EMEM;
    }

    if((partcnt = (int *) cli_calloc(root->ac_partsigs + 1, sizeof(int))) == NULL) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%d, %d)\n", root->ac_partsigs + 1, sizeof(int));
	free(buffer);
	return CL_EMEM;
    }

    if((partoff = (unsigned long int *) cli_calloc(root->ac_partsigs + 1, sizeof(unsigned long int))) == NULL) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%d, %d)\n", root->ac_partsigs + 1, sizeof(unsigned long int));
	free(buffer);
	free(partcnt);
	return CL_EMEM;
    }

    if(root->md5_hlist)
	MD5Init(&ctx);


    buff = buffer;
    buff += root->maxpatlen; /* pointer to read data block */
    endbl = buff + SCANBUFF - root->maxpatlen; /* pointer to the last block
						* length of root->maxpatlen
						*/

    pt = buff;
    length = SCANBUFF;
    while((bytes = read(desc, buff, SCANBUFF)) > 0) {

	if(scanned)
	    *scanned += bytes / CL_COUNT_PRECISION;

	if(bytes < SCANBUFF)
	    length -= SCANBUFF - bytes;

	if(cli_bm_scanbuff(pt, length, virname, root, offset, ftype, desc) == CL_VIRUS ||
	   (ret = cli_ac_scanbuff(pt, length, virname, root, partcnt, otfrec, offset, partoff, ftype, desc)) == CL_VIRUS) {
	    free(buffer);
	    free(partcnt);
	    free(partoff);
	    return CL_VIRUS;

	} else if(otfrec && ret >= CL_TYPENO) {
	    if(ret >= type)
		type = ret;
	}

	if(bytes == SCANBUFF) {
	    memmove(buffer, endbl, root->maxpatlen);
	    offset += bytes - root->maxpatlen;
	}

        pt = buffer;
        length = buffsize;

	if(root->md5_hlist)
	    MD5Update(&ctx, buff, bytes);
    }

    free(buffer);
    free(partcnt);
    free(partoff);

    if(root->md5_hlist) {
	MD5Final(digest, &ctx);

	if((md5_node = cli_vermd5(digest, root))) {
		struct stat sb;

	    if(fstat(desc, &sb))
		return CL_EIO;

	    if(sb.st_size != md5_node->size) {
		cli_warnmsg("Detected false positive MD5 match. Please report.\n");
	    } else {
		if(virname)
		    *virname = md5_node->virname;

		return CL_VIRUS;
	    }
	}
    }

    return otfrec ? type : CL_CLEAN;
}

int cl_build(struct cl_node *root)
{
    return cli_ac_buildtrie(root);
}

void cl_free(struct cl_node *root)
{
	int i;
	struct cli_md5_node *pt, *h;


    if(!root) {
	cli_errmsg("cl_free: root == NULL\n");
	return;
    }

    cli_ac_free(root);
    cli_bm_free(root);

    if(root->md5_hlist) {
	for(i = 0; i < 256; i++) {
	    pt = root->md5_hlist[i];
	    while(pt) {
		h = pt;
		pt = pt->next;
		free(h->md5);
		free(h->virname);
		if(h->viralias)
		    free(h->viralias);
		free(h);
	    }
	}
	free(root->md5_hlist);
    }

    free(root);
}

int cl_buildtrie(struct cl_node *root) /* for backward compatibility */
{
    return cl_build(root);
}

void cl_freetrie(struct cl_node *root) /* for backward compatibility */
{
    cl_free(root);
}
