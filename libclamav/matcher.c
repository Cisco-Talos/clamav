/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

extern short cli_debug_flag;

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
static pthread_mutex_t cli_ref_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

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
    } if(!strncmp(offstr, "EP+", 3) || !strncmp(offstr, "EP-", 3)) {
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

	if(offstr[2] == '+')
	    return peinfo.ep + atoi(offstr + 3);
	else
	    return peinfo.ep - atoi(offstr + 3);

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

	if(!strncmp(offstr, "SL", 2)) {

	    if(sscanf(offstr, "SL+%ld", &offset) != 1) {
		free(peinfo.section);
		return -1;
	    }

	    offset += peinfo.section[peinfo.nsections - 1].raw;

	} else {

	    if(sscanf(offstr, "S%d+%ld", &n, &offset) != 2) {
		free(peinfo.section);
		return -1;
	    }

	    if(n >= peinfo.nsections) {
		free(peinfo.section);
		return -1;
	    }

	    offset += peinfo.section[n].raw;
	}

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

int cli_checkfp(int fd, const struct cl_node *root)
{
	struct cli_md5_node *md5_node;
	unsigned char *digest;


    if(root->md5_hlist) {

	if(!(digest = cli_md5digest(fd))) {
	    cli_errmsg("cli_checkfp(): Can't generate MD5 checksum\n");
	    return 0;
	}

	if((md5_node = cli_vermd5(digest, root)) && md5_node->fp) {
		struct stat sb;

	    if(fstat(fd, &sb))
		return CL_EIO;

	    if((unsigned int) sb.st_size != md5_node->size) {
		cli_warnmsg("Detected false positive MD5 match. Please report.\n");
	    } else {
		cli_dbgmsg("Eliminated false positive match (fp sig: %s)\n", md5_node->virname);
		free(digest);
		return 1;
	    }
	}

	free(digest);
    }

    return 0;
}

int cli_validatesig(unsigned short target, unsigned short ftype, const char *offstr, unsigned long int fileoff, int desc, const char *virname)
{


    if(target) {
	if(target >= TARGET_TABLE_SIZE) {
	    cli_dbgmsg("Unknown target in signature (%s)\n", virname);
	    return 0;
	} else {
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

	if(fileoff != (unsigned long int) off) {
	    cli_dbgmsg("Virus offset: %d, expected: %d (%s)\n", fileoff, off, virname);
	    return 0;
	}
    }

    return 1;
}

int cli_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_node *root, short otfrec, unsigned short ftype)
{
 	char *buffer, *buff, *endbl, *pt;
	int bytes, ret, *partcnt, type = CL_CLEAN;
	unsigned int buffersize, length, shift = 0;
	unsigned long int *partoff, offset = 0;
	MD5_CTX ctx;
	unsigned char digest[16];
	struct cli_md5_node *md5_node;


    if(!root) {
	cli_errmsg("cli_scandesc: root == NULL\n");
	return CL_ENULLARG;
    }

    /* prepare the buffer */
    buffersize = root->maxpatlen + SCANBUFF;
    if(!(buffer = (char *) cli_calloc(buffersize, sizeof(char)))) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%d)\n", buffersize);
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
	MD5_Init(&ctx);


    buff = buffer;
    buff += root->maxpatlen; /* pointer to read data block */
    endbl = buff + SCANBUFF - root->maxpatlen; /* pointer to the last block
						* length of root->maxpatlen
						*/

    pt = buff;
    while((bytes = cli_readn(desc, buff + shift, SCANBUFF - shift)) > 0) {

	if(scanned)
	    *scanned += bytes / CL_COUNT_PRECISION;

	length = shift + bytes;
	if(pt == buffer)
	    length += root->maxpatlen;


	if(cli_bm_scanbuff(pt, length, virname, root, offset, ftype, desc) == CL_VIRUS ||
	   (ret = cli_ac_scanbuff(pt, length, virname, root, partcnt, otfrec, offset, partoff, ftype, desc)) == CL_VIRUS) {
	    free(buffer);
	    free(partcnt);
	    free(partoff);

	    lseek(desc, 0, SEEK_SET);
	    if(cli_checkfp(desc, root))
		return CL_CLEAN;
	    else
		return CL_VIRUS;

	} else if(otfrec && ret >= CL_TYPENO) {
	    if(ret >= type)
		type = ret;
	}

	if(root->md5_hlist)
	    MD5_Update(&ctx, buff + shift, bytes);

	if(bytes + shift == SCANBUFF) {
	    memmove(buffer, endbl, root->maxpatlen);
	    offset += SCANBUFF;

	    if(pt == buff) {
		pt = buffer;
		offset -= root->maxpatlen;
	    }

	    shift = 0;
	} else {
	    shift += bytes;
	}
    }

    free(buffer);
    free(partcnt);
    free(partoff);

    if(root->md5_hlist) {
	MD5_Final(digest, &ctx);

	if(cli_debug_flag) {
		char md5str[33];
		int i;

	    pt = md5str;
	    for(i = 0; i < 16; i++) {
		sprintf(pt, "%02x", digest[i]);
		pt += 2;
	    }
	    md5str[32] = 0;
	    cli_dbgmsg("Calculated MD5 checksum: %s\n", md5str);
	}

	if((md5_node = cli_vermd5(digest, root)) && !md5_node->fp) {
		struct stat sb;

	    if(fstat(desc, &sb))
		return CL_EIO;

	    if((unsigned int) sb.st_size != md5_node->size) {
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

struct cl_node *cl_dup(struct cl_node *root)
{
    if(!root) {
	cli_errmsg("cl_dup: root == NULL\n");
	return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ref_mutex);
#endif

    root->refcount++;
    
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ref_mutex);
#endif

    return root;
}

void cl_free(struct cl_node *root)
{
	int i;
	struct cli_md5_node *md5pt, *md5h;
	struct cli_meta_node *metapt, *metah;

    if(!root) {
	cli_errmsg("cl_free: root == NULL\n");
	return;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ref_mutex);
#endif

    root->refcount--;
    if (root->refcount) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_ref_mutex);
#endif
	return;
    }
    
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ref_mutex);
#endif

    cli_ac_free(root);
    cli_bm_free(root);

    if(root->md5_hlist) {
	for(i = 0; i < 256; i++) {
	    md5pt = root->md5_hlist[i];
	    while(md5pt) {
		md5h = md5pt;
		md5pt = md5pt->next;
		free(md5h->md5);
		free(md5h->virname);
		if(md5h->viralias)
		    free(md5h->viralias);
		free(md5h);
	    }
	}
	free(root->md5_hlist);
    }

    metapt = root->zip_mlist;
    while(metapt) {
	metah = metapt;
	metapt = metapt->next;
	free(metah->virname);
	if(metah->filename)
	    free(metah->filename);
	free(metah);
    }

    metapt = root->rar_mlist;
    while(metapt) {
	metah = metapt;
	metapt = metapt->next;
	free(metah->virname);
	if(metah->filename)
	    free(metah->filename);
	free(metah);
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
