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

#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "md5.h"
#include "filetypes.h"

#define MD5_BLOCKSIZE 4096


int cl_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_node *root)
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

    if((ret = cli_bm_scanbuff(buffer, length, virname, root)) != CL_VIRUS)
	ret = cli_ac_scanbuff(buffer, length, virname, root, partcnt, 0, 0, partoff);

    free(partcnt);
    free(partoff);
    return ret;
}

static struct cli_md5_node *cli_vermd5(const char *md5, const struct cl_node *root)
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

int cli_scandesc(int desc, const char **virname, long int *scanned, const struct cl_node *root, int typerec)
{
 	char *buffer, *buff, *endbl, *pt;
	int bytes, buffsize, length, ret, *partcnt, type = CL_CLEAN;
	unsigned long int *partoff, offset = 0;
	struct md5_ctx ctx;
        unsigned char md5buff[16];
	struct cli_md5_node *md5_node;


    if(!root) {
	cli_errmsg("cli_scandesc: root == NULL\n");
	return CL_ENULLARG;
    }

    /* prepare the buffer */
    buffsize = root->maxpatlen + SCANBUFF;
    if(!(buffer = (char *) cli_calloc(buffsize, sizeof(char)))) {
	cli_dbgmsg("cli_scandesc(): unable to cli_malloc(%d)\n", buffsize);
	return CL_EMEM;
    }

    if((partcnt = (int *) cli_calloc(root->ac_partsigs + 1, sizeof(int))) == NULL) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%d, %d)\n", root->ac_partsigs + 1, sizeof(int));
	free(buffer);
	return CL_EMEM;
    }

    if((partoff = (unsigned long int *) cli_calloc(root->ac_partsigs + 1, sizeof(unsigned long int))) == NULL) {
	cli_dbgmsg("cli_scanbuff(): unable to cli_calloc(%d, %d)\n", root->ac_partsigs + 1, sizeof(unsigned long int));
	free(buffer);
	free(partcnt);
	return CL_EMEM;
    }

    if(root->md5_hlist)
	md5_init_ctx (&ctx);

    buff = buffer;
    buff += root->maxpatlen; /* pointer to read data block */
    endbl = buff + SCANBUFF - root->maxpatlen; /* pointer to the last block
						* length of root->maxpatlen
						*/

    pt= buff;
    length = SCANBUFF;
    while((bytes = read(desc, buff, SCANBUFF)) > 0) {

	if(scanned)
	    *scanned += bytes / CL_COUNT_PRECISION;

	if(bytes < SCANBUFF)
	    length -= SCANBUFF - bytes;

	if(cli_bm_scanbuff(pt, length, virname, root) == CL_VIRUS ||
	   (ret = cli_ac_scanbuff(pt, length, virname, root, partcnt, typerec, offset, partoff)) == CL_VIRUS) {
	    free(buffer);
	    free(partcnt);
	    free(partoff);
	    return CL_VIRUS;

	} else if(typerec && ret >= CL_TYPENO) {
	    if(ret >= type)
		type = ret;
	}

	if(bytes == SCANBUFF) {
	    memmove(buffer, endbl, root->maxpatlen);
	    offset += bytes - root->maxpatlen;
	}

        pt = buffer;
        length = buffsize;

	/* compute MD5 */

	if(root->md5_hlist) {
	    if(bytes % 64 == 0) {
		md5_process_block(buff, bytes, &ctx);
	    } else {
		    int block = bytes;
		    char *mpt = buff;

		while(block >= MD5_BLOCKSIZE) {
		    md5_process_block(mpt, MD5_BLOCKSIZE, &ctx);
		    mpt += MD5_BLOCKSIZE;
		    block -= MD5_BLOCKSIZE;
		}

		if(block)
		    md5_process_bytes(mpt, block, &ctx);
	    }
	}
    }

    free(buffer);
    free(partcnt);
    free(partoff);

    if(root->md5_hlist) {
	md5_finish_ctx(&ctx, &md5buff);

	if((md5_node = cli_vermd5(md5buff, root))) {
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

    return typerec ? type : CL_CLEAN;
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
    return cl_free(root);
}
