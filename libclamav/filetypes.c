/*
 *  Copyright (C) 2007 Sourcefire, Inc.
 *  Author: Tomasz Kojm <tkojm@clamav.net>
 *
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *  With enhancements from Thomas Lamy <Thomas.Lamy@in-online.net>
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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "filetypes.h"
#include "others.h"
#include "readdb.h"
#include "matcher-ac.h"
#include "str.h"

#include "htmlnorm.h"
#include "entconv.h"

static const struct ftmap_s {
    const char *name;
    cli_file_t code;
} ftmap[] = {
    { "CL_TYPE_UNKNOWN_TEXT",	CL_TYPE_UNKNOWN_TEXT	},
    { "CL_TYPE_UNKNOWN_DATA",	CL_TYPE_UNKNOWN_DATA	},
    { "CL_TYPE_IGNORED",	CL_TYPE_IGNORED		},
    { "CL_TYPE_MSEXE",		CL_TYPE_MSEXE		},
    { "CL_TYPE_ELF",		CL_TYPE_ELF		},
    { "CL_TYPE_POSIX_TAR",	CL_TYPE_POSIX_TAR	},
    { "CL_TYPE_OLD_TAR",	CL_TYPE_OLD_TAR		},
    { "CL_TYPE_GZ",		CL_TYPE_GZ		},
    { "CL_TYPE_ZIP",		CL_TYPE_ZIP		},
    { "CL_TYPE_BZ",		CL_TYPE_BZ		},
    { "CL_TYPE_RAR",		CL_TYPE_RAR		},
    { "CL_TYPE_ARJ",		CL_TYPE_ARJ		},
    { "CL_TYPE_MSSZDD",		CL_TYPE_MSSZDD		},
    { "CL_TYPE_MSOLE2",		CL_TYPE_MSOLE2		},
    { "CL_TYPE_MSCAB",		CL_TYPE_MSCAB		},
    { "CL_TYPE_MSCHM",		CL_TYPE_MSCHM		},
    { "CL_TYPE_SIS",		CL_TYPE_SIS		},
    { "CL_TYPE_SCRENC",		CL_TYPE_SCRENC		},
    { "CL_TYPE_GRAPHICS",	CL_TYPE_GRAPHICS	},
    { "CL_TYPE_RIFF",		CL_TYPE_RIFF		},
    { "CL_TYPE_BINHEX",		CL_TYPE_BINHEX		},
    { "CL_TYPE_TNEF",		CL_TYPE_TNEF		},
    { "CL_TYPE_CRYPTFF",	CL_TYPE_CRYPTFF		},
    { "CL_TYPE_PDF",		CL_TYPE_PDF		},
    { "CL_TYPE_UUENCODED",	CL_TYPE_UUENCODED	},
    { "CL_TYPE_PST",		CL_TYPE_PST		},
    { "CL_TYPE_HTML_UTF16",	CL_TYPE_HTML_UTF16	},
    { "CL_TYPE_RTF",		CL_TYPE_RTF		},
    { "CL_TYPE_HTML",		CL_TYPE_HTML		},
    { "CL_TYPE_MAIL",		CL_TYPE_MAIL		},
    { "CL_TYPE_SFX",		CL_TYPE_SFX		},
    { "CL_TYPE_ZIPSFX",		CL_TYPE_ZIPSFX		},
    { "CL_TYPE_RARSFX",		CL_TYPE_RARSFX		},
    { "CL_TYPE_CABSFX",		CL_TYPE_CABSFX		},
    { "CL_TYPE_ARJSFX",		CL_TYPE_ARJSFX		},
    { "CL_TYPE_NULSFT",		CL_TYPE_NULSFT		},
    { "CL_TYPE_AUTOIT",		CL_TYPE_AUTOIT		},
    { NULL,			CL_TYPE_UNKNOWN_DATA	}
};

cli_file_t cli_ftcode(const char *name)
{
	unsigned int i;

    for(i = 0; ftmap[i].name; i++)
	if(!strcmp(ftmap[i].name, name))
	    return ftmap[i].code;

    return CL_TYPE_ERROR;
}

void cli_ftfree(struct cli_ftype *ftypes)
{
	struct cli_ftype *pt;

    while(ftypes) {
	pt = ftypes;
	ftypes = ftypes->next;
	free(pt->magic);
	free(pt->tname);
	free(pt);
    }
}

cli_file_t cli_filetype(const unsigned char *buf, size_t buflen, const struct cl_engine *engine)
{
	struct cli_ftype *ftype = engine->ftypes;


    while(ftype) {
	if(ftype->offset + ftype->length <= buflen) {
	    if(!memcmp(buf + ftype->offset, ftype->magic, ftype->length)) {
		cli_dbgmsg("Recognized %s file\n", ftype->tname);
		return ftype->type;
	    }
	}
	ftype = ftype->next;
    }

/* FIXME: improve or drop this code
 * https://wwws.clamav.net/bugzilla/show_bug.cgi?id=373
 *
	int i, text = 1, len;
    buflen < 25 ? (len = buflen) : (len = 25);
    for(i = 0; i < len; i++)
	if(!iscntrl(buf[i]) && !isprint(buf[i]) && !internat[buf[i] & 0xff]) {
	    text = 0;
	    break;
	}
    return text ? CL_TYPE_UNKNOWN_TEXT : CL_TYPE_UNKNOWN_DATA;
*/
    return CL_TYPE_UNKNOWN_TEXT;
}

int is_tar(unsigned char *buf, unsigned int nbytes);

cli_file_t cli_filetype2(int desc, const struct cl_engine *engine)
{
	unsigned char smallbuff[MAGIC_BUFFER_SIZE + 1], *decoded, *bigbuff;
	int bread, sret;
	cli_file_t ret = CL_TYPE_UNKNOWN_DATA;
	struct cli_matcher *root;
	struct cli_ac_data mdata;


    memset(smallbuff, 0, sizeof(smallbuff));
    if((bread = read(desc, smallbuff, MAGIC_BUFFER_SIZE)) > 0)
	ret = cli_filetype(smallbuff, bread, engine);

    if(engine && ret == CL_TYPE_UNKNOWN_TEXT) {
	root = engine->root[0];
	if(!root)
	    return ret;

	if(cli_ac_initdata(&mdata, root->ac_partsigs, AC_DEFAULT_TRACKLEN))
	    return ret;

	sret = cli_ac_scanbuff(smallbuff, bread, NULL, engine->root[0], &mdata, 1, 0, 0, -1, NULL);

	cli_ac_freedata(&mdata);

	if(sret >= CL_TYPENO) {
	    ret = sret;
	} else {
	    if(cli_ac_initdata(&mdata, root->ac_partsigs, AC_DEFAULT_TRACKLEN))
		return ret;

	    decoded = (unsigned char *) cli_utf16toascii((char *) smallbuff, bread);
	    if(decoded) {
		sret = cli_ac_scanbuff(decoded, strlen((char *) decoded), NULL, engine->root[0], &mdata, 1, 0, 0, -1, NULL);
		free(decoded);
		if(sret == CL_TYPE_HTML)
		    ret = CL_TYPE_HTML_UTF16;
	    }
	    cli_ac_freedata(&mdata);

	    if((((struct cli_dconf*) engine->dconf)->phishing & PHISHING_CONF_ENTCONV) && ret != CL_TYPE_HTML_UTF16) {
		    struct entity_conv conv;
		    const size_t conv_size = 2*bread < 256 ? 256 : 2*bread;

		if(init_entity_converter(&conv,UNKNOWN,conv_size) == 0) {
			int end = 0;
			m_area_t area;
			area.buffer = (unsigned char *) smallbuff;
			area.length = bread;
			area.offset = 0;

		    while(!end) {
			if(cli_ac_initdata(&mdata, root->ac_partsigs, AC_DEFAULT_TRACKLEN))
			    return ret;

			decoded =  encoding_norm_readline(&conv, NULL, &area, bread);

			if(decoded) {
			    sret = cli_ac_scanbuff(decoded, strlen((const char *) decoded), NULL, engine->root[0], &mdata, 1, 0, 0, -1, NULL);
			    free(decoded);
			    if(sret == CL_TYPE_HTML) {
				ret = CL_TYPE_HTML;
				end = 1;
			    }
			} else
			    end = 1;

			cli_ac_freedata(&mdata);
		    }

		    entity_norm_done(&conv);

		} else {
		    cli_warnmsg("cli_filetype2: Error initializing entity converter\n");
		}
	    }
	}
    }

    if(ret == CL_TYPE_UNKNOWN_DATA || ret == CL_TYPE_UNKNOWN_TEXT) {

	if(!(bigbuff = (unsigned char *) cli_calloc(37638 + 1, sizeof(unsigned char))))
	    return ret;

	lseek(desc, 0, SEEK_SET);
	if((bread = read(desc, bigbuff, 37638)) > 0) {

	    bigbuff[bread] = 0;

	    switch(is_tar(bigbuff, bread)) {
		case 1:
		    ret = CL_TYPE_OLD_TAR;
		    cli_dbgmsg("Recognized old fashioned tar file\n");
		    break;
		case 2:
		    ret = CL_TYPE_POSIX_TAR;
		    cli_dbgmsg("Recognized POSIX tar file\n");
		    break;
	    }
	}

	if(ret == CL_TYPE_UNKNOWN_DATA || ret == CL_TYPE_UNKNOWN_TEXT) {

	    if(!memcmp(bigbuff + 32769, "CD001" , 5) || !memcmp(bigbuff + 37633, "CD001" , 5)) {
		cli_dbgmsg("Recognized ISO 9660 CD-ROM data\n");
		ret = CL_TYPE_IGNORED;
	    } else if(!memcmp(bigbuff + 32776, "CDROM" , 5)) {
		cli_dbgmsg("Recognized High Sierra CD-ROM data\n");
		ret = CL_TYPE_IGNORED;
	    }
	}

	free(bigbuff);
    }

    return ret;
}
