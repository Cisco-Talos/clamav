/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
#include "textdet.h"
#include "default.h"

#include "htmlnorm.h"
#include "entconv.h"
#include "mpool.h"

static const struct ftmap_s {
    const char *name;
    cli_file_t code;
} ftmap[] = {
    { "CL_TYPE_TEXT_ASCII",	CL_TYPE_TEXT_ASCII	},
    { "CL_TYPE_TEXT_UTF8",	CL_TYPE_TEXT_UTF8	},
    { "CL_TYPE_TEXT_UTF16LE",	CL_TYPE_TEXT_UTF16LE	},
    { "CL_TYPE_TEXT_UTF16BE",	CL_TYPE_TEXT_UTF16BE	},
    { "CL_TYPE_BINARY_DATA",	CL_TYPE_BINARY_DATA	},
    { "CL_TYPE_IGNORED",	CL_TYPE_IGNORED		},
    { "CL_TYPE_ANY",		0			}, /* for ft-sigs */
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
    { "CL_TYPE_HTML_UTF16",	CL_TYPE_HTML_UTF16	},
    { "CL_TYPE_SCRIPT",         CL_TYPE_SCRIPT          },
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
    { NULL,			CL_TYPE_IGNORED		}
};

cli_file_t cli_ftcode(const char *name)
{
	unsigned int i;

    for(i = 0; ftmap[i].name; i++)
	if(!strcmp(ftmap[i].name, name))
	    return ftmap[i].code;

    return CL_TYPE_ERROR;
}

void cli_ftfree(const struct cl_engine *engine)
{
	struct cli_ftype *ftypes=engine->ftypes, *pt;

    while(ftypes) {
	pt = ftypes;
	ftypes = ftypes->next;
	mpool_free(engine->mempool, pt->magic);
	mpool_free(engine->mempool, pt->tname);
	mpool_free(engine->mempool, pt);
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

    return cli_texttype(buf, buflen);
}

int is_tar(unsigned char *buf, unsigned int nbytes);

cli_file_t cli_filetype2(int desc, const struct cl_engine *engine)
{
	unsigned char buff[MAGIC_BUFFER_SIZE + 1], *decoded;
	int bread, sret;
	cli_file_t ret = CL_TYPE_BINARY_DATA;
	struct cli_matcher *root;
	struct cli_ac_data mdata;


    if(!engine) {
	cli_errmsg("cli_filetype2: engine == NULL\n");
	return CL_TYPE_ERROR;
    }

    memset(buff, 0, sizeof(buff));
    bread = cli_readn(desc, buff, MAGIC_BUFFER_SIZE);
    if(bread == -1)
	return CL_TYPE_ERROR;
    buff[bread] = 0;

    ret = cli_filetype(buff, bread, engine);

    if(ret >= CL_TYPE_TEXT_ASCII && ret <= CL_TYPE_BINARY_DATA) {
	/* HTML files may contain special characters and could be
	 * misidentified as BINARY_DATA by cli_filetype()
	 */
	root = engine->root[0];
	if(!root)
	    return ret;

	if(cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN))
	    return ret;

	sret = cli_ac_scanbuff(buff, bread, NULL, NULL, NULL, engine->root[0], &mdata, 0, ret, desc, NULL, AC_SCAN_FT, NULL);

	cli_ac_freedata(&mdata);

	if(sret >= CL_TYPENO) {
	    ret = sret;
	} else {
	    if(cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN))
		return ret;

	    decoded = (unsigned char *) cli_utf16toascii((char *) buff, bread);
	    if(decoded) {
		sret = cli_ac_scanbuff(decoded, strlen((char *) decoded), NULL, NULL, NULL,  engine->root[0], &mdata, 0, CL_TYPE_TEXT_ASCII, desc, NULL, AC_SCAN_FT, NULL);
		free(decoded);
		if(sret == CL_TYPE_HTML)
		    ret = CL_TYPE_HTML_UTF16;
	    }
	    cli_ac_freedata(&mdata);

	    if((((struct cli_dconf*) engine->dconf)->phishing & PHISHING_CONF_ENTCONV) && ret != CL_TYPE_HTML_UTF16) {
		    const char* encoding;

		    /* check if we can autodetect this encoding.
		     * If we can't don't try to detect HTML sig, since
		     * we just tried that above, and failed */
		    if((encoding = encoding_detect_bom(buff, bread))) {
			    unsigned char decodedbuff[sizeof(buff)*2];
			    m_area_t in_area, out_area;

			    in_area.buffer = (unsigned char *) buff;
			    in_area.length = bread;
			    in_area.offset = 0;
			    out_area.buffer = decodedbuff;
			    out_area.length = sizeof(decodedbuff);
			    out_area.offset = 0;

			    /* in htmlnorm we simply skip over \0 chars, and that allows to parse HTML in any unicode 
			     * (multibyte characters will not be exactly handled, but that is not a problem).
			     * However when detecting whether a file is HTML or not, we need exact conversion.
			     * (just eliminating zeros and matching would introduce false positives */
			    if(encoding_normalize_toascii(&in_area, encoding, &out_area) >= 0 && out_area.length > 0) {
				    out_area.buffer[out_area.length] = '\0';
				    if(cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN))
					    return ret;

				    if(out_area.length > 0) {
					    sret = cli_ac_scanbuff(decodedbuff, out_area.length, NULL, NULL, NULL, engine->root[0], &mdata, 0, 0, desc, NULL, AC_SCAN_FT, NULL); /* FIXME: can we use CL_TYPE_TEXT_ASCII instead of 0? */
					    if(sret == CL_TYPE_HTML) {
						    cli_dbgmsg("cli_filetype2: detected HTML signature in Unicode file\n");
						    /* htmlnorm is able to handle any unicode now, since it skips null chars */
						    ret = CL_TYPE_HTML;
					    }
				    }

				    cli_ac_freedata(&mdata);
			    }
		    }
	    }
	}
    }

    if(ret == CL_TYPE_BINARY_DATA) {
	switch(is_tar(buff, bread)) {
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

    return ret;
}
