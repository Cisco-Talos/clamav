/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#include "iowrap.h"
#include "mbr.h"
#include "gpt.h"
#include "ooxml.h"

#include "htmlnorm.h"
#include "entconv.h"
#include "mpool.h"
#define UNZIP_PRIVATE
#include "unzip.h"

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
    { "CL_TYPE_ANY",		CL_TYPE_ANY		},
    { "CL_TYPE_MSEXE",		CL_TYPE_MSEXE		},
    { "CL_TYPE_ELF",		CL_TYPE_ELF		},
    { "CL_TYPE_MACHO",		CL_TYPE_MACHO		},
    { "CL_TYPE_MACHO_UNIBIN",	CL_TYPE_MACHO_UNIBIN	},
    { "CL_TYPE_POSIX_TAR",	CL_TYPE_POSIX_TAR	},
    { "CL_TYPE_OLD_TAR",	CL_TYPE_OLD_TAR		},
    { "CL_TYPE_CPIO_OLD",	CL_TYPE_CPIO_OLD	},
    { "CL_TYPE_CPIO_ODC",	CL_TYPE_CPIO_ODC	},
    { "CL_TYPE_CPIO_NEWC",	CL_TYPE_CPIO_NEWC	},
    { "CL_TYPE_CPIO_CRC",	CL_TYPE_CPIO_CRC	},
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
    { "CL_TYPE_ISHIELD_MSI",	CL_TYPE_ISHIELD_MSI	},
    { "CL_TYPE_7Z",		CL_TYPE_7Z		},
    { "CL_TYPE_7ZSFX",		CL_TYPE_7ZSFX		},
    { "CL_TYPE_SWF",		CL_TYPE_SWF		},
    { "CL_TYPE_ISO9660",	CL_TYPE_ISO9660		},
    { "CL_TYPE_JAVA",		CL_TYPE_JAVA		},
    { "CL_TYPE_DMG",		CL_TYPE_DMG		},
    { "CL_TYPE_MBR",		CL_TYPE_MBR		},
    { "CL_TYPE_GPT",		CL_TYPE_GPT		},
    { "CL_TYPE_APM",		CL_TYPE_APM		},
    { "CL_TYPE_XAR",		CL_TYPE_XAR		},
    { "CL_TYPE_PART_ANY",	CL_TYPE_PART_ANY	},
    { "CL_TYPE_PART_HFSPLUS",	CL_TYPE_PART_HFSPLUS	},
    { "CL_TYPE_XZ",     	CL_TYPE_XZ      	},
    { "CL_TYPE_OOXML_WORD",	CL_TYPE_OOXML_WORD     	},
    { "CL_TYPE_OOXML_PPT",	CL_TYPE_OOXML_PPT     	},
    { "CL_TYPE_OOXML_XL",	CL_TYPE_OOXML_XL     	},
    { "CL_TYPE_INTERNAL",	CL_TYPE_INTERNAL     	},
    { "CL_TYPE_XDP",		CL_TYPE_XDP		},
    { "CL_TYPE_XML_WORD",	CL_TYPE_XML_WORD	},
    { "CL_TYPE_XML_XL",		CL_TYPE_XML_XL		},
    { "CL_TYPE_HWP3",		CL_TYPE_HWP3		},
    { "CL_TYPE_XML_HWP",	CL_TYPE_XML_HWP		},
    { "CL_TYPE_HWPOLE2",	CL_TYPE_HWPOLE2		},
    { "CL_TYPE_OOXML_HWP",	CL_TYPE_OOXML_HWP	},
    { "CL_TYPE_PS",		CL_TYPE_PS		},
    { "CL_TYPE_MHTML",		CL_TYPE_MHTML		},
    { "CL_TYPE_LNK", 		CL_TYPE_LNK		},
    { NULL,			CL_TYPE_IGNORED		}
};

cli_file_t cli_partitiontype(const unsigned char *buf, size_t buflen, const struct cl_engine *engine);

cli_file_t cli_ftcode(const char *name)
{
	unsigned int i;

    for(i = 0; ftmap[i].name; i++)
	if(!strcmp(ftmap[i].name, name))
	    return ftmap[i].code;

    return CL_TYPE_ERROR;
}

const char *cli_ftname(cli_file_t code)
{
	unsigned int i;

    for(i = 0; ftmap[i].name; i++)
	if(ftmap[i].code == code)
	    return ftmap[i].name;

    return NULL;
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

    ftypes = engine->ptypes;
    while(ftypes) {
	pt = ftypes;
	ftypes = ftypes->next;
	mpool_free(engine->mempool, pt->magic);
	mpool_free(engine->mempool, pt->tname);
	mpool_free(engine->mempool, pt);
    }
}

cli_file_t cli_partitiontype(const unsigned char *buf, size_t buflen, const struct cl_engine *engine)
{
    struct cli_ftype *ptype = engine->ptypes;

    while(ptype) {
	if(ptype->offset + ptype->length <= buflen) {
	    if(!memcmp(buf + ptype->offset, ptype->magic, ptype->length)) {
		cli_dbgmsg("Recognized %s partition\n", ptype->tname);
		return ptype->type;
	    }
	}
	ptype = ptype->next;
    }

    cli_dbgmsg("Partition type is potentially unsupported\n");
    return CL_TYPE_PART_ANY;
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

int is_tar(const unsigned char *buf, unsigned int nbytes);

/* organize by length, cannot exceed SIZEOF_LH */
const struct ooxml_ftcodes {
    const char *entry;
    size_t len;
    cli_file_t type;
} ooxml_detect[] = {
    { "xl/",                     3, CL_TYPE_OOXML_XL    },
    { "ppt/",                    4, CL_TYPE_OOXML_PPT   },
    { "word/",                   5, CL_TYPE_OOXML_WORD  },
    { "BinData",                 7, CL_TYPE_ZIP         }, /* HWP */
    { "mimetype",                8, CL_TYPE_ZIP         }, /* HWP */
    { "Contents",                8, CL_TYPE_ZIP         }, /* HWP */
    { "docProps/",               9, CL_TYPE_ZIP         }, /* MS */
    { "customXml/",             10, CL_TYPE_ZIP         }, /* MS */
    { "version.xml",            11, CL_TYPE_ZIP         }, /* HWP */
    { "settings.xml",           12, CL_TYPE_ZIP         }, /* HWP */
    { "_.rels/.rels",           12, CL_TYPE_ZIP         }, /* MS */
    { "[ContentTypes].xml",     18, CL_TYPE_ZIP         }, /* MS */
    { "[Content_Types].xml",    19, CL_TYPE_ZIP         }, /* MS */
    { "Preview/PrvText.txt",    19, CL_TYPE_ZIP         }, /* HWP */
    { "Contents/content.hpf",   20, CL_TYPE_OOXML_HWP   },
    { "META-INF/container.xml", 22, CL_TYPE_ZIP         }, /* HWP */
    { NULL,                      0, CL_TYPE_ANY         }
};
/* set to biggest ooxml_detect len */
#define OOXML_DETECT_MAXLEN 22

#define OOXML_FTIDENTIFIED(type)                                \
    do {                                                        \
    if (type != CL_TYPE_ZIP) {                                  \
        switch (type) {                                         \
        case CL_TYPE_OOXML_XL:                                  \
            cli_dbgmsg("Recognized OOXML XL file\n");           \
            return CL_TYPE_OOXML_XL;                            \
        case CL_TYPE_OOXML_PPT:                                 \
            cli_dbgmsg("Recognized OOXML PPT file\n");          \
            return CL_TYPE_OOXML_PPT;                           \
        case CL_TYPE_OOXML_WORD:                                \
            cli_dbgmsg("Recognized OOXML WORD file\n");         \
            return CL_TYPE_OOXML_WORD;                          \
        case CL_TYPE_OOXML_HWP:                                 \
            cli_dbgmsg("Recognized OOXML HWP file\n");          \
            return CL_TYPE_OOXML_HWP;                           \
        default:                                                \
            cli_dbgmsg("unexpected ooxml_filetype return: %i\n", type); \
        }                                                       \
    }                                                           \
    } while(0)

cli_file_t cli_filetype2(fmap_t *map, const struct cl_engine *engine, cli_file_t basetype)
{
	unsigned char buffer[MAGIC_BUFFER_SIZE];
	const unsigned char *buff;
	unsigned char *decoded;
	int bread, sret;
	cli_file_t ret = CL_TYPE_BINARY_DATA;
	struct cli_matcher *root;
	struct cli_ac_data mdata;


    if(!engine) {
	cli_errmsg("cli_filetype2: engine == NULL\n");
	return CL_TYPE_ERROR;
    }

    if(basetype == CL_TYPE_PART_ANY) {
        bread = MIN(map->len, CL_PART_MBUFF_SIZE);
    }
    else {
        bread = MIN(map->len, CL_FILE_MBUFF_SIZE);
    }
    if(bread > MAGIC_BUFFER_SIZE) {
        /* Save anyone who tampered with the header */
        bread = MAGIC_BUFFER_SIZE;
    }

    buff = fmap_need_off_once(map, 0, bread);
    if(buff) {
        sret = cli_memcpy(buffer, buff, bread);
        if(sret) {
            cli_errmsg("cli_filetype2: fileread error!\n");
            return CL_TYPE_ERROR;
        }
        sret = 0;
    } else {
        return CL_TYPE_ERROR;
    }

    if(basetype == CL_TYPE_PART_ANY) { /* typing a partition */
        ret = cli_partitiontype(buff, bread, engine);
    }
    else { /* typing a file */
        ret = cli_filetype(buff, bread, engine);

	if(ret == CL_TYPE_BINARY_DATA) {
	    switch(is_tar(buff, bread)) {
		case 1:
		    cli_dbgmsg("Recognized old fashioned tar file\n");
		    return CL_TYPE_OLD_TAR;
		case 2:
		    cli_dbgmsg("Recognized POSIX tar file\n");
		    return CL_TYPE_POSIX_TAR;
	    }
	} else if (ret == CL_TYPE_ZIP && bread > 2*(SIZEOF_LH+5)) {
            const char lhdr_magic[4] = {0x50,0x4b,0x03,0x04};
            const unsigned char *zbuff = buff;
            uint32_t zread = bread;
            uint64_t zoff = bread;
            const unsigned char * znamep = buff;
            int32_t zlen = bread;
            int lhc = 0;
            int zi, i, likely_ooxml = 0;
            cli_file_t ret2;
            
            for (zi=0; zi<32; zi++) {
                znamep = (const unsigned char *)cli_memstr((const char *)znamep, zlen, lhdr_magic, 4);
                if (NULL != znamep) {
                    znamep += SIZEOF_LH;
                    zlen = zread - (znamep - zbuff);
                    if (zlen > OOXML_DETECT_MAXLEN) {
                        for (i = 0; ooxml_detect[i].entry; i++) {
                            if (0 == memcmp(znamep, ooxml_detect[i].entry, ooxml_detect[i].len)) {
                                if (ooxml_detect[i].type != CL_TYPE_ZIP) {
                                    OOXML_FTIDENTIFIED(ooxml_detect[i].type);
                                    /* returns any unexpected type detection */
                                    return ooxml_detect[i].type;
                                }

                                likely_ooxml = 1;
                            }
                        }
                        /* only check first three readable zip headers */
                        if (++lhc > 2) {
                            /* if likely, check full archive */
                            if (likely_ooxml) {
                                cli_dbgmsg("Likely OOXML, checking additional zip headers\n");
                                if ((ret2 = cli_ooxml_filetype(NULL, map)) != CL_SUCCESS) {
                                    /* either an error or retyping has occurred, return error or just CL_TYPE_ZIP? */
                                    OOXML_FTIDENTIFIED(ret2);
                                    /* falls-through to additional filetyping */
                                }
                            }
                            break;
                        }
                    }
                    else {
                        znamep = NULL; /* force to map more */
                    }
                }

                if (znamep == NULL) {
                    if (map->len-zoff > SIZEOF_LH) {
                        zoff -= SIZEOF_LH+OOXML_DETECT_MAXLEN+1; /* remap for SIZEOF_LH+filelen for header overlap map boundary */ 
                        zread = MIN(MAGIC_BUFFER_SIZE, map->len-zoff);
                        zbuff = fmap_need_off_once(map, zoff, zread);
                        if (zbuff == NULL) {
                            cli_dbgmsg("cli_filetype2: error mapping data for OOXML check\n");
                            return CL_TYPE_ERROR;
                        }
                        zoff += zread;
                        znamep = zbuff;
                        zlen = zread;
                    }
                    else {
                        break; /* end of data */
                    }
                }
            }
        } else if (ret == CL_TYPE_MBR) {
            /* given filetype sig type 0 */
            int iret = cli_mbr_check(buff, bread, map->len);
            if (iret == CL_TYPE_GPT) {
                cli_dbgmsg("Recognized GUID Partition Table file\n");
                return CL_TYPE_GPT;
            }
            else if (iret == CL_CLEAN) {
                return CL_TYPE_MBR;
            }

            /* re-detect type */
            cli_dbgmsg("Recognized binary data\n");
            ret = CL_TYPE_BINARY_DATA;
        }
    }

    if(ret >= CL_TYPE_TEXT_ASCII && ret <= CL_TYPE_BINARY_DATA) {
	/* HTML files may contain special characters and could be
	 * misidentified as BINARY_DATA by cli_filetype()
	 */
	root = engine->root[0];
	if(!root)
	    return ret;

	if(cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))
	    return ret;

	sret = cli_ac_scanbuff(buff, bread, NULL, NULL, NULL, engine->root[0], &mdata, 0, ret, NULL, AC_SCAN_FT, NULL);

	cli_ac_freedata(&mdata);

	if(sret >= CL_TYPENO) {
	    ret = sret;
	} else {
	    if(cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))
		return ret;

	    decoded = (unsigned char *) cli_utf16toascii((char *) buff, bread);
	    if(decoded) {
		sret = cli_ac_scanbuff(decoded, bread / 2, NULL, NULL, NULL,  engine->root[0], &mdata, 0, CL_TYPE_TEXT_ASCII, NULL, AC_SCAN_FT, NULL);
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
			    unsigned char decodedbuff[(MAGIC_BUFFER_SIZE+1)*2];
			    m_area_t in_area, out_area;
			    
			    memset(decodedbuff, 0, sizeof(decodedbuff));

			    in_area.buffer = (unsigned char *) buff;
			    in_area.length = bread;
			    in_area.offset = 0;
			    out_area.buffer = decodedbuff;
			    out_area.length = sizeof(decodedbuff);
			    out_area.offset = 0;

			    /* in htmlnorm we simply skip over \0 chars, allowing HTML parsing in any unicode 
			     * (multibyte characters will not be exactly handled, but that is not a problem).
			     * However when detecting whether a file is HTML or not, we need exact conversion.
			     * (just eliminating zeros and matching would introduce false positives */
			    if(encoding_normalize_toascii(&in_area, encoding, &out_area) >= 0 && out_area.length > 0) {
				    if(cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))
					    return ret;

				    if(out_area.length > 0) {
					    sret = cli_ac_scanbuff(decodedbuff, out_area.length, NULL, NULL, NULL, engine->root[0], &mdata, 0, 0, NULL, AC_SCAN_FT, NULL); /* FIXME: can we use CL_TYPE_TEXT_ASCII instead of 0? */
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

    return ret;
}
