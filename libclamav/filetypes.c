/*
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
#include <ctype.h>
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

struct cli_magic_s {
    size_t offset;
    const char *magic;
    size_t length;
    const char *descr;
    cli_file_t type;
};

struct cli_smagic_s {
    const char *sig;
    const char *descr;
    cli_file_t type;
};

static const struct cli_magic_s cli_magic[] = {

    /* Executables */

    {0,  "MZ",				2,  "DOS/W32 executable/library/driver", CL_TYPE_MSEXE},
    {0,	 "\177ELF",			4,  "ELF",		CL_TYPE_ELF},

    /* Archives */

    {0,	    "Rar!",			4,  "RAR",		CL_TYPE_RAR},
    {0,	    "PK\003\004",		4,  "ZIP",		CL_TYPE_ZIP},
    {0,	    "PK00PK\003\004",		8,  "ZIP",		CL_TYPE_ZIP},
    {0,	    "\037\213",			2,  "GZip",		CL_TYPE_GZ},
    {0,	    "BZh",			3,  "BZip",		CL_TYPE_BZ},
    {0,	    "\x60\xea",			2,  "ARJ",		CL_TYPE_ARJ},
    {0,	    "SZDD",			4,  "compress.exe'd",	CL_TYPE_MSSZDD},
    {0,	    "MSCF",			4,  "MS CAB",		CL_TYPE_MSCAB},
    {0,	    "ITSF",			4,  "MS CHM",           CL_TYPE_MSCHM},
    {8,	    "\x19\x04\x00\x10",		4,  "SIS",		CL_TYPE_SIS},
    {0,     "#@~^",			4,  "SCRENC",		CL_TYPE_SCRENC},
    {0,     "(This file must be converted with BinHex 4.0)",
				       45, "BinHex",		CL_TYPE_BINHEX},

    /* Mail */

    {0,  "From ",			 5, "MBox",		  CL_TYPE_MAIL},
    {0,  "Received: ",			10, "Raw mail",		  CL_TYPE_MAIL},
    {0,  "Return-Path: ",		13, "Maildir",		  CL_TYPE_MAIL},
    {0,  "Return-path: ",		13, "Maildir",		  CL_TYPE_MAIL},
    {0,  "Delivered-To: ",		14, "Mail",		  CL_TYPE_MAIL},
    {0,  "X-UIDL: ",			 8, "Mail",		  CL_TYPE_MAIL},
    {0,  "X-Apparently-To: ",		17, "Mail",		  CL_TYPE_MAIL},
    {0,  "X-Envelope-From: ",		17, "Mail",		  CL_TYPE_MAIL},
    {0,  "X-Original-To: ",		15, "Mail",		  CL_TYPE_MAIL},
    {0,  "X-Symantec-",			11, "Symantec",		  CL_TYPE_MAIL},
    {0,  "X-EVS",			 5, "EVS mail",		  CL_TYPE_MAIL},
    {0,  "X-Real-To: ",                 11, "Mail",               CL_TYPE_MAIL},
    {0,  "X-Sieve: ",			 9, "Mail",		  CL_TYPE_MAIL},
    {0,  ">From ",			 6, "Mail",		  CL_TYPE_MAIL},
    {0,  "Date: ",			 6, "Mail",		  CL_TYPE_MAIL},
    {0,  "Message-Id: ",		12, "Mail",		  CL_TYPE_MAIL},
    {0,  "Message-ID: ",		12, "Mail",		  CL_TYPE_MAIL},
    {0,  "Envelope-to: ",		13, "Mail",		  CL_TYPE_MAIL},
    {0,  "Delivery-date: ",		15, "Mail",		  CL_TYPE_MAIL},
    {0,  "To: ",			 4, "Mail",		  CL_TYPE_MAIL},
    {0,  "Subject: ",			 9, "Mail",		  CL_TYPE_MAIL},
    {0,  "For: ",			 5, "Eserv mail",	  CL_TYPE_MAIL},
    {0,  "From: ",			 6, "Exim mail",	  CL_TYPE_MAIL},
    {0,  "v:\015\012Received: ",	14, "VPOP3 Mail (DOS)",	  CL_TYPE_MAIL},
    {0,  "v:\012Received: ",		13, "VPOP3 Mail (UNIX)",  CL_TYPE_MAIL},
    {0,  "Hi. This is the qmail-send",  26, "Qmail bounce",	  CL_TYPE_MAIL},
    {0,  "\170\237\076\042",		 4, "TNEF",               CL_TYPE_TNEF},

    {0,  "begin ",			6,  "UUencoded",	  CL_TYPE_UUENCODED},
    {0, "\041\102\104\116",		4, "PST",		  CL_TYPE_PST},

    /* Graphics (may contain exploits against MS systems) */

    {0,  "GIF",				 3, "GIF",	    CL_TYPE_GRAPHICS},
    {0,  "BM",				 2, "BMP",          CL_TYPE_GRAPHICS},
    {0,  "\377\330\377",		 3, "JPEG",         CL_TYPE_GRAPHICS},
    {6,  "JFIF",			 4, "JPEG",         CL_TYPE_GRAPHICS},
    {6,  "Exif",			 4, "JPEG",         CL_TYPE_GRAPHICS},
    {0,  "\x89PNG",			 4, "PNG",          CL_TYPE_GRAPHICS},
    {0,  "RIFF",                         4, "RIFF",         CL_TYPE_RIFF},
    {0,  "RIFX",                         4, "RIFX",         CL_TYPE_RIFF},

    /* Others */

    {0,  "\320\317\021\340\241\261\032\341", 8, "OLE2 container", CL_TYPE_MSOLE2},
    {0,  "%PDF-",			 5, "PDF document", CL_TYPE_PDF},
    {0,  "\266\271\254\256\376\377\377\377", 8, "CryptFF", CL_TYPE_CRYPTFF},
    {0,  "{\\rtf",                           5, "RTF", CL_TYPE_RTF}, 

    /* Ignored types */

    {0,  "\000\000\001\263",             4, "MPEG video stream",  CL_TYPE_DATA},
    {0,  "\000\000\001\272",             4, "MPEG sys stream",    CL_TYPE_DATA},
    {0,  "OggS",                         4, "Ogg Stream",         CL_TYPE_DATA},
    {0,  "ID3",				 3, "MP3",		  CL_TYPE_DATA},
    {0,  "\377\373\220",		 3, "MP3",		  CL_TYPE_DATA},
    {0,  "%!PS-Adobe-",			11, "PostScript",	  CL_TYPE_DATA},
    {0,  "\060\046\262\165\216\146\317", 7, "WMA/WMV/ASF",	  CL_TYPE_DATA},
    {0,  ".RMF" ,			 4, "Real Media File",	  CL_TYPE_DATA},

    {0, NULL,				 0, NULL,		  CL_TYPE_UNKNOWN_DATA}
};

static const struct cli_smagic_s cli_smagic[] = {

    /* "\nFrom: " * "\nContent-Type: " */
    {"0a46726f6d3a20{-2048}0a436f6e74656e742d547970653a20", "Mail file", CL_TYPE_MAIL},

    /* "\nReceived: " * "\nContent-Type: " */
    {"0a52656365697665643a20{-2048}0a436f6e74656e742d547970653a20", "Mail file", CL_TYPE_MAIL},

    /* "\nReceived: " * "\nContent-type: " */
    {"0a52656365697665643a20{-2048}0a436f6e74656e742d747970653a20", "Mail file", CL_TYPE_MAIL},

    /* "MIME-Version: " * "\nContent-Type: " */
    {"4d494d452d56657273696f6e3a20{-2048}0a436f6e74656e742d547970653a20", "Mail file", CL_TYPE_MAIL},

    /* remember the matcher is case sensitive */
    {"3c62723e",       "HTML data", CL_TYPE_HTML},	/* <br> */
    {"3c42723e",       "HTML data", CL_TYPE_HTML},	/* <Br> */
    {"3c42523e",       "HTML data", CL_TYPE_HTML},	/* <BR> */
    {"3c703e",	       "HTML data", CL_TYPE_HTML},	/* <p> */
    {"3c503e",	       "HTML data", CL_TYPE_HTML},	/* <P> */
    {"68726566",       "HTML data", CL_TYPE_HTML},	/* href */
    {"48726566",       "HTML data", CL_TYPE_HTML},	/* Href */
    {"48524546",       "HTML data", CL_TYPE_HTML},	/* HREF */
    {"3c68746d6c3e",   "HTML data", CL_TYPE_HTML},      /* <html> */
    {"3c48544d4c3e",   "HTML data", CL_TYPE_HTML},      /* <HTML> */
    {"3c48746d6c3e",   "HTML data", CL_TYPE_HTML},      /* <Html> */
    {"3c686561643e",   "HTML data", CL_TYPE_HTML},      /* <head> */
    {"3c484541443e",   "HTML data", CL_TYPE_HTML},      /* <HEAD> */
    {"3c486561643e",   "HTML data", CL_TYPE_HTML},      /* <Head> */
    {"3c666f6e74",     "HTML data", CL_TYPE_HTML},	/* <font */
    {"3c466f6e74",     "HTML data", CL_TYPE_HTML},	/* <Font */
    {"3c464f4e54",     "HTML data", CL_TYPE_HTML},	/* <FONT */
    {"3c696d67",       "HTML data", CL_TYPE_HTML},      /* <img */
    {"3c494d47",       "HTML data", CL_TYPE_HTML},      /* <IMG */
    {"3c496d67",       "HTML data", CL_TYPE_HTML},      /* <Img */
    {"3c736372697074", "HTML data", CL_TYPE_HTML},	/* <script */
    {"3c536372697074", "HTML data", CL_TYPE_HTML},	/* <Script */
    {"3c534352495054", "HTML data", CL_TYPE_HTML},	/* <SCRIPT */
    {"3c6f626a656374", "HTML data", CL_TYPE_HTML},      /* <object */
    {"3c4f626a656374", "HTML data", CL_TYPE_HTML},      /* <Object */
    {"3c4f424a454354", "HTML data", CL_TYPE_HTML},      /* <OBJECT */
    {"3c696672616d65", "HTML data", CL_TYPE_HTML},      /* <iframe */
    {"3c494652414d45", "HTML data", CL_TYPE_HTML},      /* <IFRAME */
    {"3c7461626c65",   "HTML data", CL_TYPE_HTML},	/* <table */
    {"3c5441424c45",   "HTML data", CL_TYPE_HTML},	/* <TABLE */

    {"526172211a0700", "RAR-SFX", CL_TYPE_RARSFX},
    {"504b0304", "ZIP-SFX", CL_TYPE_ZIPSFX},
    {"4d534346", "CAB-SFX", CL_TYPE_CABSFX},
    {"60ea{7}0002", "ARJ-SFX", CL_TYPE_ARJSFX},
    {"60ea{7}0102", "ARJ-SFX", CL_TYPE_ARJSFX},
    {"60ea{7}0202", "ARJ-SFX", CL_TYPE_ARJSFX},
    {"efbeadde4e756c6c736f6674496e7374", "NSIS", CL_TYPE_NULSFT},
    {"a3484bbe986c4aa9994c530a86d6487d41553321454130(35|36)", "AUTOIT", CL_TYPE_AUTOIT},

    {"4d5a{60-300}50450000", "PE", CL_TYPE_MSEXE},

    {NULL,  NULL,   CL_TYPE_UNKNOWN_DATA}
};

static char internat[256] = {
    /* TODO: Remember to buy a beer to Joerg Wunsch <joerg@FreeBSD.ORG> */
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0,  /* 0x0X */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,  /* 0x1X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x2X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x3X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x4X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x5X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x6X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,  /* 0x7X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x8X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x9X */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0xaX */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0xbX */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0xcX */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0xdX */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0xeX */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1   /* 0xfX */
};

cli_file_t cli_filetype(const unsigned char *buf, size_t buflen)
{
	int i, text = 1, len;


    for(i = 0; cli_magic[i].magic; i++) {
	if(buflen >= cli_magic[i].offset+cli_magic[i].length) {
	    if(memcmp(buf+cli_magic[i].offset, cli_magic[i].magic, cli_magic[i].length) == 0) {
		cli_dbgmsg("Recognized %s file\n", cli_magic[i].descr);
		return cli_magic[i].type;
	    }
	}
    }

/* improve or drop this code
 * https://wwws.clamav.net/bugzilla/show_bug.cgi?id=373
 *
    buflen < 25 ? (len = buflen) : (len = 25);
    for(i = 0; i < len; i++)
	if(!iscntrl(buf[i]) && !isprint(buf[i]) && !internat[buf[i] & 0xff]) {
	    text = 0;
	    break;
	}
*/
    return text ? CL_TYPE_UNKNOWN_TEXT : CL_TYPE_UNKNOWN_DATA;
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
	ret = cli_filetype(smallbuff, bread);

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
		ret = CL_TYPE_DATA;
	    } else if(!memcmp(bigbuff + 32776, "CDROM" , 5)) {
		cli_dbgmsg("Recognized High Sierra CD-ROM data\n");
		ret = CL_TYPE_DATA;
	    }
	}

	free(bigbuff);
    }

    return ret;
}

int cli_addtypesigs(struct cl_engine *engine)
{
	int i, ret;
	struct cli_matcher *root;


    if(!engine->root[0]) {
	cli_dbgmsg("cli_addtypesigs: Need to allocate AC trie in engine->root[0]\n");
	root = engine->root[0] = (struct cli_matcher *) cli_calloc(1, sizeof(struct cli_matcher));
	if(!root) {
	    cli_errmsg("cli_addtypesigs: Can't initialise AC pattern matcher\n");
	    return CL_EMEM;
	}

	if((ret = cli_ac_init(root, cli_ac_mindepth, cli_ac_maxdepth))) {
	    /* No need to free previously allocated memory here - all engine
	     * elements will be properly freed by cl_free()
	     */
	    cli_errmsg("cli_addtypesigs: Can't initialise AC pattern matcher\n");
	    return ret;
	}
    } else {
	root = engine->root[0];
    }

    for(i = 0; cli_smagic[i].sig; i++) {
	if((ret = cli_parse_add(root, cli_smagic[i].descr, cli_smagic[i].sig, cli_smagic[i].type, NULL, 0))) {
	    cli_errmsg("cli_addtypesigs: Problem adding signature for %s\n", cli_smagic[i].descr);
	    return ret;
	}
    }

    return 0;
}
