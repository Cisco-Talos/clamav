/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
 *  With enhancements from Thomas Lamy <Thomas.Lamy@in-online.net>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "clamav.h"
#include "filetypes.h"
#include "others.h"
#include "readdb.h"

struct cli_magic_s {
    int offset;
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

    /* Archives */

    {0,	    "Rar!",			4,  "RAR",		CL_TYPE_RAR},
    {0,	    "PK\003\004",		4,  "ZIP",		CL_TYPE_ZIP},
    {0,	    "PK00PK\003\004",		8,  "ZIP",		CL_TYPE_ZIP},
    {0,	    "\037\213",			2,  "GZip",		CL_TYPE_GZ},
    {0,	    "BZh",			3,  "BZip",		CL_TYPE_BZ},
    {0,	    "SZDD",			4,  "compress.exe'd",	CL_TYPE_MSSZDD},
    {0,	    "MSCF",			4,  "MS CAB",		CL_TYPE_MSCAB},
    {0,	    "ITSF",			4,  "MS CHM",           CL_TYPE_MSCHM},
    {257,   "ustar",			5,  "POSIX tar",	CL_TYPE_TAR},
    {0,     "#@~^",			4,  "SCRENC",		CL_TYPE_SCRENC},

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

    /* Others */

    {0,  "\320\317\021\340\241\261\032\341",
	                    8, "OLE2 container",  CL_TYPE_MSOLE2},

    /* Graphics (may contain exploits against MS systems) */

    {0,  "GIF",				 3, "GIF",	    CL_TYPE_GRAPHICS},
    {0,  "BM",				 2, "BMP",          CL_TYPE_GRAPHICS},
    {0,  "\377\330\377",		 3, "JPEG",         CL_TYPE_GRAPHICS},
    {6,  "JFIF",			 4, "JPEG",         CL_TYPE_GRAPHICS},
    {6,  "Exif",			 4, "JPEG",         CL_TYPE_GRAPHICS},
    {0,  "\x89PNG",			 4, "PNG",          CL_TYPE_GRAPHICS},

    /* Ignored types */

    {0,  "\000\000\001\263",             4, "MPEG video stream",  CL_TYPE_DATA},
    {0,  "\000\000\001\272",             4, "MPEG sys stream",    CL_TYPE_DATA},
    {0,  "RIFF",                         4, "RIFF",		  CL_TYPE_DATA},
    {0,  "OggS",                         4, "Ogg Stream",         CL_TYPE_DATA},
    {0,  "ID3",				 3, "MP3",		  CL_TYPE_DATA},
    {0,  "\377\373\220",		 3, "MP3",		  CL_TYPE_DATA},
    {0,  "\%PDF-",			 5, "PDF document",	  CL_TYPE_DATA},
    {0,  "\%!PS-Adobe-",		11, "PostScript",	  CL_TYPE_DATA},
    {0,  "\060\046\262\165\216\146\317", 7, "WMA/WMV/ASF",	  CL_TYPE_DATA},
    {0,  ".RMF" ,			 4, "Real Media File",	  CL_TYPE_DATA},

    {-1, NULL,				 0, NULL,		  CL_TYPE_UNKNOWN_DATA}
};

static const struct cli_smagic_s cli_smagic[] = {

    /* "\nFrom: " * "\nContent-Type: " */
    {"0a46726f6d3a20{-2048}0a436f6e74656e742d547970653a20", "Mail file", CL_TYPE_MAIL},

    /* "\nReceived: " * "\nContent-Type: " */
    {"0a52656365697665643a20{-2048}0a436f6e74656e742d547970653a20", "Mail file", CL_TYPE_MAIL},

    /* "\nReceived: " * "\nContent-type: " */
    {"0a52656365697665643a20{-2048}0a436f6e74656e742d747970653a20", "Mail file", CL_TYPE_MAIL},

    /* remember the matcher is case sensitive */
    {"3c62723e",       "HTML data", CL_TYPE_HTML},	/* <br> */
    {"3c42723e",       "HTML data", CL_TYPE_HTML},	/* <Br> */
    {"3c42523e",       "HTML data", CL_TYPE_HTML},	/* <BR> */
    {"3c703e",	       "HTML data", CL_TYPE_HTML},	/* <p> */
    {"3c503e",	       "HTML data", CL_TYPE_HTML},	/* <P> */
    {"68726566",       "HTML data", CL_TYPE_HTML},	/* href */
    {"48726566",       "HTML data", CL_TYPE_HTML},	/* Href */
    {"48524546",       "HTML data", CL_TYPE_HTML},	/* HREF */
    {"3c686561643e",   "HTML data", CL_TYPE_HTML},      /* <head> */
    {"3c484541443e",   "HTML data", CL_TYPE_HTML},      /* <HEAD> */
    {"3c486561643e",   "HTML data", CL_TYPE_HTML},      /* <Head> */
    {"3c666f6e74",     "HTML data", CL_TYPE_HTML},	/* <font */
    {"3c466f6e74",     "HTML data", CL_TYPE_HTML},	/* <Font */
    {"3c464f4e54",     "HTML data", CL_TYPE_HTML},	/* <FONT */
    {"3c736372697074", "HTML data", CL_TYPE_HTML},	/* <script */
    {"3c536372697074", "HTML data", CL_TYPE_HTML},	/* <Script */
    {"3c534352495054", "HTML data", CL_TYPE_HTML},	/* <SCRIPT */
    {"3c6f626a656374", "HTML data", CL_TYPE_HTML},      /* <object */
    {"3c4f626a656374", "HTML data", CL_TYPE_HTML},      /* <Object */
    {"3c4f424a454354", "HTML data", CL_TYPE_HTML},      /* <OBJECT */
    {"3c696672616d65", "HTML data", CL_TYPE_HTML},      /* <iframe */
    {"3c494652414d45", "HTML data", CL_TYPE_HTML},      /* <IFRAME */

    {NULL,  NULL,   CL_TYPE_UNKNOWN_DATA}
};

cli_file_t cli_filetype(const char *buf, size_t buflen)
{
	int i, ascii = 1, len;


    for(i = 0; cli_magic[i].magic; i++) {
	if(buflen >= cli_magic[i].offset+cli_magic[i].length) {
	    if(memcmp(buf+cli_magic[i].offset, cli_magic[i].magic, cli_magic[i].length) == 0) {
		cli_dbgmsg("Recognized %s file\n", cli_magic[i].descr);
		return cli_magic[i].type;
	    }
	}
    }

    buflen < 25 ? (len = buflen) : (len = 25);
    for(i = 0; i < len; i++)
	if(!iscntrl(buf[i]) && !isprint(buf[i])) { /* FIXME: handle international chars */
	    ascii = 0;
	    break;
	}

    return ascii ? CL_TYPE_UNKNOWN_TEXT : CL_TYPE_UNKNOWN_DATA;
}

int cli_addtypesigs(struct cl_node *root)
{
	int i, ret;

    for(i = 0; cli_smagic[i].sig; i++) {
	if((ret = cli_parse_add(root, cli_smagic[i].descr, cli_smagic[i].sig, cli_smagic[i].type, NULL, 0))) {
	    cli_errmsg("cli_addtypesigs(): Problem adding signature for %s\n", cli_smagic[i].descr);
	    return ret;
	}
    }

    return 0;
}
