/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifndef __CLAMAV_H
#define __CLAMAV_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
 
#ifdef __cplusplus
extern "C"
{
#endif
 

#define CL_NUM_CHILDS 256
#define CL_MIN_LENGTH 2

#define CL_COUNT_PRECISION 4096


/* return codes */
#define CL_CLEAN	0   /* virus not found */
#define CL_VIRUS	1   /* virus found */
#define CL_EMAXREC	10  /* recursion level limit exceeded */
#define CL_EMAXSIZE	11  /* size limit exceeded */
#define CL_EMAXFILES	12  /* files limit exceeded */
#define CL_ERAR		100 /* rar handler error */
#define CL_EZIP		101 /* zip handler error */
#define	CL_EMALFZIP	102 /* malformed zip */
#define CL_EGZIP	103 /* gzip handler error */
#define CL_EBZIP	104 /* bzip2 handler error */
#define CL_EACCES	200 /* access denied */
#define CL_ENULLARG	300 /* null argument error */

#define CL_ETMPFILE	-1 /* tmpfile() failed */
#define CL_EFSYNC	-2 /* fsync() failed */
#define CL_EMEM		-3 /* memory allocation error */
#define CL_EOPEN	-4 /* file open error */
#define CL_EMALFDB	-5 /* malformed database */
#define CL_EPATSHORT	-6 /* pattern too short */
#define CL_ETMPDIR	-7 /* mkdir() failed */

/* options */
#define CL_RAW		  00
#define CL_ARCHIVE	  01
#define CL_MAIL		0100

struct patt {
    short int *pattern;
    unsigned int length;
    char *virname;
    unsigned short int sigid, parts, partno;
    struct patt *next;
};

struct cl_node {
    char islast;
    struct patt *list;
    struct cl_node *trans[CL_NUM_CHILDS], *fail;

    /* FIXME: these variables are only used in a root node */
    unsigned int maxpatlen, partsigs;
    unsigned int nodes;
    struct cl_node **nodetable;
};

struct cl_limits {
    int maxreclevel;
    int maxfiles;
    short archivememlim;
    long int maxfilesize;
};

struct cl_stat {
    char *dir;
    int no;
    struct stat *stattab;
};

/* file scanning */
extern int cl_scanbuff(const char *buffer, unsigned int length, char **virname, const struct cl_node *root);

extern int cl_scandesc(int desc, char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options);

extern int cl_scanfile(const char *filename, char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options);

/* database loading */
extern int cl_loaddb(const char *filename, struct cl_node **root, int *virnum);
extern int cl_loaddbdir(const char *dirname, struct cl_node **root, int *virnum);
extern char *cl_retdbdir(void);

/* data dir stat functions */
extern int cl_statinidir(const char *dirname, struct cl_stat *dbstat);
extern int cl_statchkdir(const struct cl_stat *dbstat);
extern int cl_statfree(struct cl_stat *dbstat);

/* enable debug information */
extern void cl_debug(void);

/* build a trie */
extern void cl_buildtrie(struct cl_node *root);

extern void cl_freetrie(struct cl_node *root);

extern char *cl_strerror(int clerror);
extern char *cl_perror(int clerror); /* deprecated */

extern char *cl_md5buff(const char *buffer, unsigned int length);

extern int cl_mbox(const char *dir, int desc);

/* compute MD5 message digest from filename (compatible with md5sum(1)) */
extern char *cl_md5file(const char *filename);

/* decode hexadecimal string */
extern short int *cl_hex2str(const char *hex);

/* encode a buffer 'string' length of 'len' to a hexadecimal string */
extern char *cl_str2hex(const char *string, unsigned int len);

/* generate a pseudo-random number */
extern unsigned int cl_rndnum(unsigned int max);

#ifdef __cplusplus
};
#endif
 
#endif
