/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __CLAMAV_H
#define __CLAMAV_H

#include <sys/types.h>
#include <sys/stat.h>
 
#ifdef __cplusplus
extern "C"
{
#endif


#define CL_COUNT_PRECISION 4096

/* return codes */
#define CL_CLEAN	0   /* virus not found */
#define CL_VIRUS	1   /* virus found */
#define CL_SUCCESS	CL_CLEAN

#define CL_EMAXREC	10  /* recursion level limit exceeded */
#define CL_EMAXSIZE	11  /* size limit exceeded */
#define CL_EMAXFILES	12  /* files limit exceeded */
#define CL_ERAR		100 /* rar handler error */
#define CL_EZIP		101 /* zip handler error */
#define	CL_EMALFZIP	102 /* malformed zip */
#define CL_EGZIP	103 /* gzip handler error */
#define CL_EBZIP	104 /* bzip2 handler error */
#define CL_EOLE2	105 /* OLE2 handler error */
#define CL_EMSCOMP	106 /* compress.exe handler error */
#define CL_EMSCAB	107 /* MS CAB module error */
#define CL_EACCES	200 /* access denied */
#define CL_ENULLARG	300 /* null argument error */

#define CL_ETMPFILE	-1  /* tmpfile() failed */
#define CL_EFSYNC	-2  /* fsync() failed */
#define CL_EMEM		-3  /* memory allocation error */
#define CL_EOPEN	-4  /* file open error */
#define CL_EMALFDB	-5  /* malformed database */
#define CL_EPATSHORT	-6  /* pattern too short */
#define CL_ETMPDIR	-7  /* mkdir() failed */
#define CL_ECVD		-8  /* not a CVD file (or broken) */
#define CL_ECVDEXTR	-9  /* CVD extraction failure */
#define CL_EMD5		-10 /* MD5 verification error */
#define CL_EDSIG	-11 /* digital signature verification error */
#define CL_EIO		-12 /* general I/O error */
#define CL_EFORMAT	-13 /* bad format or broken file */
#define CL_ESUPPORT	-14 /* not supported data format */

#define CL_EHWINIT	-15 /* hardware initialization failed */
#define	CL_EHWLOAD	-16 /* error loading hardware database */
#define CL_EHWIO	-17 /* general hardware I/O error */


/* db options */
#define CL_DB_HWACCEL		1
#define CL_DB_NOPHISHING	2
#define CL_DB_ACONLY		4   /* for developers only */

#define CL_DB_STDOPT		0

/* scan options */
#define CL_SCAN_RAW		0
#define CL_SCAN_ARCHIVE		1
#define CL_SCAN_MAIL		2
#define CL_SCAN_OLE2		4
#define CL_SCAN_BLOCKENCRYPTED	8
#define CL_SCAN_HTML		16
#define CL_SCAN_PE		32
#define CL_SCAN_BLOCKBROKEN	64
#define CL_SCAN_MAILURL		128
#define CL_SCAN_BLOCKMAX	256
#define CL_SCAN_ALGO		512
#define CL_SCAN_NOPHISHING      1024
#define CL_PHISH_NO_DOMAINLIST    4096

/* recommended options */
#define CL_SCAN_STDOPT		(CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_OLE2 | CL_SCAN_HTML | CL_SCAN_PE | CL_SCAN_ALGO) 

/* aliases for backward compatibility */
#define CL_RAW		CL_SCAN_RAW
#define CL_ARCHIVE	CL_SCAN_ARCHIVE
#define CL_MAIL		CL_SCAN_MAIL
#define CL_OLE2		CL_SCAN_OLE2
#define CL_ENCRYPTED    CL_SCAN_BLOCKENCRYPTED
#define cl_node		cl_engine


struct cli_bm_patt {
    char *pattern, *virname, *offset;
    const char *viralias;
    unsigned int length;
    unsigned short target;
    struct cli_bm_patt *next;
};

struct cli_ac_patt {
    short int *pattern, *prefix;
    unsigned int length, mindist, maxdist, prefix_length;
    char *virname, *offset;
    const char *viralias;
    unsigned short int sigid, parts, partno, alt, *altn, alt_pattern;
    unsigned short type, target;
    char **altc;
    struct cli_ac_patt *next;
};

struct cli_ac_node {
    char islast;
    struct cli_ac_patt *list;
    struct cli_ac_node *trans[256], *fail;
};

struct cli_md5_node {
    char *virname, *viralias;
    unsigned char *md5;
    unsigned int size;
    unsigned short fp;
    struct cli_md5_node *next;
};

struct cli_meta_node {
    int csize, size, method;
    unsigned int crc32, fileno, encrypted, maxdepth;
    char *filename, *virname;
    struct cli_meta_node *next;
};

struct cli_matcher {
    unsigned int maxpatlen; /* maximal length of pattern in db */
    unsigned short ac_only;

    /* Extended Boyer-Moore */
    int *bm_shift;
    struct cli_bm_patt **bm_suffix;

    /* Extended Aho-Corasick */
    unsigned int ac_depth;
    struct cli_ac_node *ac_root, **ac_nodetable;
    unsigned int ac_partsigs, ac_nodes;
};

struct cl_engine {
    unsigned int refcount; /* reference counter */
    unsigned short hwaccel;
    unsigned short sdb;

    /* Roots table */
    struct cli_matcher **root;

    /* MD5 */
    struct cli_md5_node **md5_hlist;

    /* MD5 list for PE sections */
    struct cli_md5_node *md5_sect;

    /* Zip metadata */
    struct cli_meta_node *zip_mlist;

    /* RAR metadata */
    struct cli_meta_node *rar_mlist;

    /* Hardware database handle */
    void *hwdb;

    /* Phishing .pdb and .wdb databases*/
    void *whitelist_matcher;
    void *domainlist_matcher;
};

struct cl_limits {
    unsigned int maxreclevel; /* maximal recursion level */
    unsigned int maxfiles; /* maximal number of files to be
			    * scanned within an archive
			    */
    unsigned int maxratio; /* maximal compression ratio */
    unsigned short archivememlim; /* limit memory usage for bzip2 (0/1) */
    unsigned long int maxfilesize; /* files in an archive larger than
				    * this limit will not be scanned
				    */
};

struct cl_stat {
    char *dir;
    int no;
    struct stat *stattab;
    char **statdname;
};

struct cl_cvd {
    char *time;	    /* 2 */
    int version;    /* 3 */
    int sigs;	    /* 4 */
    short int fl;   /* 5 */
    char *md5;	    /* 6 */
    char *dsig;	    /* 7 */
    char *builder;  /* 8 */
    int stime;	    /* 9 */
};

/* file scanning */
extern int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options);

extern int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options);

/* software versions */
extern int cl_retflevel(void);
extern const char *cl_retver(void);

/* database */
extern int cl_loaddb(const char *filename, struct cl_engine **engine, unsigned int *signo);
extern int cl_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo);
extern int cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options);
extern const char *cl_retdbdir(void);
extern struct cl_engine *cl_dup(struct cl_engine *engine);

/* CVD */
extern struct cl_cvd *cl_cvdhead(const char *file);
extern struct cl_cvd *cl_cvdparse(const char *head);
extern int cl_cvdverify(const char *file);
extern void cl_cvdfree(struct cl_cvd *cvd);

/* data dir stat functions */
extern int cl_statinidir(const char *dirname, struct cl_stat *dbstat);
extern int cl_statchkdir(const struct cl_stat *dbstat);
extern int cl_statfree(struct cl_stat *dbstat);

/* enable debug information */
extern void cl_debug(void);

extern void cl_settempdir(const char *dir, short leavetemps);

extern int cl_build(struct cl_engine *engine);
extern void cl_free(struct cl_engine *engine);

extern const char *cl_strerror(int clerror);

#ifdef __cplusplus
}
#endif
 
#endif
