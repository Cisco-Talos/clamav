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
#define CL_CLEAN	0   /* no virus found */
#define CL_VIRUS	1   /* virus(es) found */
#define CL_SUCCESS	CL_CLEAN

#define CL_EMAXREC	-100 /* recursion limit exceeded */
#define CL_EMAXSIZE	-101 /* size limit exceeded */
#define CL_EMAXFILES	-102 /* files limit exceeded */
#define CL_ERAR		-103 /* rar handler error */
#define CL_EZIP		-104 /* zip handler error */
#define CL_EGZIP	-105 /* gzip handler error */
#define CL_EBZIP	-106 /* bzip2 handler error */
#define CL_EOLE2	-107 /* OLE2 handler error */
#define CL_EMSCOMP	-108 /* MS Expand handler error */
#define CL_EMSCAB	-109 /* MS CAB module error */
#define CL_EACCES	-110 /* access denied */
#define CL_ENULLARG	-111 /* null argument */
#define CL_ETMPFILE	-112 /* tmpfile() failed */
#define CL_EFSYNC	-113 /* fsync() failed */
#define CL_EMEM		-114 /* memory allocation error */
#define CL_EOPEN	-115 /* file open error */
#define CL_EMALFDB	-116 /* malformed database */
#define CL_EPATSHORT	-117 /* pattern too short */
#define CL_ETMPDIR	-118 /* mkdir() failed */
#define CL_ECVD		-119 /* not a CVD file (or broken) */
#define CL_ECVDEXTR	-120 /* CVD extraction failure */
#define CL_EMD5		-121 /* MD5 verification error */
#define CL_EDSIG	-122 /* digital signature verification error */
#define CL_EIO		-123 /* general I/O error */
#define CL_EFORMAT	-124 /* bad format or broken file */
#define CL_ESUPPORT	-125 /* not supported data format */

/* NodalCore */
#define CL_ENCINIT	-200 /* NodalCore initialization failed */
#define	CL_ENCLOAD	-201 /* error loading NodalCore database */
#define CL_ENCIO	-202 /* general NodalCore I/O error */

/* db options */
#define CL_DB_NCORE	    0x1
#define CL_DB_NOPHISHING    0x2
#define CL_DB_ACONLY	    0x4 /* WARNING: only for developers */

/* recommended db settings */
#define CL_DB_STDOPT	    0x0

/* scan options */
#define CL_SCAN_RAW		0x0
#define CL_SCAN_ARCHIVE		0x1
#define CL_SCAN_MAIL		0x2
#define CL_SCAN_OLE2		0x4
#define CL_SCAN_BLOCKENCRYPTED	0x8
#define CL_SCAN_HTML		0x10
#define CL_SCAN_PE		0x20
#define CL_SCAN_BLOCKBROKEN	0x40
#define CL_SCAN_MAILURL		0x80
#define CL_SCAN_BLOCKMAX	0x100
#define CL_SCAN_ALGO		0x200
#define CL_SCAN_NOPHISHING      0x400
#define CL_PHISH_NO_DOMAINLIST  0x800
#define CL_SCAN_ELF		0x1000

/* recommended scan settings */
#define CL_SCAN_STDOPT		(CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_OLE2 | CL_SCAN_HTML | CL_SCAN_PE | CL_SCAN_ALGO | CL_SCAN_ELF) 

/* aliases for backward compatibility */
#define CL_RAW		CL_SCAN_RAW
#define CL_ARCHIVE	CL_SCAN_ARCHIVE
#define CL_MAIL		CL_SCAN_MAIL
#define CL_OLE2		CL_SCAN_OLE2
#define CL_ENCRYPTED    CL_SCAN_BLOCKENCRYPTED
#define cl_node		cl_engine

/* internal structures */
struct cli_bm_patt {
    unsigned char *pattern;
    char *virname, *offset;
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
    unsigned char islast;
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
    unsigned short ncore;
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

    /* NodalCore database handle */
    void *ncdb;

    /* Phishing .pdb and .wdb databases*/
    void *whitelist_matcher;
    void *domainlist_matcher;
    void *phishcheck;
};

struct cl_limits {
    unsigned int maxreclevel;	    /* maximum recursion level */
    unsigned int maxfiles;	    /* maximum number of files to be scanned
				     * within a single archive
				     */
    unsigned int maxratio;	    /* maximum compression ratio */
    unsigned short archivememlim;   /* limit memory usage for some unpackers */
    unsigned long int maxfilesize;  /* compressed files larger than this limit
				     * will not be scanned
				     */
};

struct cl_stat {
    char *dir;
    unsigned int entries;
    struct stat *stattab;
    char **statdname;
};

struct cl_cvd {		    /* field no. */
    char *time;		    /* 2 */
    unsigned int version;   /* 3 */
    unsigned int sigs;	    /* 4 */
    unsigned int fl;	    /* 5 */
    char *md5;		    /* 6 */
    char *dsig;		    /* 7 */
    char *builder;	    /* 8 */
    unsigned int stime;	    /* 9 */
};

/* file scanning */
extern int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options);

extern int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options);

/* database handling */
extern int cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options);
extern const char *cl_retdbdir(void);

/* engine handling */
extern int cl_build(struct cl_engine *engine);
extern struct cl_engine *cl_dup(struct cl_engine *engine);
extern void cl_free(struct cl_engine *engine);

/* CVD */
extern struct cl_cvd *cl_cvdhead(const char *file);
extern struct cl_cvd *cl_cvdparse(const char *head);
extern int cl_cvdverify(const char *file);
extern void cl_cvdfree(struct cl_cvd *cvd);

/* db dir stat functions */
extern int cl_statinidir(const char *dirname, struct cl_stat *dbstat);
extern int cl_statchkdir(const struct cl_stat *dbstat);
extern int cl_statfree(struct cl_stat *dbstat);

/* enable debug messages */
extern void cl_debug(void);

/* software versions */
extern unsigned int cl_retflevel(void);
extern const char *cl_retver(void);

/* others */
extern void cl_settempdir(const char *dir, short leavetemps);
extern const char *cl_strerror(int clerror);

#ifdef __cplusplus
}
#endif
 
#endif /* __CLAMAV_H */
