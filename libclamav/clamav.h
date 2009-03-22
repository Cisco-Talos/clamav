/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
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
typedef enum {
    /* libclamav specific */
    CL_CLEAN = 0,
    CL_SUCCESS = 0,
    CL_VIRUS,
    CL_ENULLARG,
    CL_EARG,
    CL_EMALFDB,
    CL_ECVD,
    CL_EVERIFY,
    CL_EUNPACK,

    /* I/O and memory errors */
    CL_EOPEN,
    CL_ECREAT,
    CL_EUNLINK,
    CL_ESTAT,
    CL_EREAD,
    CL_ESEEK,
    CL_EWRITE,
    CL_EDUP,
    CL_EACCES,
    CL_ETMPFILE,
    CL_ETMPDIR,
    CL_EMAP,
    CL_EMEM,
    CL_ETIMEOUT,

    /* internal (not reported outside libclamav) */
    CL_BREAK,
    CL_EMAXREC,
    CL_EMAXSIZE,
    CL_EMAXFILES,
    CL_EFORMAT
} cl_error_t;

/* db options */
#define CL_DB_PHISHING	    0x2
#define CL_DB_PHISHING_URLS 0x8
#define CL_DB_PUA	    0x10
#define CL_DB_CVDNOTMP	    0x20
#define CL_DB_OFFICIAL	    0x40    /* internal */
#define CL_DB_PUA_MODE	    0x80
#define CL_DB_PUA_INCLUDE   0x100
#define CL_DB_PUA_EXCLUDE   0x200
#define CL_DB_COMPILED	    0x400   /* internal */

/* recommended db settings */
#define CL_DB_STDOPT	    (CL_DB_PHISHING | CL_DB_PHISHING_URLS)

/* scan options */
#define CL_SCAN_RAW			0x0
#define CL_SCAN_ARCHIVE			0x1
#define CL_SCAN_MAIL			0x2
#define CL_SCAN_OLE2			0x4
#define CL_SCAN_BLOCKENCRYPTED		0x8
#define CL_SCAN_HTML			0x10
#define CL_SCAN_PE			0x20
#define CL_SCAN_BLOCKBROKEN		0x40
#define CL_SCAN_MAILURL			0x80
#define CL_SCAN_BLOCKMAX		0x100 /* ignored */
#define CL_SCAN_ALGORITHMIC		0x200
#define CL_SCAN_PHISHING_BLOCKSSL	0x800 /* ssl mismatches, not ssl by itself*/
#define CL_SCAN_PHISHING_BLOCKCLOAK	0x1000
#define CL_SCAN_ELF			0x2000
#define CL_SCAN_PDF			0x4000
#define CL_SCAN_STRUCTURED		0x8000
#define CL_SCAN_STRUCTURED_SSN_NORMAL	0x10000
#define CL_SCAN_STRUCTURED_SSN_STRIPPED	0x20000
#define CL_SCAN_PARTIAL_MESSAGE         0x40000
#define CL_SCAN_HEURISTIC_PRECEDENCE    0x80000

/* recommended scan settings */
#define CL_SCAN_STDOPT		(CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_OLE2 | CL_SCAN_PDF | CL_SCAN_HTML | CL_SCAN_PE | CL_SCAN_ALGORITHMIC | CL_SCAN_ELF)

struct cl_engine;
struct cl_settings;

#define CL_INIT_DEFAULT	0x0
extern int cl_init(unsigned int initoptions);

extern struct cl_engine *cl_engine_new(void);

enum cl_engine_field {
    CL_ENGINE_MAX_SCANSIZE,	    /* uint64_t */
    CL_ENGINE_MAX_FILESIZE,	    /* uint64_t */
    CL_ENGINE_MAX_RECURSION,	    /* uint32_t	*/
    CL_ENGINE_MAX_FILES,	    /* uint32_t */
    CL_ENGINE_MIN_CC_COUNT,	    /* uint32_t */
    CL_ENGINE_MIN_SSN_COUNT,	    /* uint32_t */
    CL_ENGINE_PUA_CATEGORIES,	    /* (char *) */
    CL_ENGINE_DB_OPTIONS,	    /* uint32_t */
    CL_ENGINE_DB_VERSION,	    /* uint32_t */
    CL_ENGINE_DB_TIME,		    /* time_t */
    CL_ENGINE_AC_ONLY,		    /* uint32_t */
    CL_ENGINE_AC_MINDEPTH,	    /* uint32_t */
    CL_ENGINE_AC_MAXDEPTH,	    /* uint32_t */
    CL_ENGINE_TMPDIR,		    /* (char *) */
    CL_ENGINE_KEEPTMP		    /* uint32_t */
};

extern int cl_engine_set_num(struct cl_engine *engine, enum cl_engine_field field, long long num);

extern long long cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err);

extern int cl_engine_set_str(struct cl_engine *engine, enum cl_engine_field field, const char *str);

extern const char *cl_engine_get_str(const struct cl_engine *engine, enum cl_engine_field field, int *err);

extern struct cl_settings *cl_engine_settings_copy(const struct cl_engine *engine);

extern int cl_engine_settings_apply(struct cl_engine *engine, const struct cl_settings *settings);

extern int cl_engine_settings_free(struct cl_settings *settings);

extern int cl_engine_compile(struct cl_engine *engine);

extern int cl_engine_addref(struct cl_engine *engine);

extern int cl_engine_free(struct cl_engine *engine);


struct cl_stat {
    char *dir;
    struct stat *stattab;
    char **statdname;
    unsigned int entries;
};

struct cl_cvd {		    /* field no. */
    char *time;		    /* 2 */
    unsigned int version;   /* 3 */
    unsigned int sigs;	    /* 4 */
    unsigned int fl;	    /* 5 */
			    /* padding */
    char *md5;		    /* 6 */
    char *dsig;		    /* 7 */
    char *builder;	    /* 8 */
    unsigned int stime;	    /* 9 */
};

/* file scanning */
extern int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions);

extern int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions);

/* database handling */
extern int cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions);
extern const char *cl_retdbdir(void);

/* engine handling */

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
extern const char *cl_strerror(int clerror);

#ifdef __cplusplus
}
#endif
 
#endif /* __CLAMAV_H */
