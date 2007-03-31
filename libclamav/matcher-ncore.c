/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *	      Written by Tomasz Kojm, dlopen() support by Peter Duthie
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

#ifdef HAVE_NCORE

#include <stdio.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef HAVE_NCORE
#include <dlfcn.h>
#endif

#include "clamav.h"
#include "matcher.h"
#include "cltypes.h"
#include "md5.h"
#include "readdb.h"
#include "str.h"
#include "matcher-ncore.h"

#define HWBUFFSIZE 32768

/* Globals */
static void *g_ncore_dllhandle = 0;
static const char *g_ncore_dllpath = "/usr/lib/libsn_sigscan.so";

/* Function pointer types */
typedef int (*sn_sigscan_initdb_t)(void **);
typedef int (*sn_sigscan_loaddb_t)(void *dbhandle, const char *filename,
        int devicenum, unsigned int *count);
typedef int (*sn_sigscan_load2dbs_t)(void *dbhandle, const char *baseFilename,
        const char *incrFilename, int devicenum, unsigned int *count);
typedef int (*sn_sigscan_closedb_t)(void *dbhandle);
typedef int (*sn_sigscan_createstream_t)(void *dbhandle,
        const uint32_t *dbMaskData, unsigned int dbMaskWords,
        void **streamhandle);
typedef int (*sn_sigscan_writestream_t)(void *streamhandle, const char *buffer,
        unsigned int len);
typedef int (*sn_sigscan_closestream_t)(void *streamhandle,
        void **resulthandle);
typedef int (*sn_sigscan_resultcount_t)(void *resulthandle);
typedef int (*sn_sigscan_resultget_name_t)(void *resulthandle,
        unsigned int index, const char **matchname);
typedef int (*sn_sigscan_resultget_startoffset_t)(void *resulthandle,
        unsigned int index, unsigned long long *startoffset);
typedef int (*sn_sigscan_resultget_endoffset_t)(void *resulthandle,
        unsigned int index, unsigned long long *endoffset);
typedef int (*sn_sigscan_resultget_targettype_t)(void *resulthandle,
        unsigned int index, int *targettype);
typedef int (*sn_sigscan_resultget_offsetstring_t)(void *resulthandle,
        unsigned int index, const char **offsetstring);
typedef int (*sn_sigscan_resultget_extradata_t)(void *resulthandle,
        unsigned int index, const char **optionalsigdata);
typedef int (*sn_sigscan_resultfree_t)(void *resulthandle);
typedef void (*sn_sigscan_error_function_t)(const char *msg);
typedef int (*sn_sigscan_seterrorlogger_t)(sn_sigscan_error_function_t errfn);

/* Function pointer values */
sn_sigscan_initdb_t sn_sigscan_initdb_f = 0;
sn_sigscan_loaddb_t sn_sigscan_loaddb_f = 0;
sn_sigscan_load2dbs_t sn_sigscan_load2dbs_f = 0;
sn_sigscan_closedb_t sn_sigscan_closedb_f = 0;
sn_sigscan_createstream_t sn_sigscan_createstream_f = 0;
sn_sigscan_writestream_t sn_sigscan_writestream_f = 0;
sn_sigscan_closestream_t sn_sigscan_closestream_f = 0;
sn_sigscan_resultcount_t sn_sigscan_resultcount_f = 0;
sn_sigscan_resultget_name_t sn_sigscan_resultget_name_f = 0;
sn_sigscan_resultget_startoffset_t sn_sigscan_resultget_startoffset_f = 0;
sn_sigscan_resultget_endoffset_t sn_sigscan_resultget_endoffset_f = 0;
sn_sigscan_resultget_targettype_t sn_sigscan_resultget_targettype_f = 0;
sn_sigscan_resultget_offsetstring_t sn_sigscan_resultget_offsetstring_f = 0;
sn_sigscan_resultget_extradata_t sn_sigscan_resultget_extradata_f = 0;
sn_sigscan_resultfree_t sn_sigscan_resultfree_f = 0;
sn_sigscan_seterrorlogger_t sn_sigscan_seterrorlogger_f = 0;

static int cli_ncore_dlinit()
{
    if(access(g_ncore_dllpath, R_OK) == -1) {
	cli_dbgmsg("cli_ncore_dlinit: Can't access %s\n", g_ncore_dllpath);
	return CL_ENCINIT;
    }

    g_ncore_dllhandle = dlopen(g_ncore_dllpath, RTLD_NOW | RTLD_LOCAL);
    if(!g_ncore_dllhandle) {
	cli_dbgmsg("cli_ncore_dlinit: dlopen() failed for %s\n", g_ncore_dllpath);
	return CL_ENCINIT;
    }

    /* get the symbols */
    sn_sigscan_initdb_f = (sn_sigscan_initdb_t)dlsym(g_ncore_dllhandle, "sn_sigscan_initdb");
    sn_sigscan_loaddb_f = (sn_sigscan_loaddb_t)dlsym(g_ncore_dllhandle, "sn_sigscan_loaddb");
    sn_sigscan_load2dbs_f = (sn_sigscan_load2dbs_t)dlsym(g_ncore_dllhandle, "sn_sigscan_load2dbs");
    sn_sigscan_closedb_f = (sn_sigscan_closedb_t)dlsym(g_ncore_dllhandle, "sn_sigscan_closedb");
    sn_sigscan_createstream_f = (sn_sigscan_createstream_t)dlsym(g_ncore_dllhandle, "sn_sigscan_createstream");
    sn_sigscan_writestream_f = (sn_sigscan_writestream_t)dlsym(g_ncore_dllhandle, "sn_sigscan_writestream");
    sn_sigscan_closestream_f = (sn_sigscan_closestream_t)dlsym(g_ncore_dllhandle, "sn_sigscan_closestream");
    sn_sigscan_resultcount_f = (sn_sigscan_resultcount_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultcount");
    sn_sigscan_resultget_name_f = (sn_sigscan_resultget_name_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultget_name");
    sn_sigscan_resultget_startoffset_f = (sn_sigscan_resultget_startoffset_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultget_startoffset");
    sn_sigscan_resultget_endoffset_f = (sn_sigscan_resultget_endoffset_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultget_endoffset");
    sn_sigscan_resultget_targettype_f = (sn_sigscan_resultget_targettype_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultget_targettype");
    sn_sigscan_resultget_offsetstring_f = (sn_sigscan_resultget_offsetstring_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultget_offsetstring");
    sn_sigscan_resultget_extradata_f = (sn_sigscan_resultget_extradata_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultget_extradata");
    sn_sigscan_resultfree_f = (sn_sigscan_resultfree_t)dlsym(g_ncore_dllhandle, "sn_sigscan_resultfree");
    sn_sigscan_seterrorlogger_f = (sn_sigscan_seterrorlogger_t)dlsym(g_ncore_dllhandle, "sn_sigscan_seterrorlogger");

    /* Check that we got all the symbols */
    if(sn_sigscan_initdb_f && sn_sigscan_loaddb_f && sn_sigscan_load2dbs_f &&
            sn_sigscan_closedb_f && sn_sigscan_createstream_f &&
            sn_sigscan_writestream_f && sn_sigscan_closestream_f &&
            sn_sigscan_resultcount_f && sn_sigscan_resultget_name_f &&
            sn_sigscan_resultget_startoffset_f &&
            sn_sigscan_resultget_endoffset_f &&
            sn_sigscan_resultget_targettype_f &&
            sn_sigscan_resultget_offsetstring_f &&
            sn_sigscan_resultget_extradata_f && sn_sigscan_resultfree_f &&
            sn_sigscan_seterrorlogger_f)
    {
        return CL_SUCCESS;
    }

    dlclose(g_ncore_dllhandle);
    g_ncore_dllhandle = 0;
    return CL_ENCINIT;
}

int cli_ncore_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_engine *engine, unsigned short ftype, unsigned int *targettab)
{
	void *streamhandle;
	void *resulthandle;
	static const uint32_t datamask[2] = { 0xffffffff, 0xffffffff };
	int count, hret, i;
	char *pt;
	int ret = CL_CLEAN;


    /* TODO: Setup proper data bitmask (need specs) */
    /* Create the hardware scanning stream */
    hret = (*sn_sigscan_createstream_f)(engine->ncdb, datamask, 2, &streamhandle);
    if(hret) {
        cli_errmsg("cli_ncore_scanbuff: can't create new hardware stream: %d\n", hret);
        return CL_ENCIO;
    }

    /* Write data to the hardware scanning stream */
    hret = (*sn_sigscan_writestream_f)(streamhandle, buffer, length);
    if(hret) {
        cli_errmsg("cli_ncore_scanbuff: can't write %u bytes to hardware stream: %d\n", length, hret);
        (*sn_sigscan_closestream_f)(streamhandle, &resulthandle);
        (*sn_sigscan_resultfree_f)(resulthandle);
        return CL_ENCIO;
    }

    /* Close the hardware scanning stream and collect the result */
    hret = (*sn_sigscan_closestream_f)(streamhandle, &resulthandle);
    if(hret) {
        cli_errmsg("cli_ncore_scanbuff: can't close hardware stream: %d\n", hret);
        return CL_ENCIO;
    }

    /* Iterate through the results */
    count = (*sn_sigscan_resultcount_f)(resulthandle);
    for(i = 0; i < count; i++) {
        const char *matchname = NULL, *offsetstring = NULL, *optionalsigdata = NULL;
        unsigned int targettype = 0;

        /* Acquire the name of the result */
        hret = (*sn_sigscan_resultget_name_f)(resulthandle, i, &matchname);
        if(hret) {
            cli_errmsg("cli_ncore_scanbuff: sn_sigscan_resultget_name failed for result %u: %d\n", i, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
            return CL_ENCIO;
        }
        if(!matchname) {
            cli_errmsg("cli_ncore_scanbuff: HW Result[%u]: Signature without name\n", i);
            (*sn_sigscan_resultfree_f)(resulthandle);
            return CL_EMALFDB;
        }

        /* Acquire the result file type and check that it is correct */
        hret = (*sn_sigscan_resultget_targettype_f)(resulthandle, i, &targettype);
        if(hret) {
            cli_errmsg("cli_ncore_scanbuff: sn_sigscan_resultget_targettype failed for result %u, signature %s: %d\n", i, matchname, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
            return CL_ENCIO;
        }

        if(targettype && targettab[targettype] != ftype) {
            cli_dbgmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Target type: %u, expected: %u\n", i, matchname, targettab[targettype], ftype);
            continue;
        }

        hret = (*sn_sigscan_resultget_offsetstring_f)(resulthandle, i, &offsetstring);
        if(hret) {
            cli_errmsg("cli_ncore_scanbuff: sn_sigscan_resultget_offsetstring failed for result %u, signature %s: %d\n", i, matchname, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
            return CL_ENCIO;
        }
        if(offsetstring) {
            cli_dbgmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Offset based signature not supported in buffer mode\n", i, matchname);
            continue;
        }

        hret = (*sn_sigscan_resultget_extradata_f)(resulthandle, i, &optionalsigdata);
        if(hret) {
            cli_errmsg("cli_ncore_scanbuff: sn_sigscan_resultget_extradata failed for result %u, signature %s: %d\n", i, matchname, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
            return CL_ENCIO;
        }
        if(optionalsigdata && strlen(optionalsigdata)) {
            pt = cli_strtok(optionalsigdata, 1, ":");
            if(pt) {
                if(!isdigit(*pt)) {
                    free(pt);
                    cli_errmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
                    (*sn_sigscan_resultfree_f)(resulthandle);
                    return CL_EMALFDB;
                }

                if((unsigned int) atoi(pt) < cl_retflevel()) {
                    cli_dbgmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Signature max flevel: %d, current: %d\n", i, matchname, atoi(pt), cl_retflevel());
                    free(pt);
                    continue;
                }

                free(pt);
                pt = cli_strtok(optionalsigdata, 0, ":");
                if(pt) {
                    if(!isdigit(*pt)) {
                        free(pt);
                        cli_errmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
                        (*sn_sigscan_resultfree_f)(resulthandle);
                        return CL_EMALFDB;
                    }

                    if((unsigned int) atoi(pt) > cl_retflevel()) {
                        cli_dbgmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Signature required flevel: %u, current: %u\n", i, matchname, atoi(pt), cl_retflevel());
                        free(pt);
                        continue;
                    }
                    free(pt);
                }

            } else {
                if(!isdigit(*optionalsigdata)) {
                    cli_errmsg("cli_ncore_scanbuff: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
                    (*sn_sigscan_resultfree_f)(resulthandle);
                    return CL_EMALFDB;
                }

                if((unsigned int) atoi(optionalsigdata) > cl_retflevel()) {
                    cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Signature required flevel: %u, current: %u\n", i, matchname, atoi(optionalsigdata), cl_retflevel());
                    continue;
                }
            }
        }

        /* Store the name of the match */
        *virname = matchname;
        ret = CL_VIRUS;
        break;
    }

    /* Clean up the result structure */
    hret = (*sn_sigscan_resultfree_f)(resulthandle);
    if(hret) {
        cli_errmsg("cli_ncore_scanbuff: can't free results: %d\n", ret);
        return CL_ENCIO;
    }

    return ret;
}

int cli_ncore_scandesc(int desc, cli_ctx *ctx, unsigned short ftype, int *cont, unsigned int *targettab, cli_md5_ctx *md5ctx)
{
	void *streamhandle;
	void *resulthandle;
	uint32_t datamask[2] = { 0xffffffff, 0xffffffff };
	struct cli_target_info info;
	int i, count, hret, bytes, ret = CL_CLEAN;
	off_t origoff;
	*cont = 0;
	char *buffer;


    /* TODO: Setup proper data bitmask (need specs) */
    /* Create the hardware scanning stream */
    hret = (*sn_sigscan_createstream_f)(ctx->engine->ncdb, datamask, 2, &streamhandle);
    if(hret) {
        cli_errmsg("cli_ncore_scandesc: can't create new hardware stream: %d\n", hret);
        return CL_ENCIO;
    }

    /* Obtain the initial offset */
    origoff = lseek(desc, 0, SEEK_CUR);
    if(origoff == -1) {
        cli_errmsg("cli_ncore_scandesc: lseek() failed for descriptor %d\n", desc);
	(*sn_sigscan_closestream_f)(streamhandle, &resulthandle);
        (*sn_sigscan_resultfree_f)(resulthandle);
        return CL_EIO;
    }

    buffer = (char *) cli_calloc(HWBUFFSIZE, sizeof(char));
    if(!buffer) {
        cli_dbgmsg("cli_ncore_scandesc: unable to cli_calloc(%u)\n", HWBUFFSIZE);
	(*sn_sigscan_closestream_f)(streamhandle, &resulthandle);
        (*sn_sigscan_resultfree_f)(resulthandle);
        return CL_EMEM;
    }

    /* Initialize the MD5 hasher */
    if(ctx->engine->md5_hlist)
        MD5_Init(md5ctx);

    /* Read and scan the data */
    while ((bytes = cli_readn(desc, buffer, HWBUFFSIZE)) > 0) {
        hret = (*sn_sigscan_writestream_f)(streamhandle, buffer, bytes);
        if(hret) {
            cli_errmsg("cli_ncore_scandesc: can't write to hardware stream: %d\n", hret);
            ret = CL_ENCIO;
            break;
        } else {
            if(ctx->scanned)
                *ctx->scanned += bytes / CL_COUNT_PRECISION;
 
    	    if(ctx->engine->md5_hlist)
                MD5_Update(md5ctx, buffer, bytes);
        }
    }

    free(buffer);

    /* Close the stream and get the result */
    hret = (*sn_sigscan_closestream_f)(streamhandle, &resulthandle);
    if(hret) {
        cli_errmsg("cli_ncore_scandesc: can't close hardware stream: %d\n", hret);
        return CL_ENCIO;
    }

    memset(&info, 0, sizeof(info));

    /* Iterate over the list of results */
    count = (*sn_sigscan_resultcount_f)(resulthandle);
    for(i = 0; i < count; i++) {
    	const char *matchname = NULL, *offsetstring = NULL, *optionalsigdata = NULL;
    	unsigned long long startoffset = 0;
    	unsigned int targettype = 0, maxshift = 0;
        char *pt;

        /* Get the description of the match */
        hret = (*sn_sigscan_resultget_name_f)(resulthandle, i, &matchname);
        if(hret) {
            cli_errmsg("cli_ncore_scandesc: sn_sigscan_resultget_name failed for result %u: %d\n", i, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
            return CL_ENCIO;
        }

        if(!matchname) {
            cli_errmsg("cli_ncore_scandesc: HW Result[%u]: Signature without name\n", i);
            (*sn_sigscan_resultfree_f)(resulthandle);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
            return CL_EMALFDB;
        }

        hret = (*sn_sigscan_resultget_targettype_f)(resulthandle, i, &targettype);
        if(hret) {
    	    cli_errmsg("cli_ncore_scandesc: sn_sigscan_resultget_targettype failed for result %d, signature %s: %d\n", i, matchname, hret);
    	    (*sn_sigscan_resultfree_f)(resulthandle);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
    	    return CL_ENCIO;
        }
        if(targettype && targettab[targettype] != ftype) {
    	    cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Target type: %u, expected: %d\n", i, matchname, targettab[targettype], ftype);
            continue;
        }

        hret = (*sn_sigscan_resultget_offsetstring_f)(resulthandle, i, &offsetstring);
        if(hret) {
            cli_errmsg("cli_ncore_scandesc: sn_sigscan_resultget_offsetstring failed for result %u, signature %s: %d\n", i, matchname, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
            return CL_ENCIO;
        }

        hret = (*sn_sigscan_resultget_startoffset_f)(resulthandle, i, &startoffset);
        if(hret) {
    	    cli_errmsg("cli_ncore_scandesc: sn_sigscan_resultget_startoffset failed for result %u, signature %s: %d\n", i, matchname, hret);
    	    (*sn_sigscan_resultfree_f)(resulthandle);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
    	    return CL_ENCIO;
        }
        if(offsetstring && strcmp(offsetstring, "*")) {
	    off_t off = cli_caloff(offsetstring, &info, desc, ftype, &hret, &maxshift);

    	    if(hret == -1) {
                cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Bad offset in signature\n", i, matchname);
                (*sn_sigscan_resultfree_f)(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
                return CL_EMALFDB;
            }
	    if(maxshift) {
		if((startoffset < (unsigned long long) off) || (startoffset > (unsigned long long) off + maxshift)) {
		    cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Virus offset: %Lu, expected: [%Lu..%Lu]\n", i, matchname, startoffset, off, off + maxshift);
		    continue;
		}
	    } else if(startoffset != (unsigned long long) off) {
                cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Virus offset: %Lu, expected: %Lu\n", i, matchname, startoffset, off);
                continue;
            }
        }

        hret = (*sn_sigscan_resultget_extradata_f)(resulthandle, i, &optionalsigdata);
        if(hret) {
            cli_errmsg("cli_ncore_scandesc: sn_sigscan_resultget_extradata failed for result %d, signature %s: %d\n", i, matchname, hret);
            (*sn_sigscan_resultfree_f)(resulthandle);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
            return CL_ENCIO;
        }

        if(optionalsigdata && strlen(optionalsigdata)) {
    	    pt = cli_strtok(optionalsigdata, 1, ":");
    	    if(pt) {
    	        if(!isdigit(*pt)) {
    		    free(pt);
                    cli_errmsg("cli_ncore_scandesc: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
		    (*sn_sigscan_resultfree_f)(resulthandle);
		    if(info.exeinfo.section)
			free(info.exeinfo.section);
                    return CL_EMALFDB;
                }

                if((unsigned int) atoi(pt) < cl_retflevel()) {
                    cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Signature max flevel: %d, current: %d\n", i, matchname, atoi(pt), cl_retflevel());
                    free(pt);
                    continue;
                }

                free(pt);

    	        pt = cli_strtok(optionalsigdata, 0, ":");
    	        if(pt) {
                    if(!isdigit(*pt)) {
                        free(pt);
                        cli_errmsg("cli_ncore_scandesc: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			(*sn_sigscan_resultfree_f)(resulthandle);
			if(info.exeinfo.section)
			    free(info.exeinfo.section);
                        return CL_EMALFDB;
                    }

                    if((unsigned int) atoi(pt) > cl_retflevel()) {
                        cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Signature required flevel: %d, current: %d\n", i, matchname, atoi(pt), cl_retflevel());
                        free(pt);
                        continue;
                    }
                    free(pt);
                }
            } else {
                if(!isdigit(*optionalsigdata)) {
                    cli_errmsg("cli_ncore_scandesc: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
                    (*sn_sigscan_resultfree_f)(resulthandle);
		    if(info.exeinfo.section)
			free(info.exeinfo.section);
                    return CL_EMALFDB;
                }

                if((unsigned int) atoi(optionalsigdata) > cl_retflevel()) {
                    cli_dbgmsg("cli_ncore_scandesc: HW Result[%u]: %s: Signature required flevel: %d, current: %d\n", i, matchname, atoi(optionalsigdata), cl_retflevel());
                    continue;
                }
            }
        }

        *ctx->virname = matchname;
        ret = CL_VIRUS;
        break;
    }

    if(info.exeinfo.section)
	free(info.exeinfo.section);

    hret = (*sn_sigscan_resultfree_f)(resulthandle);
    if(hret) {
        cli_errmsg("cli_ncore_scandesc: can't free results: %d\n", ret);
        return CL_ENCIO;
    }

    if(ctx->engine->md5_hlist) {
        unsigned char digest[16];
        struct cli_md5_node *md5_node;
        MD5_Final(digest, md5ctx);

        md5_node = cli_vermd5(digest, ctx->engine);
        if(md5_node) {
            struct stat sb;
            if(fstat(desc, &sb) == -1)
                return CL_EIO;

    	    if((unsigned int) sb.st_size != md5_node->size) {
                cli_warnmsg("Detected false positive MD5 match. Please report.\n");
            } else {
                if(md5_node->fp) {
                    cli_dbgmsg("Eliminated false positive match (fp sig: %s)\n", md5_node->virname);
                    ret = CL_CLEAN;
                } else {
                    if(ctx->virname)
                        *ctx->virname = md5_node->virname;

                    ret = CL_VIRUS;
                }
            }
        }
    }

    if(ret == CL_VIRUS || (ftype != CL_TYPE_UNKNOWN_TEXT && ftype != CL_TYPE_UNKNOWN_DATA))
        return ret;

    if(lseek(desc, origoff, SEEK_SET) == -1) {
        cli_errmsg("cli_ncore_scandesc: lseek() failed for descriptor %d\n", desc);
        return CL_EIO;
    }

    *cont = 1;
    return ret;
}

int cli_ncore_load(const char *filename, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	int ret = 0;
	unsigned int newsigs = 0;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if((ret = cli_ncore_dlinit())) {
	cl_free(*engine);
	return ret;
    }

    ret = (*sn_sigscan_initdb_f)(&(*engine)->ncdb);
    if(ret) {
        cli_errmsg("cli_ncore_load: error initializing the matcher: %d\n", ret);
        cl_free(*engine);
        return CL_ENCINIT;
    }

    (*engine)->ncore = 1;

    ret = (*sn_sigscan_loaddb_f)((*engine)->ncdb, filename, 0, &newsigs);
    if(ret) {
        cli_errmsg("cli_ncore_load: can't load hardware database: %d\n", ret);
        cl_free(*engine);
        return CL_ENCLOAD;
    }

    *signo += newsigs;
    return CL_SUCCESS;
}

void cli_ncore_unload(struct cl_engine *engine)
{
	int ret;

    ret = (*sn_sigscan_closedb_f)(engine->ncdb);
    if(ret)
        cli_errmsg("cl_free: can't close hardware database: %d\n", ret);
}
#endif
