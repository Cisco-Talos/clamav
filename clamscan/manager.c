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
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef C_WINDOWS
#include <sys/utime.h>
#else
#include <sys/wait.h>
#include <utime.h>
#endif
#ifndef C_WINDOWS
#include <dirent.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#include "manager.h"
#include "others.h"
#include "global.h"

#include "shared/optparser.h"
#include "shared/actions.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "libclamav/matcher-ac.h"
#include "libclamav/str.h"
#include "libclamav/readdb.h"
#include "libclamav/cltypes.h"

#ifdef C_LINUX
dev_t procdev;
#endif

#ifdef C_WINDOWS
#undef P_tmpdir
#define P_tmpdir    "C:\\WINDOWS\\TEMP"
#endif

#ifndef	O_BINARY
#define	O_BINARY    0
#endif

static int scanfile(const char *filename, struct cl_engine *engine, const struct optstruct *opts, unsigned int options)
{
  int ret = 0, fd, included, printclean = 1, fsize;
	const struct optstruct *opt;
	const char *virname;
#ifdef C_LINUX
	struct stat sb;

    /* argh, don't scan /proc files */
    if(procdev)
	if(stat(filename, &sb) != -1)
	    if(sb.st_dev == procdev) {
		if(!printinfected)
		    logg("~%s: Excluded (/proc)\n", filename);
		return 0;
	    }
#endif    

    if((opt = optget(opts, "exclude"))->enabled) {
	while(opt) {
	    if(match_regex(filename, opt->strarg) == 1) {
		if(!printinfected)
		    logg("~%s: Excluded\n", filename);
		return 0;
	    }
	    opt = opt->nextarg;
	}
    }

    if((opt = optget(opts, "include"))->enabled) {
	included = 0;
	while(opt) {
	    if(match_regex(filename, opt->strarg) == 1) {
		included = 1;
		break;
	    }
	    opt = opt->nextarg;
	}
	if(!included) {
	    if(!printinfected)
		logg("~%s: Excluded\n", filename);
	    return 0;
	}
    }

    fsize = fileinfo(filename, 1);
    if(fsize == 0) {
	if(!printinfected)
	    logg("~%s: Empty file\n", filename);
	return 0;
    }
    info.rblocks += fsize / CL_COUNT_PRECISION;
#ifndef C_WINDOWS
    if(geteuid())
	if(checkaccess(filename, NULL, R_OK) != 1) {
	    if(!printinfected)
		logg("~%s: Access denied\n", filename);
	    return 0;
	}
#endif

    logg("*Scanning %s\n", filename);

    if((fd = open(filename, O_RDONLY|O_BINARY)) == -1) {
	logg("^Can't open file %s\n", filename);
	return 54;
    }

    info.files++;

    if((ret = cl_scandesc(fd, &virname, &info.blocks, engine, options)) == CL_VIRUS) {
	logg("~%s: %s FOUND\n", filename, virname);
	info.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected && printclean)
	    mprintf("~%s: OK\n", filename);
    } else
	if(!printinfected)
	    logg("~%s: %s ERROR\n", filename, cl_strerror(ret));

    close(fd);

    if(ret == CL_VIRUS && action)
	action(filename);

    return ret;
}

static int scandirs(const char *dirname, struct cl_engine *engine, const struct optstruct *opts, unsigned int options, unsigned int depth)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;
	int scanret = 0, included;
	const struct optstruct *opt;


    if((opt = optget(opts, "exclude-dir"))->enabled) {
	while(opt) {
	    if(match_regex(dirname, opt->strarg) == 1) {
		if(!printinfected)
		    logg("~%s: Excluded\n", dirname);
		return 0;
	    }
	    opt = opt->nextarg;
	}
    }

    if((opt = optget(opts, "include-dir"))->enabled) {
	included = 0;
	while(opt) {
	    if(match_regex(dirname, opt->strarg) == 1) {
		included = 1;
		break;
	    }
	    opt = opt->nextarg;
	}
	if(!included) {
	    if(!printinfected)
		logg("~%s: Excluded\n", dirname);
	    return 0;
	}
    }

    if(depth > (unsigned int) optget(opts, "max-dir-recursion")->numarg)
	return 0;

    info.dirs++;
    depth++;

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
#if !defined(C_INTERIX) && !defined(C_WINDOWS)
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if(!strcmp(dirname, "/"))
			sprintf(fname, "/%s", dent->d_name);
		    else
			sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode) && recursion) {
			    if(scandirs(fname, engine, opts, options, depth) == 1)
				scanret++;
			} else {
			    if(S_ISREG(statbuf.st_mode))
				scanret += scanfile(fname, engine, opts, options);
			}
		    }
		    free(fname);
		}
	    }
	}
    } else {
	if(!printinfected)
	    logg("~%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);

    if(scanret)
	return 1;
    else
	return 0;

}

static int scanstdin(const struct cl_engine *engine, const struct optstruct *opts, int options)
{
	int ret;
	unsigned int fsize = 0;
	const char *virname, *tmpdir;
	char *file, buff[FILEBUFF];
	size_t bread;
	FILE *fs;

    if(optget(opts, "tempdir")->enabled) {
	tmpdir = optget(opts, "tempdir")->strarg;
    } else {
	/* check write access */
	tmpdir = getenv("TMPDIR");

	if(tmpdir == NULL)
#ifdef P_tmpdir
	    tmpdir = P_tmpdir;
#else
	    tmpdir = "/tmp";
#endif
    }

    if(checkaccess(tmpdir, CLAMAVUSER, W_OK) != 1) {
	logg("!Can't write to temporary directory\n");
	return 64;
    }

    file = cli_gentemp(tmpdir);

    if(!(fs = fopen(file, "wb"))) {
	logg("!Can't open %s for writing\n", file);
	free(file);
	return 63;
    }

    while((bread = fread(buff, 1, FILEBUFF, stdin))) {
	fsize += bread;
	if(fwrite(buff, 1, bread, fs) < bread) {
	    logg("!Can't write to %s\n", file);
	    free(file);
	    return 58;
	}
    }
    fclose(fs);

    logg("*Checking %s\n", file);
    info.files++;
    info.rblocks += fsize / CL_COUNT_PRECISION;

    if((ret = cl_scanfile(file, &virname, &info.blocks, engine, options)) == CL_VIRUS) {
	logg("stdin: %s FOUND\n", virname);
	info.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected)
	    mprintf("stdin: OK\n");
    } else
	if(!printinfected)
	    logg("stdin: %s ERROR\n", cl_strerror(ret));

    unlink(file);
    free(file);
    return ret;
}

int scanmanager(const struct optstruct *opts)
{
	mode_t fmode;
	int ret = 0, fmodeint, i;
	unsigned int options = 0, dboptions = 0;
	struct cl_engine *engine;
	struct stat sb;
	char *file, cwd[1024], *pua_cats = NULL;
	const char *filename;
	const struct optstruct *opt;
#ifndef C_WINDOWS
	struct rlimit rlim;
#endif

    if(optget(opts, "phishing-sigs")->enabled)
	dboptions |= CL_DB_PHISHING;

    if(optget(opts,"phishing-scan-urls")->enabled)
	dboptions |= CL_DB_PHISHING_URLS;

    if((ret = cl_init(CL_INIT_DEFAULT))) {
	logg("!Can't initialize libclamav: %s\n", cl_strerror(ret));
	return 50;
    }

    if(!(engine = cl_engine_new())) {
	logg("!Can't initialize antivirus engine\n");
	return 50;
    }

    if(optget(opts, "detect-pua")->enabled) {
	dboptions |= CL_DB_PUA;
	if((opt = optget(opts, "exclude-pua"))->enabled) {
	    dboptions |= CL_DB_PUA_EXCLUDE;
	    i = 0;
	    while(opt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    cl_engine_free(engine);
		    return 70;
		}
		sprintf(pua_cats + i, ".%s", opt->strarg);
		i += strlen(opt->strarg) + 1;
		pua_cats[i] = 0;
		opt = opt->nextarg;
	    }
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if((opt = optget(opts, "include-pua"))->enabled) {
	    if(pua_cats) {
		logg("!--exclude-pua and --include-pua cannot be used at the same time\n");
		cl_engine_free(engine);
		free(pua_cats);
		return 40;
	    }
	    dboptions |= CL_DB_PUA_INCLUDE;
	    i = 0;
	    while(opt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    return 70;
		}
		sprintf(pua_cats + i, ".%s", opt->strarg);
		i += strlen(opt->strarg) + 1;
		pua_cats[i] = 0;
		opt = opt->nextarg;
	    }
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if(pua_cats) {
	    if((ret = cl_engine_set_str(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))) {
		logg("!cli_engine_set_str(CL_ENGINE_PUA_CATEGORIES) failed: %s\n", cl_strerror(ret));
		free(pua_cats);
		cl_engine_free(engine);
		return 50;
	    }
	    free(pua_cats);
	}
    }

    if(optget(opts, "dev-ac-only")->enabled)
	cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);

    if(optget(opts, "dev-ac-depth")->enabled)
	cl_engine_set_num(engine, CL_ENGINE_AC_MAXDEPTH, optget(opts, "dev-ac-depth")->numarg);

    if(optget(opts, "leave-temps")->enabled)
	cl_engine_set_num(engine, CL_ENGINE_KEEPTMP, 1);

    if((opt = optget(opts, "tempdir"))->enabled) {
	if((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, opt->strarg))) {
	    logg("!cli_engine_set_str(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 50;
	}
    }

    if((opt = optget(opts, "database"))->active) {
	if((ret = cl_load(opt->strarg, engine, &info.sigs, dboptions))) {
	    logg("!%s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 50;
	}

    } else {
	    char *dbdir = freshdbdir();

	if((ret = cl_load(dbdir, engine, &info.sigs, dboptions))) {
	    logg("!%s\n", cl_strerror(ret));
	    free(dbdir);
	    cl_engine_free(engine);
	    return 50;
	}
	free(dbdir);
    }

    if((ret = cl_engine_compile(engine)) != 0) {
	logg("!Database initialization error: %s\n", cl_strerror(ret));;
	cl_engine_free(engine);
	return 50;
    }

    /* set limits */

    if((opt = optget(opts, "max-scansize"))->enabled) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_SCANSIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 50;
	}
    }

    if((opt = optget(opts, "max-filesize"))->enabled) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 50;
	}
    }

#ifndef C_WINDOWS
    if(getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
	if(rlim.rlim_cur < (rlim_t) cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL))
	    logg("^System limit for file size is lower than engine->maxfilesize\n");
	if(rlim.rlim_cur < (rlim_t) cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL))
	    logg("^System limit for file size is lower than engine->maxscansize\n");
    } else {
	logg("^Cannot obtain resource limits for file size\n");
    }
#endif

    if((opt = optget(opts, "max-files"))->enabled) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_FILES) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 50;
	}
    }

    if((opt = optget(opts, "max-recursion"))->enabled) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_RECURSION) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 50;
	}
    }

    /* set scan options */
    if(optget(opts,"phishing-ssl")->enabled)
	options |= CL_SCAN_PHISHING_BLOCKSSL;

    if(optget(opts,"phishing-cloak")->enabled)
	options |= CL_SCAN_PHISHING_BLOCKCLOAK;

    if(optget(opts,"heuristic-scan-precedence")->enabled)
	options |= CL_SCAN_HEURISTIC_PRECEDENCE;

    if(optget(opts, "scan-archive")->enabled)
	options |= CL_SCAN_ARCHIVE;

    if(optget(opts, "detect-broken")->enabled)
	options |= CL_SCAN_BLOCKBROKEN;

    if(optget(opts, "block-encrypted")->enabled)
	options |= CL_SCAN_BLOCKENCRYPTED;

    if(optget(opts, "scan-pe")->enabled)
	options |= CL_SCAN_PE;

    if(optget(opts, "scan-elf")->enabled)
	options |= CL_SCAN_ELF;

    if(optget(opts, "scan-ole2")->enabled)
	options |= CL_SCAN_OLE2;

    if(optget(opts, "scan-pdf")->enabled)
	options |= CL_SCAN_PDF;

    if(optget(opts, "scan-html")->enabled)
	options |= CL_SCAN_HTML;

    if(optget(opts, "scan-mail")->enabled) {
	options |= CL_SCAN_MAIL;

	if(optget(opts, "mail-follow-urls")->enabled)
	    options |= CL_SCAN_MAILURL;
    }

    if(optget(opts, "algorithmic-detection")->enabled)
	options |= CL_SCAN_ALGORITHMIC;

    if(optget(opts, "detect-structured")->enabled) {
	options |= CL_SCAN_STRUCTURED;

	if((opt = optget(opts, "structured-ssn-format"))->enabled) {
	    switch(opt->numarg) {
		case 0:
		    options |= CL_SCAN_STRUCTURED_SSN_NORMAL;
		    break;
		case 1:
		    options |= CL_SCAN_STRUCTURED_SSN_STRIPPED;
		    break;
		case 2:
		    options |= (CL_SCAN_STRUCTURED_SSN_NORMAL | CL_SCAN_STRUCTURED_SSN_STRIPPED);
		    break;
		default:
		    logg("!Invalid argument for --structured-ssn-format\n");
		    return 40;
	    }
	} else {
	    options |= CL_SCAN_STRUCTURED_SSN_NORMAL;
	}

	if((opt = optget(opts, "structured-ssn-count"))->enabled) {
	    if((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_SSN_COUNT, opt->numarg))) {
		logg("!cli_engine_set_num(CL_ENGINE_MIN_SSN_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 50;
	    }
	}

	if((opt = optget(opts, "structured-cc-count"))->enabled) {
	    if((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_CC_COUNT, opt->numarg))) {
		logg("!cli_engine_set_num(CL_ENGINE_MIN_CC_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 50;
	    }
	}

    } else {
	options &= ~CL_SCAN_STRUCTURED;
    }

#ifdef C_LINUX
    procdev = (dev_t) 0;
    if(stat("/proc", &sb) != -1 && !sb.st_size)
	procdev = sb.st_dev;
#endif

    /* check filetype */
    if(!opts->filename && !optget(opts, "file-list")->enabled) {
	/* we need full path for some reasons (eg. archive handling) */
	if(!getcwd(cwd, sizeof(cwd))) {
	    logg("!Can't get absolute pathname of current working directory\n");
	    ret = 57;
	} else
	    ret = scandirs(cwd, engine, opts, options, 1);

    } else if(opts->filename && !optget(opts, "file-list")->enabled && !strcmp(opts->filename[0], "-")) { /* read data from stdin */
	ret = scanstdin(engine, opts, options);

    } else {
	if(opts->filename && optget(opts, "file-list")->enabled)
	    logg("^Only scanning files from --file-list (files passed at cmdline are ignored)\n");

	while((filename = filelist(opts, &ret)) && (file = strdup(filename))) {
	    if((fmodeint = fileinfo(file, 2)) == -1) {
		logg("^Can't access file %s\n", file);
		perror(file);
		ret = 56;
	    } else {
		for(i = strlen(file) - 1; i > 0; i--) {
		    if(file[i] == '/')
			file[i] = 0;
		    else
			break;
		}

		fmode = (mode_t) fmodeint;

		switch(fmode & S_IFMT) {
		    case S_IFREG:
			ret = scanfile(file, engine, opts, options);
			break;

		    case S_IFDIR:
			ret = scandirs(file, engine, opts, options, 1);
			break;

		    default:
			logg("!Not supported file type (%s)\n", file);
			ret = 52;
		}
	    }
	    free(file);
	}
    }

    /* free the engine */
    cl_engine_free(engine);

    /* overwrite return code */
    if(info.ifiles)
	ret = 1;
    else if(ret < 50) /* hopefully no error detected */ 
	ret = 0; /* just make sure it's 0 */

    return ret;
}

