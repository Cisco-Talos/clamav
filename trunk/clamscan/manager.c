/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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
 *  Wed Mar  5 03:45:31 CET 2003: included --move code from Damien Curtain
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

#include "shared/options.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "libclamav/matcher-ac.h"
#include "libclamav/str.h"
#include "libclamav/readdb.h"

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

static void move_infected(const char *filename, const struct optstruct *opt);

static int scanfile(const char *filename, struct cl_engine *engine, const struct optstruct *opt, const struct cl_limits *limits, unsigned int options)
{
	int ret = 0, fd, included, printclean = 1;
	const struct optnode *optnode;
	char *argument;
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

    if(opt_check(opt, "exclude")) {
	argument = opt_firstarg(opt, "exclude", &optnode);
	while(argument) {
	    if(match_regex(filename, argument) == 1) {
		if(!printinfected)
		    logg("~%s: Excluded\n", filename);
		return 0;
	    }
	    argument = opt_nextarg(&optnode, "exclude");
	}
    }

   if(opt_check(opt, "include")) {
	included = 0;
	argument = opt_firstarg(opt, "include", &optnode);
	while(argument && !included) {
	    if(match_regex(filename, argument) == 1) {
		included = 1;
		break;
	    }
	    argument = opt_nextarg(&optnode, "include");
	}

	if(!included) {
	    if(!printinfected)
		logg("~%s: Excluded\n", filename);
	    return 0;
	}
    }

    if(fileinfo(filename, 1) == 0) {
	if(!printinfected)
	    logg("~%s: Empty file\n", filename);
	return 0;
    }

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

    if((ret = cl_scandesc(fd, &virname, &info.blocks, engine, limits, options)) == CL_VIRUS) {
	logg("~%s: %s FOUND\n", filename, virname);
	info.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected && printclean)
	    mprintf("~%s: OK\n", filename);
    } else
	if(!printinfected)
	    logg("~%s: %s\n", filename, cl_strerror(ret));

    close(fd);

    if(ret == CL_VIRUS) {
	if(opt_check(opt, "remove")) {
	    if(unlink(filename)) {
		logg("^%s: Can't remove\n", filename);
		info.notremoved++;
	    } else {
		logg("~%s: Removed\n", filename);
	    }
	} else if(opt_check(opt, "move") || opt_check(opt, "copy"))
            move_infected(filename, opt);
    }

    return ret;
}

static int scandirs(const char *dirname, struct cl_engine *engine, const struct optstruct *opt, const struct cl_limits *limits, unsigned int options, unsigned int depth)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;
	int scanret = 0, included;
	unsigned int maxdepth;
	const struct optnode *optnode;
	char *argument;


    if(opt_check(opt, "exclude-dir")) {
	argument = opt_firstarg(opt, "exclude-dir", &optnode);
	while(argument) {
	    if(match_regex(dirname, argument) == 1) {
		if(!printinfected)
		    logg("~%s: Excluded\n", dirname);
		return 0;
	    }
	    argument = opt_nextarg(&optnode, "exclude-dir");
	}
    }

   if(opt_check(opt, "include-dir")) {
	included = 0;
	argument = opt_firstarg(opt, "include-dir", &optnode);
	while(argument && !included) {
	    if(match_regex(dirname, argument) == 1) {
		included = 1;
		break;
	    }
	    argument = opt_nextarg(&optnode, "include-dir");
	}

	if(!included) {
	    if(!printinfected)
		logg("~%s: Excluded\n", dirname);
	    return 0;
	}
    }

    if(opt_check(opt, "max-dir-recursion"))
        maxdepth = atoi(opt_arg(opt, "max-dir-recursion"));
    else
        maxdepth = 15;

    if(depth > maxdepth)
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
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode) && recursion) {
			    if(scandirs(fname, engine, opt, limits, options, depth) == 1)
				scanret++;
			} else {
			    if(S_ISREG(statbuf.st_mode))
				scanret += scanfile(fname, engine, opt, limits, options);
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

static int scanstdin(const struct cl_engine *engine, const struct cl_limits *limits, int options)
{
	int ret;
	const char *virname, *tmpdir;
	char *file, buff[FILEBUFF];
	size_t bread;
	FILE *fs;


    /* check write access */
    tmpdir = getenv("TMPDIR");

    if(tmpdir == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

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

    while((bread = fread(buff, 1, FILEBUFF, stdin)))
	if(fwrite(buff, 1, bread, fs) < bread) {
	    logg("!Can't write to %s\n", file);
	    free(file);
	    return 58;
	}

    fclose(fs);

    logg("*Checking %s\n", file);
    info.files++;

    if((ret = cl_scanfile(file, &virname, &info.blocks, engine, limits, options)) == CL_VIRUS) {
	logg("stdin: %s FOUND\n", virname);
	info.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected)
	    mprintf("stdin: OK\n");
    } else
	if(!printinfected)
	    logg("stdin: %s\n", cl_strerror(ret));

    unlink(file);
    free(file);
    return ret;
}

int scanmanager(const struct optstruct *opt)
{
	mode_t fmode;
	int ret = 0, fmodeint, i, x;
	unsigned int options = 0, dboptions = 0;
	struct cl_engine *engine = NULL;
	struct cl_limits limits;
	struct stat sb;
	char *file, cwd[1024], *pua_cats = NULL, *argument;
	const struct optnode *optnode;
#ifndef C_WINDOWS
	struct rlimit rlim;
#endif


    if(!opt_check(opt, "no-phishing-sigs"))
	dboptions |= CL_DB_PHISHING;

    if(!opt_check(opt,"no-phishing-scan-urls"))
	dboptions |= CL_DB_PHISHING_URLS;
    if(opt_check(opt,"phishing-ssl")) {
	options |= CL_SCAN_PHISHING_BLOCKSSL;
    }
    if(opt_check(opt,"phishing-cloak")) {
	options |= CL_SCAN_PHISHING_BLOCKCLOAK;
    }
    if(opt_check(opt,"heuristic-scan-precedence")) {
	options |= CL_SCAN_HEURISTIC_PRECEDENCE;
    }

    if(opt_check(opt, "dev-ac-only"))
	dboptions |= CL_DB_ACONLY;

    if(opt_check(opt, "dev-ac-depth"))
	cli_ac_setdepth(AC_DEFAULT_MIN_DEPTH, atoi(opt_arg(opt, "dev-ac-depth")));

    if(opt_check(opt, "detect-pua")) {
	dboptions |= CL_DB_PUA;

	if(opt_check(opt, "exclude-pua")) {
	    dboptions |= CL_DB_PUA_EXCLUDE;
	    argument = opt_firstarg(opt, "exclude-pua", &optnode);
	    i = 0;
	    while(argument) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(argument) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    return 70;
		}
		sprintf(pua_cats + i, ".%s", argument);
		i += strlen(argument) + 1;
		pua_cats[i] = 0;
		argument = opt_nextarg(&optnode, "exclude-pua");
	    }
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if(opt_check(opt, "include-pua")) {
	    if(pua_cats) {
		logg("!--exclude-pua and --include-pua cannot be used at the same time\n");
		free(pua_cats);
		return 40;
	    }
	    dboptions |= CL_DB_PUA_INCLUDE;
	    argument = opt_firstarg(opt, "include-pua", &optnode);
	    i = 0;
	    while(argument) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(argument) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    return 70;
		}
		sprintf(pua_cats + i, ".%s", argument);
		i += strlen(argument) + 1;
		pua_cats[i] = 0;
		argument = opt_nextarg(&optnode, "include-pua");
	    }
	    pua_cats[i] = '.';
	    pua_cats[i + 1] = 0;
	}

	if(pua_cats) {
	    /* FIXME with the new API */
	    if((ret = cli_initengine(&engine, dboptions))) {
		logg("!cli_initengine() failed: %s\n", cl_strerror(ret));
		free(pua_cats);
		return 50;
	    }
	    engine->pua_cats = pua_cats;
	}
    }

    if(opt_check(opt, "database")) {
	if((ret = cl_load(opt_arg(opt, "database"), &engine, &info.sigs, dboptions))) {
	    logg("!%s\n", cl_strerror(ret));
	    return 50;
	}

    } else {
	    char *dbdir = freshdbdir();

	if((ret = cl_load(dbdir, &engine, &info.sigs, dboptions))) {
	    logg("!%s\n", cl_strerror(ret));
	    free(dbdir);
	    return 50;
	}
	free(dbdir);
    }

    if(!engine) {
	logg("!Can't initialize the virus database\n");
	return 50;
    }

    if((ret = cl_build(engine)) != 0) {
	logg("!Database initialization error: %s\n", cl_strerror(ret));;
	return 50;
    }

    /* set limits */
    memset(&limits, 0, sizeof(struct cl_limits));

    if(opt_check(opt, "max-scansize")) {
	char *cpy, *ptr;
	ptr = opt_arg(opt, "max-scansize");
	if(tolower(ptr[strlen(ptr) - 1]) == 'm') {
	    cpy = calloc(strlen(ptr), 1);
	    strncpy(cpy, ptr, strlen(ptr) - 1);
	    cpy[strlen(ptr)-1]='\0';
	    limits.maxscansize = atoi(cpy) * 1024 * 1024;
	    free(cpy);
	} else
	    limits.maxscansize = atoi(ptr) * 1024;
    } else
	limits.maxscansize = 104857600;

    if(opt_check(opt, "max-filesize")) {
	char *cpy, *ptr;
	ptr = opt_arg(opt, "max-filesize");
	if(tolower(ptr[strlen(ptr) - 1]) == 'm') {
	    cpy = calloc(strlen(ptr), 1);
	    strncpy(cpy, ptr, strlen(ptr) - 1);
	    cpy[strlen(ptr)-1]='\0';
	    limits.maxfilesize = atoi(cpy) * 1024 * 1024;
	    free(cpy);
	} else
	    limits.maxfilesize = atoi(ptr) * 1024;
    } else
	limits.maxfilesize = 26214400;

#ifndef C_WINDOWS
    if(getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
	if((rlim.rlim_max < limits.maxfilesize) || (rlim.rlim_max < limits.maxscansize))
	    logg("^System limit for file size is lower than maxfilesize or maxscansize\n");
    } else {
	logg("^Cannot obtain resource limits for file size\n");
    }
#endif

    if(opt_check(opt, "max-files"))
	limits.maxfiles = atoi(opt_arg(opt, "max-files"));
    else
        limits.maxfiles = 10000;

    if(opt_check(opt, "max-recursion"))
        limits.maxreclevel = atoi(opt_arg(opt, "max-recursion"));
    else
        limits.maxreclevel = 16;

    /* set options */

    if(opt_check(opt, "disable-archive") || opt_check(opt, "no-archive"))
	options &= ~CL_SCAN_ARCHIVE;
    else
	options |= CL_SCAN_ARCHIVE;

    if(opt_check(opt, "detect-broken"))
	options |= CL_SCAN_BLOCKBROKEN;

    if(opt_check(opt, "block-encrypted"))
	options |= CL_SCAN_BLOCKENCRYPTED;

    if(opt_check(opt, "no-pe"))
	options &= ~CL_SCAN_PE;
    else
	options |= CL_SCAN_PE;

    if(opt_check(opt, "no-elf"))
	options &= ~CL_SCAN_ELF;
    else
	options |= CL_SCAN_ELF;

    if(opt_check(opt, "no-ole2"))
	options &= ~CL_SCAN_OLE2;
    else
	options |= CL_SCAN_OLE2;

    if(opt_check(opt, "no-pdf"))
	options &= ~CL_SCAN_PDF;
    else
	options |= CL_SCAN_PDF;

    if(opt_check(opt, "no-html"))
	options &= ~CL_SCAN_HTML;
    else
	options |= CL_SCAN_HTML;

    if(opt_check(opt, "no-mail")) {
	options &= ~CL_SCAN_MAIL;
    } else {
	options |= CL_SCAN_MAIL;

	if(opt_check(opt, "mail-follow-urls"))
	    options |= CL_SCAN_MAILURL;
    }

    if(opt_check(opt, "no-algorithmic"))
	options &= ~CL_SCAN_ALGORITHMIC;
    else
	options |= CL_SCAN_ALGORITHMIC;

    if(opt_check(opt, "detect-structured")) {
	options |= CL_SCAN_STRUCTURED;

	if(opt_check(opt, "structured-ssn-format")) {
	    switch(atoi(opt_arg(opt, "structured-ssn-format"))) {
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

	if(opt_check(opt, "structured-ssn-count"))
	    limits.min_ssn_count = atoi(opt_arg(opt, "structured-ssn-count"));
	else
	    limits.min_ssn_count = 3;

	if(opt_check(opt, "structured-cc-count"))
	    limits.min_cc_count = atoi(opt_arg(opt, "structured-cc-count"));
	else
	    limits.min_cc_count = 3;

    } else
	options &= ~CL_SCAN_STRUCTURED;


#ifdef C_LINUX
    procdev = (dev_t) 0;
    if(stat("/proc", &sb) != -1 && !sb.st_size)
	procdev = sb.st_dev;
#endif

    /* check filetype */
    if(opt->filename == NULL || strlen(opt->filename) == 0) {

	/* we need full path for some reasons (eg. archive handling) */
	if(!getcwd(cwd, sizeof(cwd))) {
	    logg("!Can't get absolute pathname of current working directory\n");
	    ret = 57;
	} else
	    ret = scandirs(cwd, engine, opt, &limits, options, 1);

    } else if(!strcmp(opt->filename, "-")) { /* read data from stdin */
	ret = scanstdin(engine, &limits, options);

    } else {
	for (x = 0; (file = cli_strtok(opt->filename, x, "\t")) != NULL; x++) {
	    if((fmodeint = fileinfo(file, 2)) == -1) {
		logg("^Can't access file %s\n", file);
		perror(file);
		ret = 56;
	    } else {
		int slash = 1;
		for(i = strlen(file) - 1; i > 0 && slash; i--) {
		    if(file[i] == '/')
			file[i] = 0;
		    else
			slash = 0;
		}

		fmode = (mode_t) fmodeint;

		switch(fmode & S_IFMT) {
		    case S_IFREG:
			ret = scanfile(file, engine, opt, &limits, options);
			break;

		    case S_IFDIR:
			ret = scandirs(file, engine, opt, &limits, options, 1);
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
    cl_free(engine);

    /* overwrite return code */
    if(info.ifiles)
	ret = 1;
    else if(ret < 50) /* hopefully no error detected */ 
	ret = 0; /* just make sure it's 0 */

    return ret;
}

static void move_infected(const char *filename, const struct optstruct *opt)
{
	char *movedir, *movefilename, numext[4 + 1];
	const char *tmp;
	struct stat ofstat, mfstat;
	int n, len, movefilename_size;
	int moveflag = opt_check(opt, "move");
	struct utimbuf ubuf;


    if((moveflag && !(movedir = opt_arg(opt, "move"))) ||
	(!moveflag && !(movedir = opt_arg(opt, "copy")))) {
        /* Should never reach here */
        logg("!opt_arg() returned NULL\n");
        info.notmoved++;
        return;
    }

    if(access(movedir, W_OK|X_OK) == -1) {
	logg("!Can't %s file '%s': cannot write to '%s': %s\n", (moveflag) ? "move" : "copy", filename, movedir, strerror(errno));
        info.notmoved++;
        return;
    }

    if(!(tmp = strrchr(filename, '/')))
	tmp = filename;

    movefilename_size = sizeof(char) * (strlen(movedir) + strlen(tmp) + sizeof(numext) + 2);

    if(!(movefilename = malloc(movefilename_size))) {
        logg("!malloc() failed\n");
	exit(71);
    }

    if(!(cli_strrcpy(movefilename, movedir))) {
        logg("!cli_strrcpy() returned NULL\n");
        info.notmoved++;
        free(movefilename);
        return;
    }

    strcat(movefilename, "/");

    if(!(strcat(movefilename, tmp))) {
        logg("!strcat() returned NULL\n");
        info.notmoved++;
        free(movefilename);
        return;
    }

    stat(filename, &ofstat);

    if(!stat(movefilename, &mfstat)) {
        if((ofstat.st_dev == mfstat.st_dev) && (ofstat.st_ino == mfstat.st_ino)) { /* It's the same file*/
            logg("File excluded '%s'\n", filename);
            info.notmoved++;
            free(movefilename);
            return;
        } else {
            /* file exists - try to append an ordinal number to the
	     * quranatined file in an attempt not to overwrite existing
	     * files in quarantine  
	     */
            len = strlen(movefilename);
            n = 0;        		        		
            do {
                /* reset the movefilename to it's initial value by
		 * truncating to the original filename length
		 */
                movefilename[len] = 0;
                /* append .XXX */
                sprintf(numext, ".%03d", n++);
                strcat(movefilename, numext);            	
            } while(!stat(movefilename, &mfstat) && (n < 1000));
       }
    }

    if(!moveflag || rename(filename, movefilename) == -1) {
	if(filecopy(filename, movefilename) == -1) {
	    logg("!Can't %s '%s' to '%s': %s\n", (moveflag) ? "move" : "copy", filename, movefilename, strerror(errno));
	    info.notmoved++;
	    free(movefilename);
	    return;
	}

	chmod(movefilename, ofstat.st_mode);
#ifndef C_OS2
	if(chown(movefilename, ofstat.st_uid, ofstat.st_gid) == -1) {
		logg("!Can't chown '%s': %s\n", movefilename, strerror(errno));
	}
#endif

	ubuf.actime = ofstat.st_atime;
	ubuf.modtime = ofstat.st_mtime;
	utime(movefilename, &ubuf);

	if(moveflag && unlink(filename)) {
	    logg("!Can't unlink '%s': %s\n", filename, strerror(errno));
	    info.notremoved++;            
	    free(movefilename);
	    return;
	}
    }

    logg("~%s: %s to '%s'\n", filename, (moveflag) ? "moved" : "copied", movefilename);

    free(movefilename);
}

