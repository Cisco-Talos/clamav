/*
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
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <dirent.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <utime.h>
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
#include <target.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "manager.h"
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

char hostid[37];

char *get_hostid(void *cbdata);

#ifdef _WIN32
/* FIXME: If possible, handle users correctly */
static int checkaccess(const char *path, const char *username, int mode)
{
    return !access(path, mode);
}
#else
static int checkaccess(const char *path, const char *username, int mode)
{
	struct passwd *user;
	int ret = 0, status;

    if(!geteuid()) {

	if((user = getpwnam(username)) == NULL) {
	    return -1;
	}

	switch(fork()) {
	    case -1:
		return -2;

	    case 0:
		if(setgid(user->pw_gid)) {
		    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
		    exit(0);
		}

		if(setuid(user->pw_uid)) {
		    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
		    exit(0);
		}

		if(access(path, mode))
		    exit(0);
		else
		    exit(1);

	    default:
		wait(&status);
		if(WIFEXITED(status) && WEXITSTATUS(status) == 1)
		    ret = 1;
	}

    } else {
	if(!access(path, mode))
	    ret = 1;
    }

    return ret;
}
#endif

struct metachain {
    char **chains;
    unsigned lastadd;
    unsigned lastvir;
    unsigned level;
    unsigned n;
};

static cl_error_t pre(int fd, const char *type, void *context)
{
    struct metachain *c = context;
    if (c) {
	c->level++;
    }
    return CL_CLEAN;
}

static int print_chain(struct metachain *c, char *str, unsigned len)
{
    unsigned i;
    unsigned na = 0;
    for (i=0;i<c->n-1;i++) {
	unsigned int n = strlen(c->chains[i]);
	if (na)
	    str[na++] = '!';
	if (n + na + 2 > len)
	    break;
	memcpy(str + na, c->chains[i], n);
	na += n;
    }
    str[na] = '\0';
    str[len-1] = '\0';
    return i == c->n-1 ? 0 : 1;
}

static cl_error_t post(int fd, int result, const char *virname, void *context)
{
    struct metachain *c = context;
    if (c && c->n) {
	char str[128];
	int toolong = print_chain(c, str, sizeof(str));
	if (c->level == c->lastadd && !virname)
	    free(c->chains[--c->n]);
	if (virname && !c->lastvir)
	    c->lastvir = c->level;
    }
    if (c)
	c->level--;
    return CL_CLEAN;
}

static cl_error_t meta(const char* container_type, unsigned long fsize_container, const char *filename,
		       unsigned long fsize_real,  int is_encrypted, unsigned int filepos_container, void *context)
{
    int na = 0;
    char prev[128];
    struct metachain *c = context;
    const char *type = !strncmp(container_type,"CL_TYPE_",8) ? container_type + 8 : container_type;
    unsigned n = strlen(type) + 1 + strlen(filename) + 1;
    char *chain;
    char **chains;
    int toolong;

    if (!c)
	return CL_CLEAN;
    chain = malloc(n);
    if (!chain)
	return CL_CLEAN;
    if (!strcmp(type, "ANY"))
	snprintf(chain, n,"%s", filename);
    else
	snprintf(chain, n,"%s:%s", type, filename);
    if (c->lastadd != c->level) {
	n = c->n + 1;
	chains = realloc(c->chains, n * sizeof(*chains));
	if (!chains) {
	    free(chain);
	    return CL_CLEAN;
	}
	c->chains = chains;
	c->n = n;
	c->lastadd = c->level;
    } else {
	free(c->chains[c->n-1]);
    }
    c->chains[c->n-1] = chain;
    toolong = print_chain(c, prev, sizeof(prev));
    logg("*Scanning %s%s!%s\n", prev,toolong ? "..." : "", chain);
    return CL_CLEAN;
}

static void scanfile(const char *filename, struct cl_engine *engine, const struct optstruct *opts, unsigned int options)
{
	int ret = 0, fd, included;
	unsigned i;
	const struct optstruct *opt;
	const char *virname;
	const char **virpp = &virname;
	STATBUF sb;
	struct metachain chain;

    if((opt = optget(opts, "exclude"))->enabled) {
	while(opt) {
	    if(match_regex(filename, opt->strarg) == 1) {
		if(!printinfected)
		    logg("~%s: Excluded\n", filename);
		return;
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
	    return;
	}
    }

    /* argh, don't scan /proc files */
    if(CLAMSTAT(filename, &sb) != -1) {
#ifdef C_LINUX
	if(procdev && sb.st_dev == procdev) {
	    if(!printinfected)
		logg("~%s: Excluded (/proc)\n", filename);
		return;
	}
#endif    
	if(!sb.st_size) {
	    if(!printinfected)
		logg("~%s: Empty file\n", filename);
	    return;
	}
	info.rblocks += sb.st_size / CL_COUNT_PRECISION;
    }

#ifndef _WIN32
    if(geteuid())
	if(checkaccess(filename, NULL, R_OK) != 1) {
	    if(!printinfected)
		logg("~%s: Access denied\n", filename);
	    info.errors++;
	    return;
	}
#endif

    memset(&chain, 0, sizeof(chain));
    if(optget(opts, "archive-verbose")->enabled) {
	chain.chains = malloc(sizeof(*chain.chains));
	if (chain.chains) {
	    chain.chains[0] = strdup(filename);
	    chain.n = 1;
	}
    }
    logg("*Scanning %s\n", filename);

    if((fd = safe_open(filename, O_RDONLY|O_BINARY)) == -1) {
	logg("^Can't open file %s: %s\n", filename, strerror(errno));
	info.errors++;
	return;
    }


    if((ret = cl_scandesc_callback(fd, virpp, &info.blocks, engine, options, &chain)) == CL_VIRUS) {
	if(optget(opts, "archive-verbose")->enabled) {
	    if (chain.n > 1) {
		char str[128];
		int toolong = print_chain(&chain, str, sizeof(str));
		logg("~%s%s!(%d)%s: %s FOUND\n", str, toolong ? "..." : "", chain.lastvir-1, chain.chains[chain.n-1], virname);
	    } else if (chain.lastvir)
		logg("~%s!(%d): %s FOUND\n", filename, chain.lastvir-1, virname);
	}
	if (options & CL_SCAN_ALLMATCHES) {
	    int i = 0;
	    virpp = (const char **)*virpp; /* horrible */
	    virname = virpp[0];
	    while (virpp[i])
		logg("~%s: %s FOUND\n", filename, virpp[i++]);
	    free((void *)virpp);
	}
	else
	    logg("~%s: %s FOUND\n", filename, virname);
	info.files++;
	info.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected && printclean)
	    mprintf("~%s: OK\n", filename);
	info.files++;
    } else {
	if(!printinfected)
	    logg("~%s: %s ERROR\n", filename, cl_strerror(ret));
	info.errors++;
    }

    for (i=0;i<chain.n;i++)
	free(chain.chains[i]);
    free(chain.chains);
    close(fd);

    if(ret == CL_VIRUS && action)
	action(filename);
}

static void scandirs(const char *dirname, struct cl_engine *engine, const struct optstruct *opts, unsigned int options, unsigned int depth, dev_t dev)
{
	DIR *dd;
	struct dirent *dent;
	STATBUF sb;
	char *fname;
	int included;
	const struct optstruct *opt;
	unsigned int dirlnk, filelnk;


    if((opt = optget(opts, "exclude-dir"))->enabled) {
	while(opt) {
	    if(match_regex(dirname, opt->strarg) == 1) {
		if(!printinfected)
		    logg("~%s: Excluded\n", dirname);
		return;
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
	    return;
	}
    }

    if(depth > (unsigned int) optget(opts, "max-dir-recursion")->numarg)
	return;

    dirlnk = optget(opts, "follow-dir-symlinks")->numarg;
    filelnk = optget(opts, "follow-file-symlinks")->numarg;

    if((dd = opendir(dirname)) != NULL) {
	info.dirs++;
	depth++;
	while((dent = readdir(dd))) {
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if (fname == NULL) { /* oops, malloc() failed, print warning and return */
			logg("!scandirs: Memory allocation failed for fname\n");
			break;
		    }

		    if(!strcmp(dirname, PATHSEP))
			sprintf(fname, PATHSEP"%s", dent->d_name);
		    else
			sprintf(fname, "%s"PATHSEP"%s", dirname, dent->d_name);

		    /* stat the file */
		    if(LSTAT(fname, &sb) != -1) {
			if(!optget(opts, "cross-fs")->enabled) {
			    if(sb.st_dev != dev) {
				if(!printinfected)
				    logg("~%s: Excluded\n", fname);
				free(fname);
				continue;
			    }
			}
			if(S_ISLNK(sb.st_mode)) {
			    if(dirlnk != 2 && filelnk != 2) {
				if(!printinfected)
				    logg("%s: Symbolic link\n", fname);
			    } else if(CLAMSTAT(fname, &sb) != -1) {
				if(S_ISREG(sb.st_mode) && filelnk == 2) {
				    scanfile(fname, engine, opts, options);
				} else if(S_ISDIR(sb.st_mode) && dirlnk == 2) {
				    if(recursion)
					scandirs(fname, engine, opts, options, depth, dev);
				} else {
				    if(!printinfected)
					logg("%s: Symbolic link\n", fname);
				}
			    }
			} else if(S_ISREG(sb.st_mode)) {
			    scanfile(fname, engine, opts, options);
			} else if(S_ISDIR(sb.st_mode) && recursion) {
			    scandirs(fname, engine, opts, options, depth, dev);
			}
		    }
		    free(fname);
		}
	    }
	}
	closedir(dd);
    } else {
	if(!printinfected)
	    logg("~%s: Can't open directory.\n", dirname);
	info.errors++;
    }
}

static int scanstdin(const struct cl_engine *engine, const struct optstruct *opts, int options)
{
	int ret;
	unsigned int fsize = 0;
	const char *virname, *tmpdir;
	const char **virpp = &virname;

	char *file, buff[FILEBUFF];
	size_t bread;
	FILE *fs;

    if(optget(opts, "tempdir")->enabled) {
	tmpdir = optget(opts, "tempdir")->strarg;
    } else
	/* check write access */
	tmpdir = cli_gettmpdir();

    if(checkaccess(tmpdir, CLAMAVUSER, W_OK) != 1) {
	logg("!Can't write to temporary directory\n");
	return 2;
    }

    if(!(file = cli_gentemp(tmpdir))) {
	logg("!Can't generate tempfile name\n");
	return 2;
    }

    if(!(fs = fopen(file, "wb"))) {
	logg("!Can't open %s for writing\n", file);
	free(file);
	return 2;
    }

    while((bread = fread(buff, 1, FILEBUFF, stdin))) {
	fsize += bread;
	if(fwrite(buff, 1, bread, fs) < bread) {
	    logg("!Can't write to %s\n", file);
	    free(file);
	    fclose(fs);
	    return 2;
	}
    }
    fclose(fs);

    logg("*Checking %s\n", file);
    info.files++;
    info.rblocks += fsize / CL_COUNT_PRECISION;

    if((ret = cl_scanfile(file, &virname, &info.blocks, engine, options)) == CL_VIRUS) {
        if (options & CL_SCAN_ALLMATCHES) {
            int i = 0;
            virpp = (const char **)*virpp; /* temp hack for scanall mode until api augmentation */
            virname = virpp[0];
            while (virpp[i])
                logg("stdin: %s FOUND\n", virpp[i++]);
            free((void *)virpp);
        }
	else
	    logg("stdin: %s FOUND\n", virname);

	info.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected)
	    mprintf("stdin: OK\n");
    } else {
	if(!printinfected)
	    logg("stdin: %s ERROR\n", cl_strerror(ret));
	info.errors++;
    }

    unlink(file);
    free(file);
    return ret;
}

int scanmanager(const struct optstruct *opts)
{
	int ret = 0, i;
	unsigned int options = 0, dboptions = 0, dirlnk = 1, filelnk = 1;
	struct cl_engine *engine;
	STATBUF sb;
	char *file, cwd[1024], *pua_cats = NULL;
	const char *filename;
	const struct optstruct *opt;
#ifndef _WIN32
	struct rlimit rlim;
#endif

    dirlnk = optget(opts, "follow-dir-symlinks")->numarg;
    if(dirlnk > 2) {
	logg("!--follow-dir-symlinks: Invalid argument\n");
	return 2;
    }

    filelnk = optget(opts, "follow-file-symlinks")->numarg;
    if(filelnk > 2) {
	logg("!--follow-file-symlinks: Invalid argument\n");
	return 2;
    }

    if(optget(opts, "phishing-sigs")->enabled)
	dboptions |= CL_DB_PHISHING;

    if(optget(opts, "official-db-only")->enabled)
	dboptions |= CL_DB_OFFICIAL_ONLY;

    if(optget(opts,"phishing-scan-urls")->enabled)
	dboptions |= CL_DB_PHISHING_URLS;

    if(optget(opts,"bytecode")->enabled)
	dboptions |= CL_DB_BYTECODE;

    if((ret = cl_init(CL_INIT_DEFAULT))) {
	logg("!Can't initialize libclamav: %s\n", cl_strerror(ret));
	return 2;
    }

    if(!(engine = cl_engine_new())) {
	logg("!Can't initialize antivirus engine\n");
	return 2;
    }

    if (optget(opts, "disable-cache")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1);

    if (optget(opts, "disable-pe-stats")->enabled) {
        cl_engine_set_num(engine, CL_ENGINE_DISABLE_PE_STATS, 1);
    }

    if (optget(opts, "enable-stats")->enabled) {
        cl_engine_stats_enable(engine);
    }

    if (optget(opts, "stats-timeout")->enabled) {
        cl_engine_set_num(engine, CL_ENGINE_STATS_TIMEOUT, optget(opts, "StatsTimeout")->numarg);
    }

    if (optget(opts, "stats-host-id")->enabled) {
        char *p = optget(opts, "stats-host-id")->strarg;

        if (strcmp(p, "default")) {
            if (!strcmp(p, "none")) {
                cl_engine_set_clcb_stats_get_hostid(engine, NULL);
            } else if (!strcmp(p, "anonymous")) {
                strcpy(hostid, STATS_ANON_UUID);
            } else {
                if (strlen(p) > 36) {
                    logg("!Invalid HostID\n");
                    cl_engine_set_clcb_stats_submit(engine, NULL);
                    cl_engine_free(engine);
                    return 2;
                }

                strcpy(hostid, p);
            }

            cl_engine_set_clcb_stats_get_hostid(engine, get_hostid);
        }
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
		    return 2;
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
		return 2;
	    }
	    dboptions |= CL_DB_PUA_INCLUDE;
	    i = 0;
	    while(opt) {
		if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
		    logg("!Can't allocate memory for pua_cats\n");
		    cl_engine_free(engine);
		    return 2;
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
		return 2;
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

    if(optget(opts, "force-to-disk")->enabled)
	cl_engine_set_num(engine, CL_ENGINE_FORCETODISK, 1);

    if(optget(opts, "bytecode-unsigned")->enabled)
	dboptions |= CL_DB_BYTECODE_UNSIGNED;

    if(optget(opts, "bytecode-statistics")->enabled)
	dboptions |= CL_DB_BYTECODE_STATS;

    if((opt = optget(opts,"bytecode-timeout"))->enabled)
	cl_engine_set_num(engine, CL_ENGINE_BYTECODE_TIMEOUT, opt->numarg);
    if((opt = optget(opts,"bytecode-mode"))->enabled) {
	enum bytecode_mode mode;
	if (!strcmp(opt->strarg, "ForceJIT"))
	    mode = CL_BYTECODE_MODE_JIT;
	else if(!strcmp(opt->strarg, "ForceInterpreter"))
	    mode = CL_BYTECODE_MODE_INTERPRETER;
	else if(!strcmp(opt->strarg, "Test"))
	    mode = CL_BYTECODE_MODE_TEST;
	else
	    mode = CL_BYTECODE_MODE_AUTO;
	cl_engine_set_num(engine, CL_ENGINE_BYTECODE_MODE, mode);
    }

    if((opt = optget(opts, "tempdir"))->enabled) {
	if((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, opt->strarg))) {
	    logg("!cli_engine_set_str(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "database"))->active) {
	while(opt) {
	    if((ret = cl_load(opt->strarg, engine, &info.sigs, dboptions))) {
		logg("!%s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 2;
	    }
	    opt = opt->nextarg;
	}
    } else {
	    char *dbdir = freshdbdir();

	if((ret = cl_load(dbdir, engine, &info.sigs, dboptions))) {
	    logg("!%s\n", cl_strerror(ret));
	    free(dbdir);
	    cl_engine_free(engine);
	    return 2;
	}
	free(dbdir);
    }

    if((ret = cl_engine_compile(engine)) != 0) {
	logg("!Database initialization error: %s\n", cl_strerror(ret));;
	cl_engine_free(engine);
	return 2;
    }

    if(optget(opts, "archive-verbose")->enabled) {
	cl_engine_set_clcb_meta(engine, meta);
	cl_engine_set_clcb_pre_cache(engine, pre);
	cl_engine_set_clcb_post_scan(engine, post);
    }

    if (optget(opts, "nocerts")->enabled)
        engine->dconf->pe |= PE_CONF_DISABLECERT;

    if (optget(opts, "dumpcerts")->enabled)
        engine->dconf->pe |= PE_CONF_DUMPCERT;

    /* set limits */

    if((opt = optget(opts, "max-scansize"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_SCANSIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-filesize"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

#ifndef _WIN32
    if(getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
	if(rlim.rlim_cur < (rlim_t) cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL))
	    logg("^System limit for file size is lower than engine->maxfilesize\n");
	if(rlim.rlim_cur < (rlim_t) cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL))
	    logg("^System limit for file size is lower than engine->maxscansize\n");
    } else {
	logg("^Cannot obtain resource limits for file size\n");
    }
#endif

    if((opt = optget(opts, "max-files"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_FILES) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-recursion"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_RECURSION) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    /* Engine max sizes */

    if((opt = optget(opts, "max-embeddedpe"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_EMBEDDEDPE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-htmlnormalize"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_HTMLNORMALIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-htmlnotags"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_HTMLNOTAGS) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-scriptnormalize"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_SCRIPTNORMALIZE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-ziptypercg"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_ZIPTYPERCG) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-partitions"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_PARTITIONS, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_PARTITIONS) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    if((opt = optget(opts, "max-iconspe"))->active) {
	if((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ICONSPE, opt->numarg))) {
	    logg("!cli_engine_set_num(CL_ENGINE_MAX_ICONSPE) failed: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    return 2;
	}
    }

    /* set scan options */
    if(optget(opts, "allmatch")->enabled)
	options |= CL_SCAN_ALLMATCHES;

    if(optget(opts,"phishing-ssl")->enabled)
	options |= CL_SCAN_PHISHING_BLOCKSSL;

    if(optget(opts,"phishing-cloak")->enabled)
	options |= CL_SCAN_PHISHING_BLOCKCLOAK;

    if(optget(opts,"partition-intersection")->enabled)
	options |= CL_SCAN_PARTITION_INTXN;

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

    if(optget(opts, "scan-swf")->enabled)
	options |= CL_SCAN_SWF;

    if(optget(opts, "scan-html")->enabled)
	options |= CL_SCAN_HTML;

    if(optget(opts, "scan-mail")->enabled)
	options |= CL_SCAN_MAIL;

    if(optget(opts, "algorithmic-detection")->enabled)
	options |= CL_SCAN_ALGORITHMIC;

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if(optget(opts, "dev-collect-hashes")->enabled)
	options |= CL_SCAN_INTERNAL_COLLECT_SHA;
#endif

    if(optget(opts, "dev-performance")->enabled)
	options |= CL_SCAN_PERFORMANCE_INFO;

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
		    return 2;
	    }
	} else {
	    options |= CL_SCAN_STRUCTURED_SSN_NORMAL;
	}

	if((opt = optget(opts, "structured-ssn-count"))->active) {
	    if((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_SSN_COUNT, opt->numarg))) {
		logg("!cli_engine_set_num(CL_ENGINE_MIN_SSN_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 2;
	    }
	}

	if((opt = optget(opts, "structured-cc-count"))->active) {
	    if((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_CC_COUNT, opt->numarg))) {
		logg("!cli_engine_set_num(CL_ENGINE_MIN_CC_COUNT) failed: %s\n", cl_strerror(ret));
		cl_engine_free(engine);
		return 2;
	    }
	}

    } else {
	options &= ~CL_SCAN_STRUCTURED;
    }

#ifdef C_LINUX
    procdev = (dev_t) 0;
    if(CLAMSTAT("/proc", &sb) != -1 && !sb.st_size)
	procdev = sb.st_dev;
#endif

    /* check filetype */
    if(!opts->filename && !optget(opts, "file-list")->enabled) {
	/* we need full path for some reasons (eg. archive handling) */
	if(!getcwd(cwd, sizeof(cwd))) {
	    logg("!Can't get absolute pathname of current working directory\n");
	    ret = 2;
	} else {
	    CLAMSTAT(cwd, &sb);
	    scandirs(cwd, engine, opts, options, 1, sb.st_dev);
	}

    } else if(opts->filename && !optget(opts, "file-list")->enabled && !strcmp(opts->filename[0], "-")) { /* read data from stdin */
	ret = scanstdin(engine, opts, options);

    } else {
	if(opts->filename && optget(opts, "file-list")->enabled)
	    logg("^Only scanning files from --file-list (files passed at cmdline are ignored)\n");

	while((filename = filelist(opts, &ret)) && (file = strdup(filename))) {
	    if(LSTAT(file, &sb) == -1) {
		perror(file);
		logg("^%s: Can't access file\n", file);
		ret = 2;
	    } else {
		for(i = strlen(file) - 1; i > 0; i--) {
		    if(file[i] == *PATHSEP)
			file[i] = 0;
		    else
			break;
		}

		if(S_ISLNK(sb.st_mode)) {
		    if(dirlnk == 0 && filelnk == 0) {
			if(!printinfected)
			    logg("%s: Symbolic link\n", file);
		    } else if(CLAMSTAT(file, &sb) != -1) {
			if(S_ISREG(sb.st_mode) && filelnk) {
			    scanfile(file, engine, opts, options);
			} else if(S_ISDIR(sb.st_mode) && dirlnk) {
			    scandirs(file, engine, opts, options, 1, sb.st_dev);
			} else {
			    if(!printinfected)
				logg("%s: Symbolic link\n", file);
			}
		    }
		} else if(S_ISREG(sb.st_mode)) {
		    scanfile(file, engine, opts, options);
		} else if(S_ISDIR(sb.st_mode)) {
		    scandirs(file, engine, opts, options, 1, sb.st_dev);
		} else {
		    logg("^%s: Not supported file type\n", file);
		    ret = 2;
		}
	    }
	    free(file);
	}
    }

    if(optget(opts, "bytecode-statistics")->enabled) {
	cli_sigperf_print();
	cli_sigperf_events_destroy();
    }

    /* free the engine */
    cl_engine_free(engine);

    /* overwrite return code - infection takes priority */
    if(info.ifiles)
	ret = 1;
    else if(info.errors)
	ret = 2;

    return ret;
}

int is_valid_hostid(void)
{
    int count, i;

    if (strlen(hostid) != 36)
        return 0;

    count=0;
    for (i=0; i < 36; i++)
        if (hostid[i] == '-')
            count++;

    if (count != 4)
        return 0;

    if (hostid[8] != '-' || hostid[13] != '-' || hostid[18] != '-' || hostid[23] != '-')
        return 0;

    return 1;
}

char *get_hostid(void *cbdata)
{
    if (!strcmp(hostid, "none"))
        return NULL;

    if (!is_valid_hostid())
        return strdup(STATS_ANON_UUID);

    logg("HostID is valid: %s\n", hostid);

    return strdup(hostid);
}
