/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *
 *  Sat May 18 15:23:21 CEST 2002: included cpu autodetection from Magnus Ekdahl
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
#include <sys/wait.h>
#include <grp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <clamav.h>
#include <errno.h>

#include "defaults.h"
#include "others.h"
#include "options.h"
#include "manager.h"
#include "treewalk.h"
#include "shared.h"
#include "mbox.h"
#include "str.h"
#include "strrcpy.h"
#include "memory.h"
#include "output.h"

#ifdef C_LINUX
dev_t procdev;
#endif

int scanmanager(const struct optstruct *opt)
{
	mode_t fmode;
	int ret = 0, compression = 0, fmodeint;
	struct cl_node *trie = NULL;
	struct cl_limits *limits = NULL;
	struct passwd *user = NULL;
	struct stat sb;
	char *fullpath = NULL, cwd[200];


/* njh@bandsman.co.uk: BeOS */
#if !defined(C_CYGWIN) && !defined(C_BEOS)
    if(!getuid()) {
	if((user = getpwnam(UNPUSER)) == NULL) {
	    mprintf("@Can't get information about user "UNPUSER".\n");
	    exit(60); /* this is critical problem, so we just exit here */
	}
    }
#endif


    if(optl(opt, "unzip") || optl(opt, "unrar") || optl(opt, "unace") ||
       optl(opt, "arj") || optl(opt, "unzoo") || optl(opt, "jar") ||
       optl(opt, "lha") || optl(opt, "tar") || optl(opt, "tgz") ||
       optl(opt, "deb"))
	    compression = 1;


    /* now initialize the database */

    if(optc(opt, 'd')) {
	stat(getargc(opt, 'd'), &sb);
	switch(sb.st_mode & S_IFMT) {
	    case S_IFREG:
		if((ret = cl_loaddb(getargc(opt, 'd'), &trie, &claminfo.signs))) {
		    mprintf("@%s\n", cl_strerror(ret));
		    return 50;
		}
		break;
            case S_IFDIR:
		if((ret = cl_loaddbdir(getargc(opt, 'd'), &trie, &claminfo.signs))) {
		    mprintf("@%s\n", cl_strerror(ret));
		    return 50;
		}
		break;
            default:
		mprintf("@%s: Not supported database file type\n", getargc(opt, 'd'));
		return 50;
	}

    } else {
	if((ret = cl_loaddbdir(cl_retdbdir(), &trie, &claminfo.signs))) {
	    mprintf("@%s\n", cl_strerror(ret));
	    return 50;
	}
    }


    if(!trie) {
	mprintf("@Can't initialize the virus database.\n");
	return 50;
    }

    /* build the proper trie */
    if((ret=cl_buildtrie(trie)) != 0) {
	mprintf("@Database initialization error: %s\n", cl_strerror(ret));;
	return 50;
    }

    /* set (default) limits */

    limits = (struct cl_limits *) calloc(1, sizeof(struct cl_limits));

    if(optl(opt, "max-space")) {
	char *cpy, *ptr;
	ptr = getargl(opt, "max-space");
	if(tolower(ptr[strlen(ptr) - 1]) == 'm') {
	    cpy = mcalloc(strlen(ptr), sizeof(char));
	    strncpy(cpy, ptr, strlen(ptr) - 1);
	    limits->maxfilesize = atoi(cpy) * 1024 * 1024;
	    free(cpy);
	} else
	    limits->maxfilesize = atoi(ptr) * 1024;
    } else
	limits->maxfilesize = 10485760;

    if(optl(opt, "max-files"))
	limits->maxfiles = atoi(getargl(opt, "max-files"));
    else
        limits->maxfiles = 500;

    if(optl(opt, "max-recursion"))
        limits->maxreclevel = atoi(getargl(opt, "max-recursion"));
    else
        limits->maxreclevel = 5;


#ifdef C_LINUX
    if(stat("/proc", &sb) == -1)
	procdev = 0;
    else
	procdev = sb.st_dev;
#endif

    /* check filetype */
    if(opt->filename == NULL || strlen(opt->filename) == 0) {

	/* we need full path for some reasons (eg. archive handling) */
	if(!getcwd(cwd, 200)) {
	    mprintf("@Can't get absolute pathname of current working directory.\n");
	    ret = 57;
	} else
	    ret = scandirs(cwd, trie, user, opt, limits);

    } else if(!strcmp(opt->filename, "-")) { /* read data from stdin */
	/*
	 * njh@bandsman.co.uk: treat the input as a mailbox, the program
	 * can then be used as a filter called when mail is received
	 */
	if(optc(opt, 'm')) {
		const char *tmpdir;
		char *dir;

		/* njh@bandsman.co.uk: BeOS */
#if !defined(C_CYGWIN) && !defined(C_BEOS)
		if(!getuid()) {
		    if((user = getpwnam(UNPUSER)) == NULL) {
			mprintf("@Can't get information about user %s\n", UNPUSER);
			exit(60); /* this is critical problem, so we just exit here */
		    }
		}
#endif

		if((tmpdir = getargl(opt, "tempdir")) == NULL)
			tmpdir = getenv("TMPDIR");

		if(tmpdir == NULL)
#ifdef P_tmpdir
			tmpdir = P_tmpdir;
#else
			tmpdir = "/tmp";
#endif

		if(writeaccess(tmpdir, UNPUSER) != 1) {
			mprintf("@Can't write to the temporary directory.\n");
			exit(64);
		}
		/* generate the temporary directory */

		dir = cl_gentemp(tmpdir);
		if(mkdir(dir, 0700)) {
			mprintf("@Can't create the temporary directory %s\n", dir);
			exit(63); /* critical */
		}

		if(user)
			chown(dir, user->pw_uid, user->pw_gid);

		/*
		 * Extract the attachments into the temporary directory
		 */
		ret = cl_mbox(dir, 0);

		if(ret == 0) {
			/* fix permissions of extracted files */
			fixperms(dir);

			if(ret == 0) /* execute successful */
				ret = treewalk(dir, trie, user, opt, limits);

			/* remove the directory - as clamav */
			clamav_rmdirs(dir);

			/* free dir - it's not necessary now */
			free(dir);
		}
	} else
	    ret = checkstdin(trie, limits);

    } else {
	int x;
	char *thefilename;
	for (x=0; (thefilename = cli_strtok(opt->filename, x, "\t")) != NULL; x++) {
	    if((fmodeint = fileinfo(thefilename, 2)) == -1) {
		mprintf("@Can't access file %s\n", thefilename);
		perror(thefilename);
		ret = 56;
	    } else {
		fmode = (mode_t) fmodeint;

		if(compression && (thefilename[0] != '/')) {
		    /* we need to complete the path */
		    if(!getcwd(cwd, 200)) {
			mprintf("@Can't get absolute pathname of current working directory.\n");
			return 57;
		    } else {
			fullpath = mcalloc(512, sizeof(char));
#ifdef NO_SNPRINTF
			sprintf(fullpath, "%s/%s", cwd, thefilename);
#else
			snprintf(fullpath, 512, "%s/%s", cwd, thefilename);
#endif
			mprintf("*Full path: %s\n", fullpath);
		    }
		} else
		    fullpath = (char *) thefilename;

		switch(fmode & S_IFMT) {
		    case S_IFREG:
			ret = scanfile(fullpath, trie, user, opt, limits);
			break;

		    case S_IFDIR:
			ret = scandirs(fullpath, trie, user, opt, limits);
			break;

		    default:
			mprintf("@Not supported file type (%s)\n", thefilename);
			ret = 52;
		}

		if(compression && thefilename[0] != '/') {
		    free(fullpath);
		    fullpath = NULL;
		}
	    }
	    free(thefilename);
	}
    }

    /* free the trie */
    cl_freetrie(trie);

    free(limits);

    /* overwrite return code */
    if(claminfo.ifiles)
	ret = 1;
    else if(ret < 50) /* hopefully no error detected */ 
	ret = 0; /* just make sure it's 0 */

    return ret;
}

int scanfile(const char *filename, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits)
{
	int ret, options = 0, included;
	struct optnode *optnode;
	char *argument;
#ifdef C_LINUX
	struct stat sb;

    /* argh, don't scan /proc files */
    if(procdev)
	if(stat(filename, &sb) != -1)
	    if(sb.st_dev == procdev) {
		if(!printinfected)
		    mprintf("%s: Excluded (/proc).\n", filename);
		return 0;
	    }
#endif

    if(optl(opt, "exclude")) {
	argument = getfirstargl(opt, "exclude", &optnode);
	while (argument) {
	    if(strstr(filename, argument)) {
		if(!printinfected)
		    mprintf("%s: Excluded.\n", filename);
		return 0;
	    }
	    argument = getnextargl(&optnode, "exclude");
	}
    }

    if(optl(opt, "include")) {
	included = 0;
	argument = getfirstargl(opt, "include",&optnode);
	while (argument && !included) {
	    if(strstr(filename, argument))
		included = 1;
	    argument = getnextargl(&optnode, "include");
	}

	if (!included) {
	    if(!printinfected)
		mprintf("%s: Excluded.\n", filename);
	    return 0;
	}
	
    }


    if(fileinfo(filename, 1) == 0) {
	if(!printinfected)
	    mprintf("%s: Empty file.\n", filename);
	return 0;
    }

    if(optl(opt, "disable-archive") || optl(opt, "no-archive"))
	options &= ~CL_ARCHIVE;
    else
	options |= CL_ARCHIVE;

    if(optl(opt, "block-encrypted"))
	options |= CL_ENCRYPTED;

    if(optl(opt, "no-ole2"))
	options &= ~CL_OLE2;
    else
	options |= CL_OLE2;

    if(optc(opt, 'm'))
	options |= CL_MAIL;

    /* 
     * check the extension  - this is a special case, normally we don't need to
     * do this (libclamav detects archive by its magic string), but here we
     * want to know the exit code from internal unpacker and try to use
     * external (if provided) when internal cannot extract data.
     */

    if((cli_strbcasestr(filename, ".zip") || cli_strbcasestr(filename, ".rar")) && (options & CL_ARCHIVE)) {
	/* try to use internal archivers */
	if((ret = checkfile(filename, root, limits, options)) == CL_VIRUS) {
	    if(optl(opt, "remove")) {
		if(unlink(filename)) {
		    mprintf("%s: Can't remove.\n", filename);
		    logg("%s: Can't remove.\n", filename);
		    claminfo.notremoved++;
		} else {
		    mprintf("%s: Removed.\n", filename);
		    logg("%s: Removed.\n", filename);
		}
	    } else if (optl(opt, "move"))
		move_infected(filename, opt);

	    return 1;

	} else if(ret == CL_CLEAN)
	    return 0;
	/* in other case try to continue with external archivers */
	options &= ~CL_ARCHIVE; /* and disable decompression for the below checkfile() */
	claminfo.files--; /* don't count it */
    }

    if((cli_strbcasestr(filename, ".zip") && optl(opt, "unzip"))
    || (cli_strbcasestr(filename, ".rar") && optl(opt, "unrar"))
    || (cli_strbcasestr(filename, ".ace") && optl(opt, "unace"))
    || (cli_strbcasestr(filename, ".arj") && optl(opt, "arj"))
    || (cli_strbcasestr(filename, ".zoo") && optl(opt, "unzoo"))
    || (cli_strbcasestr(filename, ".jar") && optl(opt, "jar"))
    || (cli_strbcasestr(filename, ".lzh") && optl(opt, "lha"))
    || (cli_strbcasestr(filename, ".tar") && optl(opt, "tar"))
    || (cli_strbcasestr(filename, ".deb") && optl(opt, "deb"))
    || ((cli_strbcasestr(filename, ".tar.gz") || cli_strbcasestr(filename, ".tgz")) 
	 && (optl(opt, "tgz") || optl(opt, "deb"))) ) {

	/* check permissions */
	switch(readaccess(filename, UNPUSER)) {
	    case -1:
		mprintf("@Can't get information about user "UNPUSER".\n");
		exit(60); /* this is critical problem, so we just exit here */
	    case -2:
		mprintf("@Can't get information about current user.\n");
		exit(59); /* this is critical problem, so we just exit here */
	    case 0: /* read access denied */
		if(getuid()) {
		    if(!printinfected)
			mprintf("%s: Access denied to archive.\n", filename);
		} else {

		    if(limits && limits->maxfilesize)
			if(fileinfo(filename, 1) / 1024 > limits->maxfilesize) {
			    if(!printinfected)
				mprintf("%s: Archive too big.\n", filename);
			    return 0;
			}

		    return(scandenied(filename, root, user, opt, limits));
		}
		return 0;
	    case 1:
		return(scancompressed(filename, root, user, opt, limits));
	}
    }

    if(getuid())
	switch(readaccess(filename, NULL)) {
	    case -2:
		mprintf("@Can't get information about current user.\n");
		exit(59); /* this is critical problem, so we just exit here */
	    case 0: /* read access denied */
		if(!printinfected)
		    mprintf("%s: Access denied.\n", filename);
		return 0;
	}

    if((ret = checkfile(filename, root, limits, options)) == CL_VIRUS) {
	if(optl(opt, "remove")) {
	    if(unlink(filename)) {
		mprintf("%s: Can't remove.\n", filename);
		logg("%s: Can't remove.\n", filename);
		claminfo.notremoved++;
	    } else {
		mprintf("%s: Removed.\n", filename);
		logg("%s: Removed.\n", filename);
	    }
	} else if (optl(opt, "move"))
            move_infected(filename, opt);
    }
    return ret;
}

/* it has guaranteed read access to the archive */
int scancompressed(const char *filename, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits)
{
	int ret = 0;
	char *tmpdir, *gendir, *userprg;
	struct stat statbuf;

    stat(filename, &statbuf);

    if(!S_ISREG(statbuf.st_mode)) {
	mprintf("^Suspected archive %s is not a regular file.\n", filename);
	return 0; /* hmm ? */
    }

    /* check write access */

    if((tmpdir = getargl(opt, "tempdir")) == NULL)
	/* njh@bandsman.co.uk: use TMPDIR as an alternative */
	tmpdir = getenv("TMPDIR");

    if(tmpdir == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

    if(writeaccess(tmpdir, UNPUSER) != 1) {
	mprintf("@Can't write to the temporary directory.\n");
	exit(64);
    }

    /* generate the temporary directory */

    gendir = cl_gentemp(tmpdir);
    if(mkdir(gendir, 0700)) {
	mprintf("@Can't create the temporary directory %s\n", gendir);
	exit(63); /* critical */
    }

    if(user)
	chown(gendir, user->pw_uid, user->pw_gid);


    /* unpack file  - as unprivileged user */
    if(cli_strbcasestr(filename, ".zip")) {
	char *args[] = { "unzip", "-P", "clam", "-o", (char *) filename, NULL };

	if((userprg = getargl(opt, "unzip")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("unzip", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".rar")) { 
	char *args[] = { "unrar", "x", "-p-", "-y", (char *) filename, NULL };
	if((userprg = getargl(opt, "unrar")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("unrar", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".ace")) { 
	char *args[] = { "unace", "x", "-y", (char *) filename, NULL };
	if((userprg = getargl(opt, "unace")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("unace", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".arj")) { 
        char *args[] = { "arj", "x","-y", (char *) filename, NULL };
        if((userprg = getargl(opt, "arj")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("arj", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".zoo")) { 
	char *args[] = { "unzoo", "-x","-j","./", (char *) filename, NULL };
	if((userprg = getargl(opt, "unzoo")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("unzoo", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".jar")) { 
	char *args[] = { "unzip", "-P", "clam", "-o", (char *) filename, NULL };
	if((userprg = getargl(opt, "jar")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("unzip", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".lzh")) { 
	char *args[] = { "lha", "xf", (char *) filename, NULL };
	if((userprg = getargl(opt, "lha")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("lha", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".tar")) { 
	char *args[] = { "tar", "-xpvf", (char *) filename, NULL };
	if((userprg = getargl(opt, "tar")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("tar", args, gendir, user, opt);

    } else if(cli_strbcasestr(filename, ".deb")) { 
	char *args[] = { "ar", "x", (char *) filename, NULL };
	if((userprg = getargl(opt, "deb")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("ar", args, gendir, user, opt);

    } else if((cli_strbcasestr(filename, ".tar.gz") || cli_strbcasestr(filename, ".tgz"))) {
	char *args[] = { "tar", "-zxpvf", (char *) filename, NULL };
	if((userprg = getargl(opt, "tgz")))
	    ret = clamav_unpack(userprg, args, gendir, user, opt);
	else
	    ret = clamav_unpack("tar", args, gendir, user, opt);
    }

    /* fix permissions of extracted files */
    fixperms(gendir);

    if(!ret) /* execute successful */
	ret = treewalk(gendir, root, user, opt, limits);

    /* remove the directory  - as clamav */
    clamav_rmdirs(gendir);

    /* free gendir - it's not necessary now */
    free(gendir);

    switch(ret) {
	case -1:
	    mprintf("@Can't fork().\n");
	    exit(61); /* this is critical problem, so we just exit here */
	case -2:
	    mprintf("@Can't execute some unpacker. Check paths and permissions on the temporary directory.\n");
	    /* This is no longer a critical error (since 0.24). We scan
	     * raw archive.
	     */
	    if(!printinfected)
		mprintf("(raw) ");

	    if((ret = checkfile(filename, root, limits, 0)) == CL_VIRUS) {
		if(optl(opt, "remove")) {
		    if(unlink(filename)) {
			mprintf("%s: Can't remove.\n", filename);
			logg("%s: Can't remove.\n", filename);
			claminfo.notremoved++;
		    } else {
			mprintf("%s: Removed.\n", filename);
			logg("%s: Removed.\n", filename);
		    }
		} else if (optl(opt, "move"))
		    move_infected(filename, opt);
	    }
	    return ret;
	case -3:
	    return 0;
	case 0:
	    /* no viruses found in archive, we scan just in case the same
	     * archive
	     */
	    if(!printinfected)
		mprintf("(raw) ");

	    if((ret = checkfile(filename, root, limits, 0)) == CL_VIRUS) {
		if(optl(opt, "remove")) {
		    if(unlink(filename)) {
			mprintf("%s: Can't remove.\n", filename);
			logg("%s: Can't remove.\n", filename);
			claminfo.notremoved++;
		    } else {
			mprintf("%s: Removed.\n", filename);
			logg("%s: Removed.\n", filename);
		    }
		} else if (optl(opt, "move"))
		    move_infected(filename, opt);
	    }
	    return ret;
	case 1:
	    logg("%s: Infected Archive FOUND\n", filename);
	    mprintf("%s: Infected Archive FOUND\n", filename);

	    if(bell)
		fprintf(stderr, "\007");

	    if(optl(opt, "remove")) {
		if(unlink(filename)) {
		    mprintf("%s: Can't remove.\n", filename);
		    logg("%s: Can't remove.\n", filename);
		    claminfo.notremoved++;
		} else {
		    mprintf("%s: Removed.\n", filename);
		    logg("%s: Removed.\n", filename);
		}
	    } else if (optl(opt, "move"))
		move_infected(filename, opt);

	    return 1;
	default:
	    mprintf("@Strange value (%d) returned in scancompressed()\n", ret);
	    return 0;
    }
}

int scandenied(const char *filename, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits)
{
	char *tmpdir, *gendir, *tmpfile, *pt;
	struct stat statbuf;
	int ret;

    stat(filename, &statbuf);
    if(!S_ISREG(statbuf.st_mode)) {
	mprintf("^Suspected archive %s is not a regular file.\n", filename);
	return 0;
    }

    /* check write access */

    if((tmpdir = getargl(opt, "tempdir")) == NULL)
        tmpdir = getenv("TMPDIR");

    if(tmpdir == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif


    if(writeaccess(tmpdir, UNPUSER) != 1) {
	mprintf("@Can't write to the temporary directory %s.\n", tmpdir);
	exit(64);
    }

    /* generate the temporary directory */
    gendir = cl_gentemp(tmpdir);
    if(mkdir(gendir, 0700)) {
	mprintf("@Can't create the temporary directory %s\n", gendir);
	exit(63); /* critical */
    }

    tmpfile = (char *) mcalloc(strlen(gendir) + strlen(filename) + 10, sizeof(char));
    pt = strrchr(filename, '/');
    if(!pt)
	pt = (char *) filename;
    else
	pt += 1;

    sprintf(tmpfile, "%s/%s", gendir, pt);

    if(filecopy(filename, tmpfile) == -1) {
	mprintf("!I/O error.\n");
	perror("copyfile()");
	exit(58);
    }

    fixperms(gendir);

    if(user) {
	chown(gendir, user->pw_uid, user->pw_gid);
	chown(tmpfile, user->pw_uid, user->pw_gid);
    }

    if((ret = treewalk(gendir, root, user, opt, limits)) == 1) {
	logg("(Real infected archive: %s)\n", filename);
	mprintf("(Real infected archive: %s)\n", filename);

	if(optl(opt, "remove")) {
	    if(unlink(filename)) {
		mprintf("%s: Can't remove.\n", filename);
		logg("%s: Can't remove.\n", filename);
		claminfo.notremoved++;
	    } else {
	        mprintf("%s: Removed.\n", filename);
	        logg("%s: Removed.\n", filename);
	    }
	} else if (optl(opt, "move"))
	    move_infected(filename, opt);
    }

    /* remove the directory  - as clamav */
    clamav_rmdirs(gendir);

    free(gendir);
    free(tmpfile);

    return ret;
}

int scandirs(const char *dirname, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits)
{
	return treewalk(dirname, root, user, opt, limits);
}

int checkfile(const char *filename, const struct cl_node *root, const struct cl_limits *limits, int options)
{
	int fd, ret;
	const char *virname;

    if((fd = open(filename, O_RDONLY)) == -1) {
	mprintf("@Can't open file %s\n", filename);
	return 54;
    }

    claminfo.files++;

    if((ret = cl_scandesc(fd, &virname, &claminfo.blocks, root, limits, options)) == CL_VIRUS) {
	mprintf("%s: %s FOUND\n", filename, virname);
	logg("%s: %s FOUND\n", filename, virname);
	claminfo.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected)
	    mprintf("%s: OK\n", filename);
    } else
	if(!printinfected)
	    mprintf("%s: %s\n", filename, cl_strerror(ret));

    close(fd);
    return ret;
}

int checkstdin(const struct cl_node *root, const struct cl_limits *limits)
{
	int ret;
	const char *virname;


    claminfo.files++;

    if((ret = cl_scandesc(0, &virname, &claminfo.blocks, root, limits, CL_RAW)) == CL_VIRUS) {
	mprintf("stdin: %s FOUND\n", virname);
	claminfo.ifiles++;

	if(bell)
	    fprintf(stderr, "\007");

    } else if(ret == CL_CLEAN) {
	if(!printinfected)
	    mprintf("stdin: OK\n");
    } else
	if(!printinfected)
	    mprintf("stdin: %s\n", cl_strerror(ret));

    return ret;
}

/*
 * -1 -> can't fork
 * -2 -> can't execute
 * -3 -> external signal
 * 0 -> OK
 */

int clamav_unpack(const char *prog, char **args, const char *tmpdir, const struct passwd *user, const struct optstruct *opt)
{
	pid_t pid;
	int status, wret, maxfiles, maxspace, fdevnull;
	struct s_du n;


    if(optl(opt, "max-files"))
	maxfiles = atoi(getargl(opt, "max-files"));
    else
	maxfiles = 0;

    if(optl(opt, "max-space")) {
	    char *cpy, *ptr;
	ptr = getargl(opt, "max-space");
	if(tolower(ptr[strlen(ptr) - 1]) == 'm') { /* megabytes */
	    cpy = mcalloc(strlen(ptr), sizeof(char));
	    strncpy(cpy, ptr, strlen(ptr) - 1);
	    maxspace = atoi(cpy) * 1024;
	    free(cpy);
	} else /* default - kilobytes */
	    maxspace = atoi(ptr);
    } else
	maxspace = 0;


    switch(pid = fork()) {
	case -1:
	    return -1;
	case 0:
#ifndef C_CYGWIN
	    if(!getuid() && user) {
		setgroups(1, &user->pw_gid);
		setgid(user->pw_gid);
		setuid(user->pw_uid);
	    }
#endif
	    chdir(tmpdir);

	    if(printinfected) {
  	        fdevnull = open("/dev/null", O_WRONLY);
		if(fdevnull == -1) {
		    mprintf("Non fatal error: cannot open /dev/null. Continuing with full output\n");
		    printinfected = 0;
		} else {
		    dup2(fdevnull,1);
		    dup2(fdevnull,2);
		}
	    }

	    if(strchr(prog, '/')) /* we have full path */
		execv(prog, args);
	    else
		execvp(prog, args);
	    perror("execv(p)");
	    abort();
	    break;
	default:

	    if(maxfiles || maxspace) {
		while(!(wret = waitpid(pid, &status, WNOHANG))) {
		    memset(&n, 0, sizeof(struct s_du));

		    if(!du(tmpdir, &n))
			if((maxfiles && n.files > maxfiles) || (maxspace && n.space > maxspace)) {
			    mprintf("*n.files: %d, n.space: %d\n", n.files, n.space);
			    kill(pid, 9); /* stop it immediately */
			}
		}
	    } else
		waitpid(pid, &status, 0);


	    if(WIFSIGNALED(status)) {
		switch(WTERMSIG(status)) {

		    case 9:
			mprintf("\nUnpacker process %d stopped due to exceeded limits.\n", pid);
			return 0;
		    case 6: /* abort */
			mprintf("@Can't run %s\n", prog);
			return -2;
		    default:
			mprintf("@\nUnpacker stopped with external signal %d\n", WTERMSIG(status));
			return -3;
		}
	    } else if(WIFEXITED(status))
		return 0;
    }

    return 0;
}

void move_infected(const char *filename, const struct optstruct *opt)
{
    char *movedir, *movefilename, *tmp;
    struct stat fstat, mfstat;

    if(!(movedir = getargl(opt, "move")))
    {
        /* Should never reach here */
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: getargc() returned NULL.\n");
        logg("clamscan: getargc() returned NULL.\n");
        claminfo.notmoved++;
        return;
    }

    if(access(movedir, W_OK|X_OK) == -1)
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: cannot write to '%s': %s.\n", movedir, strerror(errno));
        logg("clamscan: cannot write to '%s': %s.\n", movedir, strerror(errno));
        claminfo.notmoved++;
        return;
    }
    
    if(!(tmp = strrchr(filename, '/')))
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: '%s' does not appear to be a valid filename.\n", filename);
        logg("clamscan: '%s' does not appear to be a valid filename.\n", filename);
        claminfo.notmoved++;
        return;
    }
    
    if(!(movefilename = malloc(sizeof(char) * (strlen(movedir) + strlen(tmp) + 1))))
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: malloc() returned NULL.\n");
        logg("clamscan: malloc() returned NULL.\n");
        claminfo.notmoved++;
        return;
    }
    
    if(!(strrcpy(movefilename, movedir)))
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: strrcpy() returned NULL.\n");
        logg("clamscan: strrcpy() returned NULL.\n");
        claminfo.notmoved++;
        free(movefilename);
        return;
    }
    
    if(!(strcat(movefilename, tmp)))
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: strcat() returned NULL.\n");
        logg("clamscan: strcat() returned NULL.\n");
        claminfo.notmoved++;
        free(movefilename);
        return;
    }
    
    stat(filename, &fstat);

    if(!stat(movefilename, &mfstat))
    {
        if(fstat.st_ino == mfstat.st_ino) { /* It's the same file*/
            mprintf("clamscan: file excluded '%s'.\n", filename);
            logg("clamscan: file excluded '%s'.\n", filename);
            claminfo.notmoved++;
            free(movefilename);
            return;
        }
    }
    
    if(filecopy(filename, movefilename) == -1)
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: cannot move '%s' to '%s': %s.\n", filename, movefilename, strerror(errno));
        logg("clamscan: cannot move '%s' to '%s': %s.\n", filename, movefilename, strerror(errno));
        claminfo.notmoved++;
        free(movefilename);
        return;
    }

    chmod(movefilename, fstat.st_mode);
    chown(movefilename, fstat.st_uid, fstat.st_gid);
    
    if(unlink(filename))
    {
        mprintf("@error moving file '%s'.\n", filename);
        mprintf("clamscan: cannot unlink '%s': %s.\n", filename, strerror(errno));
        logg("clamscan: cannot unlink '%s': %s.\n", filename, strerror(errno));
        claminfo.notremoved++;            
    }
    else
    {
        mprintf("%s: moved to '%s'.\n", filename, movefilename);
        logg("%s: moved to '%s'.\n", filename, movefilename);
    }

    free(movefilename);
}
