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
 */

/* some things may need to be tuned here (look at jmp variables) */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <time.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <clamav.h>
#include <sys/wait.h>
#include <dirent.h>

#include "options.h"
#include "others.h"
#include "strings.h"
#include "md5.h"
#include "cvd.h"
#include "str.h"
#include "memory.h"
#include "output.h"

#define LINE 1024

#define MIN_LENGTH 15
#define MAX_LENGTH 200

void help(void);
char *getdsig(const char *host, const char *user, const char *data);
void cvdinfo(struct optstruct *opt);
int build(struct optstruct *opt);
int unpack(struct optstruct *opt);
int listdb(const char *filename);
int listdir(const char *dirname);
void listsigs(struct optstruct *opt);
int cli_rmdirs(const char *dirname); /* libclamav's internal */

int scanfile(const char *cmd, const char *str, const char *file)
{
	FILE *pd;
	char *command, buffer[LINE];


    /* build the command */
    command = (char *) mcalloc(strlen(cmd) + strlen(file) + 10, sizeof(char));
    sprintf(command, "%s %s", cmd, file);

    if((pd = popen(command, "r")) == NULL) {
	mprintf("!popen() failed\n");
	return 3;
    }

    while(fgets(buffer, LINE, pd)) {
	if(strstr(buffer, str)) {
	    free(command);
            fclose(pd);
	    return 1; /* found */
	}
    }

    free(command);
    fclose(pd);
    return 0; /* substring not found */
}

char *cut(const char *file, long int start, long int end)
{
	char *fname = NULL, buffer[FILEBUFF];
	int bytes, size, sum;
	FILE *rd, *wd;


    if((rd = fopen(file, "rb")) == NULL) {
	mprintf("!File %s doesn't exist.\n", file);
	exit(13);
    }

    if((fname = cl_gentemp(".")) == NULL) {
	mprintf("!Can't generate temporary file name.\n");
	exit(1);
    }

    if((wd = fopen(fname, "wb")) == NULL) {
	mprintf("!Can't create temporary file %s\n", fname);
	exit(14);
    }

    fseek(rd, start, SEEK_SET);

    size = end - start;
    sum = 0;

    while((bytes = fread(buffer, 1, FILEBUFF, rd)) > 0) {
	if(sum + bytes >= size) {
	    fwrite(buffer, 1, size - sum, wd);
	    break;
	} else
	    fwrite(buffer, 1, bytes, wd);

	sum += bytes;
    }

    fclose(rd);
    fclose(wd);

    return fname;
}

char *change(const char *file, long int x)
{
	char *fname = NULL, buffer[FILEBUFF];
	int bytes, ch;
	FILE *rd, *wd;


    if((rd = fopen(file, "rb")) == NULL) {
	mprintf("!File %s doesn't exist.\n", file);
	exit(13);
    }

    if((fname = cl_gentemp(".")) == NULL) {
	mprintf("!Can't generate temporary file name.\n");
	exit(1);
    }

    if((wd = fopen(fname, "wb+")) == NULL) {
	mprintf("!Can't create temporary file %s\n", fname);
	exit(14);
    }

    while((bytes = fread(buffer, 1, FILEBUFF, rd)) > 0)
	fwrite(buffer, 1, bytes, wd);

    fclose(rd);

    if(x) { /* don't alter first character in the file */
	fflush(wd);
	fseek(wd, x, SEEK_SET);
	ch = fgetc(wd);
	fseek(wd, -1, SEEK_CUR);
	fputc(++ch, wd);
    }

    fclose(wd);
    return fname;
}

void sigtool(struct optstruct *opt)
{
	    char buffer[FILEBUFF];
	    int bytes;
	    char *pt;


    if(optl(opt, "quiet")) mprintf_quiet = 1;
    else mprintf_quiet = 0;

    if(optl(opt, "stdout")) mprintf_stdout = 1;
    else mprintf_stdout = 0;

    if(optl(opt, "debug"))
	cl_debug();

    if(optc(opt, 'V')) {
	mprintf("sigtool / ClamAV version "VERSION"\n");
	exit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    if(optl(opt, "hex-dump")) {

	while((bytes = read(0, buffer, FILEBUFF)) > 0) {
	    pt = cl_str2hex(buffer, bytes);
	    write(1, pt, 2 * bytes);
	    free(pt);
	}

    } else if(optc(opt, 'b')) {
	if(!optl(opt, "server")) {
	    mprintf("!--server is required in this mode\n");
	    exit(10);
	}

	build(opt);

    } else if(optc(opt, 'u')) {

	unpack(opt);

    } else if(optl(opt, "unpack-current")) {

	unpack(opt);

    } else if(optc(opt, 'i')) {

	cvdinfo(opt);

    } else if(optc(opt, 'l')) {

	listsigs(opt);

    } else {
	    int jmp, lastjmp = 0, end, found = 0, exec = 0, pos, filesize,
		maxsize = 0, ret;
	    char *c, *s, *f, *tmp, *signame, *bsigname, *f2 = NULL;
	    FILE *fd, *wd;

	if(!optc(opt, 'c')) {
	    mprintf("!--command, -c is required in this mode\n");
	    exit(10);
	} else if(!optc(opt, 's')) {
	    mprintf("!--string, -s is required in this mode\n");
	    exit(10);
	} else if(!optc(opt, 'f')) {
	    mprintf("!--file, -f is required in this mode\n");
	    exit(10);
	}

	/* these are pointers to corresponding strings in option list */
	c = getargc(opt, 'c');
	s = getargc(opt, 's');
	f = getargc(opt, 'f');

	if(scanfile(c, s, f) != 1) {
	    mprintf("!String %s not found in scanner's output.\n", s);
	    mprintf("Please check it and try again.\n");
	    mprintf("Does the scanner write to stdout ? It has to.\n");
	    exit(11);
	}

	/* initial values */
	filesize = end = fileinfo(f, 1);
	jmp = end / 5 + 1;

	/* find signature end */
	while(1) {
	    tmp = cut(f, 0, end);
	    exec++;
	    ret = scanfile(c, s, tmp);
	    unlink(tmp);
	    free(tmp);

	    if(ret == 1) {

		if(end >= jmp) {
		    mprintf("Detected, decreasing end %d -> %d\n", end, end - jmp);
		    end -= jmp;
		} else
		    end = 0;

	    } else {
		mprintf("Not detected at %d, moving forward.\n", end);
		if(jmp == 1) {

		    while(end <= filesize) {
			tmp = cut(f, 0, end);
			exec++;
			if(scanfile(c, s, tmp) == 1) {
			    mprintf(" *** Signature end found at %d\n", end);
			    found = 1;
			    f2 = strdup(tmp); /* remember this file */
			    free(tmp);
			    break;
			} else {
			    unlink(tmp);
			    free(tmp);
			    mprintf("Increasing end %d -> %d\n", end, end + 1);
			}
			end++;
		    }

		    if(found) break;
		}

		if(jmp)
		    jmp--;
		jmp = jmp/2 + 1;
		end += jmp;
		if(end > filesize)
		    end = filesize;

	    }

	}

	/* find signature start */
	found = 0;
	jmp = 50;
	pos = end - jmp;

	while(1) {

	    tmp = change(f2, pos);
	    if(scanfile(c, s, tmp) != 1) {
		exec++;
		unlink(tmp);
		free(tmp);

		if(pos >= jmp) {
		    mprintf("Not detected, moving backward %d -> %d\n", pos, pos - jmp);
		    pos -= jmp;
		    maxsize += jmp;
		} else {
		    mprintf("Not detected, using the beginning of the file.\n");
		    pos = 0;
		    break;
		}

		if(maxsize > MAX_LENGTH) {
		    mprintf("!Generated signature is too big.\n");
		    unlink(f2);
		    free(f2);
		    exit(1);
		}

	    } else {
		mprintf("Detected at %d, moving forward.\n", pos);
		if(jmp == 1 && lastjmp == 1) {
		    unlink(tmp);
		    free(tmp);
		    while(pos < end) {
			tmp = change(f2, pos);
			exec++;
			ret = scanfile(c, s, tmp);
			unlink(tmp);
			free(tmp);
			if(ret == 1) {
			    mprintf("Moving forward %d -> %d\n", pos, pos + 1);
			    pos++;

			    if(end - pos < MIN_LENGTH) {
				mprintf("!Generated signature is too small.\n");
				unlink(f2);
				free(f2);
				exit(1);
			    }

			} else {
			    mprintf(" *** Signature start found at %d\n", pos);
			    found = 1;
			    break;
			}
		    }

		    if(pos >= end) {
		        mprintf("!Can't generate a proper signature.\n");
			unlink(f2);
			free(f2);
		        exit(1);
		    }

		    if(found)
			break;
		}

		lastjmp = jmp;
		if(jmp > 0)
		    jmp--;
		jmp = jmp/2 + 1;
		pos += jmp;

		if(pos >= end - 2 * jmp)
		    pos = end - 2 * jmp;

		unlink(tmp);
		free(tmp);
	    }

	}

	unlink(f2);
	free(f2);
	tmp = cut(f, pos, end);

	mprintf("\nThe scanner was executed %d times.\n", exec);
	mprintf("The signature length is %d (%d hex)\n", end - pos, 2 * (end - pos));

	if(end - pos < MIN_LENGTH) {
	    mprintf("\nWARNING: THE SIGNATURE IS TOO SMALL (PROBABLY ONLY A PART OF A REAL SIGNATURE).\n");
	    mprintf("         PLEASE DON'T USE IT.\n\n");
	}

	if((fd = fopen(tmp, "rb")) == NULL) {
	    mprintf("!Can't believe. Where is my signature, dude ?\n");
	    exit(99);
	}

	signame = (char *) mcalloc(strlen(f) + 10, sizeof(char));
	sprintf(signame, "%s.sig", f);
	if(fileinfo(signame, 1) != -1) {
	    mprintf("File %s exists.\n", signame);
	    free(signame);
	    signame = cl_gentemp(".");
	}

	bsigname = (char *) mcalloc(strlen(f) + 10, sizeof(char));
	sprintf(bsigname, "%s.bsig", f);
	if(fileinfo(bsigname, 1) != -1) {
	    mprintf("File %s exists.\n", bsigname);
	    free(bsigname);
	    bsigname = cl_gentemp(".");
	}

	if((wd = fopen(signame, "wb")) == NULL) {
	    mprintf("Can't write to %s\n", signame);
	    unlink(tmp);
	    free(tmp);
	    exit(15);
	}

	mprintf("Saving signature in %s file.\n", signame);

	while((bytes = fread(buffer, 1, FILEBUFF, fd)) > 0) {
	    pt = cl_str2hex(buffer, bytes);
	    fwrite(pt, 1, 2 * bytes, wd);
	    free(pt);
	}

	mprintf("Saving binary signature in %s file.\n", bsigname);
	rename(tmp, bsigname);

	fclose(fd);
	fclose(wd);
	free(tmp);
	free(signame);
	free(bsigname);
    }

    /* free_opt(opt); */
}

int countlines(const char *filename)
{
	FILE *fd;
	char buff[65536];
	int lines = 0;

    if((fd = fopen(filename, "r")) == NULL)
	return 0;

    while(fgets(buff, sizeof(buff), fd))
	lines++;

    fclose(fd);
    return lines;
}

int build(struct optstruct *opt)
{
	int ret, no = 0, realno = 0, bytes, itmp;
	struct stat foo;
	char buffer[FILEBUFF], *tarfile = NULL, *gzfile = NULL, header[257],
	     smbuff[30], *pt;
        struct cl_node *root = NULL;
	FILE *tar, *cvd, *fd;
	gzFile *gz;
	time_t timet;
	struct tm *brokent;
	struct cl_cvd *oldcvd = NULL;

    /* build a tar.gz archive
     * we need: COPYING and {viruses.db, viruses.db2}+
     * in current working directory
     */

    if(stat("COPYING", &foo) == -1) {
	mprintf("COPYING file not found in current working directory.\n");
	exit(1);
    }

    if(stat("viruses.db", &foo) == -1 && stat("viruses.db2", &foo) == -1) {
	mprintf("Virus database not found in current working directory.\n");
	exit(1);
    }

    cl_debug(); /* enable debug messages */

    if((ret = cl_loaddbdir(".", &root, &no))) {
	mprintf("!Can't load database: %s\n", cl_strerror(ret));
	exit(1);
    }

    cl_freetrie(root);

    mprintf("Database properly parsed.\n");

    if(!no) {
	mprintf("WARNING: There are no signatures in the database(s).\n");
    } else {
	mprintf("Signatures: %d\n", no);
	realno = countlines("viruses.db") + countlines("viruses.db2");

	if(realno != no) {
	    mprintf("!Signatures in database: %d. Loaded: %d.\n", realno, no);
	    mprintf("Please check the current directory and remove unnecessary databases\n");
	    mprintf("or install the latest ClamAV version.\n");
	    exit(1);
	}
    }

    tarfile = cl_gentemp(".");

    switch(fork()) {
	case -1:
	    mprintf("!Can't fork.\n");
	    exit(1);
	case 0:
	    {
		char *args[] = { "tar", "-cvf", tarfile, "COPYING", "viruses.db", "viruses.db2", "Notes", NULL };
		execv("/bin/tar", args);
		mprintf("!Can't execute tar\n");
		perror("tar");
		exit(1);
	    }
	default:
	    wait(NULL);
    }

    if(stat(tarfile, &foo) == -1) {
	mprintf("!Can't generate tar file.\n");
	exit(1);
    }

    if((tar = fopen(tarfile, "rb")) == NULL) {
	mprintf("!Can't open file %s\n", tarfile);
	exit(1);
    }

    gzfile = cl_gentemp(".");
    if((gz = gzopen(gzfile, "wb")) == NULL) {
	mprintf("!Can't open file %s to write.\n", gzfile);
	exit(1);
    }

    while((bytes = fread(buffer, 1, FILEBUFF, tar)) > 0)
	gzwrite(gz, buffer, bytes);

    fclose(tar);
    unlink(tarfile);
    free(tarfile);

    gzclose(gz);


    /* try to read cvd header of old database */
    sprintf(buffer, "%s/%s", cl_retdbdir(), getargc(opt, 'b'));
    if((oldcvd = cl_cvdhead(buffer)) == NULL)
	mprintf("WARNING: CAN'T READ CVD HEADER OF CURRENT DATABASE %s\n", buffer);

    /* generate header */

    /* magic string */

    strcpy(header, "ClamAV-VDB:");

    /* time */

    time(&timet);
    brokent = localtime(&timet);
    setlocale(LC_TIME, "C");
    strftime(smbuff, 30, "%d %b %Y %H-%M %z", brokent);
    strcat(header, smbuff);

    /* version number */

    /* ... increment version number by one */

    if(oldcvd) {
	sprintf(smbuff, ":%d:", oldcvd->version + 1);
    } else {
	fflush(stdin);
	mprintf("Version number: ");
	scanf("%d", &itmp);
	sprintf(smbuff, "%d:", itmp);
    }
    strcat(header, smbuff);

    /* number of signatures */
    sprintf(smbuff, "%d:", no);
    strcat(header, smbuff);

    /* functionality level (TODO: use cl_funclevel()) */
    sprintf(smbuff, "%d:", 1);
    strcat(header, smbuff);

    /* MD5 */
    pt = cl_md5file(gzfile);
    strcat(header, pt);
    free(pt);
    strcat(header, ":");

    /* builder - question */
    fflush(stdin);
    mprintf("Builder id: ");
    fscanf(stdin, "%s", smbuff);

    /* digital signature */
    fd = fopen(gzfile, "rb");
    __md5_stream(fd, &buffer);
    fclose(fd);
    if(!(pt = getdsig(getargl(opt, "server"), smbuff, buffer))) {
	mprintf("No digital signature - no CVD file...\n");
	unlink(gzfile);
	exit(1);
    }

    strcat(header, pt);
    free(pt);
    strcat(header, ":");

    /* builder - add */
    strcat(header, smbuff);

    /* fill up with spaces */

    while(strlen(header) < 512)
	strcat(header, " ");

    /* build the final database */

    pt = getargc(opt, 'b');
    if((cvd = fopen(pt, "wb")) == NULL) {
	mprintf("!Can't write the final database %s\n", pt);
	unlink(gzfile);
	exit(1);
    }

    fwrite(header, 1, 512, cvd);

    if((tar = fopen(gzfile, "rb")) == NULL) {
	mprintf("!Can't open file %s for reading.\n", gzfile);
	exit(1);
    }

    while((bytes = fread(buffer, 1, FILEBUFF, tar)) > 0)
	fwrite(buffer, 1, bytes, cvd);

    fclose(tar);
    fclose(cvd);

    unlink(gzfile);
    free(gzfile);

    mprintf("Database %s created.\n", pt);

    /* try to load final cvd */
    return 0;
}

void cvdinfo(struct optstruct *opt)
{
	struct cl_cvd *cvd;
	char *pt;
	int ret;

    pt = getargc(opt, 'i');
    if((cvd = cl_cvdhead(pt)) == NULL) {
	mprintf("!Can't read/parse CVD header from %s\n", pt);
	exit(1);
    }

    mprintf("Build time: %s\n", cvd->time);
    mprintf("Version: %d\n", cvd->version);
    mprintf("# of signatures: %d\n", cvd->sigs);
    mprintf("Functionality level: %d\n", cvd->fl);
    mprintf("Builder: %s\n", cvd->builder);
    mprintf("MD5: %s\n", cvd->md5);

    mprintf("Digital signature: %s\n", cvd->dsig);

#ifndef HAVE_GMP
    mprintf("Digital signature support not compiled in.\n");
#endif

    if((ret = cl_cvdverify(pt)))
	mprintf("!Verification: %s\n", cl_strerror(ret));
    else
	mprintf("Verification OK.\n");

    /* free */
}

char *getdsig(const char *host, const char *user, const char *data)
{
	char buff[300], cmd[100], *pass, *pt;
        struct sockaddr_in server;
	int sockd, bread, len;


#ifdef PF_INET
    if((sockd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#else
    if((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
#endif
	perror("socket()");
	mprintf("!Can't create the socket.\n");
	return NULL;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(33101);

    if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) < 0) {
        close(sockd);
	perror("connect()");
	mprintf("!Can't connect to ClamAV Signing Service at %s.\n", host);
	return NULL;
    }

    memset(cmd, 0, sizeof(cmd));
    pass = getpass("Password:");
    sprintf(cmd, "ClamSign:%s:%s:", user, pass);
    len = strlen(cmd);
    pt = cmd;
    pt += len;
    memcpy(pt, data, 16);
    len += 16;

    if(write(sockd, cmd, len) < 0) {
	mprintf("!Can't write to the socket.\n");
	close(sockd);
	memset(cmd, 0, len);
	memset(pass, 0, strlen(pass));
	return NULL;
    }

    memset(cmd, 0, len);
    memset(pass, 0, strlen(pass));

    memset(buff, 0, sizeof(buff));
    if((bread = read(sockd, buff, sizeof(buff))) > 0) {
	if(!strstr(buff, "Signature:")) {
	    mprintf("!Signature generation error.\n");
	    mprintf("ClamAV SDaemon: %s.\n", buff);
	    close(sockd);
	    return NULL;
	} else {
	    mprintf("Signature received (length = %d).\n", strlen(buff) - 10);
	}
    }

    close(sockd);
    pt = buff;
    pt += 10;
    return strdup(pt);
}

int unpack(struct optstruct *opt)
{
	FILE *fd;
	char *name;

    if(optl(opt, "unpack-current")) {
	name = mcalloc(300, sizeof(char)); /* FIXME */
	sprintf(name, "%s/%s", cl_retdbdir(), getargl(opt, "unpack-current"));
    } else
	name = getargc(opt, 'u');

    if((fd = fopen(name, "rb")) == NULL) {
	mprintf("!Can't open CVD file %s\n", name);
	exit(1);
    }

    fseek(fd, 512L, SEEK_SET);

    if(cli_untgz(fileno(fd), ".")) {
	mprintf("!Can't unpack file.\n");
	fclose(fd);
	exit(1);
    }

    fclose(fd);
    exit(0);
}

int listdb(const char *filename)
{
	FILE *fd, *tmpd;
	char *buffer, *pt, *start, *dir, *tmp;
	int line = 0, bytes;
	const char *tmpdir;


    if((fd = fopen(filename, "rb")) == NULL) {
	mprintf("!listdb(): Can't open file %s\n", filename);
	return -1;
    }

    if(!(buffer = (char *) mmalloc(FILEBUFF))) {
	mprintf("!listdb(): Can't allocate memory.\n");
	return -1;
    }

    memset(buffer, 0, FILEBUFF);
    /* check for CVD file */
    fgets(buffer, 12, fd);
    rewind(fd);

    if(!strncmp(buffer, "ClamAV-VDB:", 11)) {

	fseek(fd, 512, SEEK_SET);

	tmpdir = getenv("TMPDIR");
	if(tmpdir == NULL)
#ifdef P_tmpdir
	    tmpdir = P_tmpdir;
#else
	    tmpdir = "/tmp";
#endif

	dir = cl_gentemp(tmpdir);
	if(mkdir(dir, 0700)) {
	    mprintf("!listdb(): Can't create temporary directory %s\n", dir);
	    free(buffer);
	    fclose(fd);
	    return -1;
	}

	/* FIXME: it seems there is some problem with current position indicator
	* after gzdopen() call in cli_untgz(). Temporarily we need this wrapper:
	*/

	/* start */

	tmp = cl_gentemp(tmpdir);
	if((tmpd = fopen(tmp, "wb+")) == NULL) {
	    mprintf("!listdb(): Can't create temporary file %s\n", tmp);
	    free(dir);
	    free(tmp);
	    free(buffer);
	    fclose(fd);
	    return -1;
	}

	while((bytes = fread(buffer, 1, FILEBUFF, fd)) > 0)
	    fwrite(buffer, 1, bytes, tmpd);

	free(buffer);
	fclose(fd);

	fflush(tmpd);
	fseek(tmpd, 0L, SEEK_SET);

	if(cli_untgz(fileno(tmpd), dir)) {
	    mprintf("!listdb(): Can't unpack CVD file.\n");
	    cli_rmdirs(dir);
	    free(dir);
	    unlink(tmp);
	    free(tmp);
	    free(buffer);
	    return -1;
	}

	fclose(tmpd);
	unlink(tmp);
	free(tmp);

	/* wrapper end */

	/* list extracted directory */
	listdir(dir);

	cli_rmdirs(dir);
	free(dir);

	return 0;
    }


    /* old style database */

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;
	pt = strchr(buffer, '=');
	if(!pt) {
	    mprintf("!listdb(): Malformed pattern line %d (file %s).\n", line, filename);
	    fclose(fd);
	    free(buffer);
	    return -1;
	}

	start = buffer;
	*pt = 0;

	if((pt = strstr(start, " (Clam)")))
	    *pt = 0;

	mprintf("%s\n", start);
    }

    fclose(fd);
    free(buffer);
    return 0;
}

int listdir(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	char *dbfile;


    if((dd = opendir(dirname)) == NULL) {
        mprintf("!Can't open directory %s\n", dirname);
        return -1;
    }

    while((dent = readdir(dd))) {
	if(dent->d_ino) {
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")  ||
	     cli_strbcasestr(dent->d_name, ".db2") ||
	     cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbfile = (char *) mcalloc(strlen(dent->d_name) + strlen(dirname) + 2, sizeof(char));

		if(!dbfile) {
		    mprintf("!listdir(): Can't allocate memory.\n");
		    closedir(dd);
		    return -1;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);

		if(listdb(dbfile)) {
		    mprintf("!listdb(): error listing database %s\n", dbfile);
		    free(dbfile);
		    closedir(dd);
		    return -1;
		}
		free(dbfile);
	    }
	}
    }

    closedir(dd);
    return 0;
}

void listsigs(struct optstruct *opt)
{
	int ret;
	const char *name;

    mprintf_stdout = 1;

    if((name = getargc(opt, 'l')))
	ret = listdb(name);
    else
	ret = listdir(cl_retdbdir());

    ret ? exit(1) : exit(0);
}

void help(void)
{
    mprintf("\n");
    mprintf("                Clam AntiVirus: Signature Tool (sigtool)  "VERSION"\n");
    mprintf("                (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>\n\n");

    mprintf("    --help                 -h              show help\n");
    mprintf("    --version              -V              print version number and exit\n");
    mprintf("    --quiet                                be quiet, output only error messages\n");
    mprintf("    --debug                                enable debug messages\n");
    mprintf("    --stdout                               write to stdout instead of stderr\n");
    mprintf("                                           (this help is always written to stdout)\n");
    mprintf("    --hex-dump                             convert data from stdin to a hex\n");
    mprintf("                                           string and print it on stdout\n");
    mprintf("    --command              -c              scanner command string, with options\n");
    mprintf("    --string               -s              'virus found' string in scan. output\n");
    mprintf("    --file                 -f              infected file\n");
    mprintf("    --info=FILE            -i FILE         print database information\n");
    mprintf("    --build=NAME           -b NAME         build a CVD file\n");
    mprintf("    --server=ADDR                          ClamAV Signing Service address\n");
    mprintf("    --unpack=FILE          -u FILE         Unpack a CVD file\n");
    mprintf("    --unpack-current=NAME                  Unpack local CVD\n");
    mprintf("    --list-sigs[=FILE]     -l[FILE]        List signature names\n");
    mprintf("\n");

    exit(0);
}
