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
#include <sys/stat.h>
#include <fcntl.h>
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
#include "cfgparser.h"
#include "misc.h"
#include "../clamscan/others.h"
#include "../libclamav/others.h"
#include "../libclamav/str.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

void help(void);
char *getdsig(const char *host, const char *user, const char *data);
void cvdinfo(struct optstruct *opt);
int build(struct optstruct *opt);
int unpack(struct optstruct *opt);
int listdb(const char *filename);
int listdir(const char *dirname);
void listsigs(struct optstruct *opt);


void sigtool(struct optstruct *opt)
{

    if(optl(opt, "quiet"))
	mprintf_quiet = 1;

    if(optl(opt, "stdout"))
	mprintf_stdout = 1;

    if(optl(opt, "debug"))
	cl_debug();

    if(optc(opt, 'V')) {
	print_version();
	exit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    if(optl(opt, "hex-dump")) {
	    char buffer[FILEBUFF];
	    int bytes;
	    char *pt;

	while((bytes = read(0, buffer, FILEBUFF)) > 0) {
	    pt = cli_str2hex(buffer, bytes);
	    write(1, pt, 2 * bytes);
	    free(pt);
	}

    } else if(optl(opt, "md5")) {
	    char *md5, *filename;
	    int i;
	    struct stat sb;

	mprintf_stdout = 1;

	if(opt->filename) {

	    for(i = 0; (filename = cli_strtok(opt->filename, i, "\t")); i++) {
		if(stat(filename, &sb) == -1) {
		    mprintf("!Can't access file %s\n", filename);
		    perror(filename);
		} else {
		    if((sb.st_mode & S_IFMT) == S_IFREG) {
			if((md5 = cli_md5file(filename))) {
			    mprintf("%s:%d:%s\n", md5, sb.st_size, filename);
			    free(md5);
			} else
			    mprintf("!Can't generate MD5 checksum for %s\n", filename);
		    }
		}

		free(filename);
	    }

	} else {

	    md5 = cli_md5stream(stdin, NULL);
	    mprintf("%s\n", md5);
	    free(md5);
	}

    } else if(optl(opt, "html-normalise")) {
	    int fd;

	if((fd = open(getargl(opt, "html-normalise"), O_RDONLY)) == -1) {
	    mprintf("Can't open file %s\n", getargl(opt, "html-normalise"));
	    exit(1);
	}

	html_normalise_fd(fd, ".", NULL);

	close(fd);

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

	help();
    }

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
	char buffer[FILEBUFF], *tarfile = NULL, *gzfile = NULL, header[512],
	     smbuff[30], *pt;
        struct cl_node *root = NULL;
	FILE *tar, *cvd, *fd;
	gzFile *gz;
	time_t timet;
	struct tm *brokent;
	struct cl_cvd *oldcvd = NULL;


    if(stat("COPYING", &foo) == -1) {
	mprintf("COPYING file not found in current working directory.\n");
	exit(1);
    }

    if(stat("main.db", &foo) == -1 && stat("daily.db", &foo) == -1 && stat("main.hdb", &foo) == -1 && stat("daily.hdb", &foo) == -1 && stat("main.ndb", &foo) == -1 && stat("daily.ndb", &foo) == -1) {
	mprintf("Virus database not found in current working directory.\n");
	exit(1);
    }

    cl_debug(); /* enable debug messages */

    if((ret = cl_loaddbdir(".", &root, &no))) {
	mprintf("!Can't load database: %s\n", cl_strerror(ret));
	exit(1);
    }

    cl_free(root);

    mprintf("Database properly parsed.\n");

    if(!no) {
	mprintf("WARNING: There are no signatures in the database(s).\n");
    } else {
	mprintf("Signatures: %d\n", no);
	realno = countlines("main.db") + countlines("daily.db") + countlines("main.hdb") + countlines("daily.hdb") + countlines("main.ndb") + countlines("daily.ndb");
	if(realno != no) {
	    mprintf("!Signatures in database: %d. Loaded: %d.\n", realno, no);
	    mprintf("Please check the current directory and remove unnecessary databases\n");
	    mprintf("or install the latest ClamAV version.\n");
	    exit(1);
	}
    }

    tarfile = cli_gentemp(".");

    switch(fork()) {
	case -1:
	    mprintf("!Can't fork.\n");
	    exit(1);
	case 0:
	    {
		char *args[] = { "tar", "-cvf", NULL, "COPYING", "main.db", "daily.db", "Notes", "viruses.db3", "main.hdb", "daily.hdb", "main.ndb", "daily.ndb", NULL };
		args[2] = tarfile;
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

    gzfile = cli_gentemp(".");
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
    sprintf(buffer, "%s/%s", freshdbdir(), getargc(opt, 'b'));
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

    /* functionality level */
    sprintf(smbuff, "%d:", cl_retflevel());
    strcat(header, smbuff);

    /* MD5 */
    pt = cli_md5file(gzfile);
    strcat(header, pt);
    free(pt);
    strcat(header, ":");

    /* ask for builder name */
    fflush(stdin);
    mprintf("Builder id: ");
    fscanf(stdin, "%s", smbuff);

    /* digital signature */
    fd = fopen(gzfile, "rb");
    pt = cli_md5stream(fd, buffer);
    fclose(fd);
    free(pt);
    if(!(pt = getdsig(getargl(opt, "server"), smbuff, buffer))) {
	mprintf("No digital signature - no CVD file...\n");
	unlink(gzfile);
	exit(1);
    }

    strcat(header, pt);
    free(pt);
    strcat(header, ":");

    /* add builder */
    strcat(header, smbuff);

    /* add current time */
    sprintf(header + strlen(header), ":%d", (int) timet);

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
	int fd;
	char *name;

    if(optl(opt, "unpack-current")) {
	name = mcalloc(strlen(freshdbdir()) + strlen(getargl(opt, "unpack-current")) + 2, sizeof(char));
	sprintf(name, "%s/%s", freshdbdir(), getargl(opt, "unpack-current"));
    } else
	name = strdup(getargc(opt, 'u'));

    if((fd = open(name, O_RDONLY|O_BINARY)) == -1) {
	mprintf("!Can't open CVD file %s\n", name);
	free(name);
	exit(1);
    }

    free(name);
    lseek(fd, 512, SEEK_SET);

    if(cli_untgz(fd, ".")) {
	mprintf("!Can't unpack file.\n");
	close(fd);
	exit(1);
    }

    close(fd);
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
	fclose(fd);
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

	dir = cli_gentemp(tmpdir);
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

	tmp = cli_gentemp(tmpdir);
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
	    fclose(tmpd);
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

    if(cli_strbcasestr(filename, ".db") || cli_strbcasestr(filename, ".db2")) {
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

    } else if(cli_strbcasestr(filename, ".hdb")) {

	while(fgets(buffer, FILEBUFF, fd)) {
	    line++;
	    cli_chomp(buffer);
	    start = cli_strtok(buffer, 2, ":");

	    if(!start) {
		mprintf("!listdb(): Malformed pattern line %d (file %s).\n", line, filename);
		fclose(fd);
		free(buffer);
		return -1;
	    }

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    mprintf("%s\n", start);
	    free(start);
	}

    } else if(cli_strbcasestr(filename, ".ndb")) {

	while(fgets(buffer, FILEBUFF, fd)) {
	    line++;
	    cli_chomp(buffer);
	    start = cli_strtok(buffer, 0, ":");

	    if(!start) {
		mprintf("!listdb(): Malformed pattern line %d (file %s).\n", line, filename);
		fclose(fd);
		free(buffer);
		return -1;
	    }

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    mprintf("%s\n", start);
	    free(start);
	}
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
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")  ||
	     cli_strbcasestr(dent->d_name, ".db2") ||
	     cli_strbcasestr(dent->d_name, ".hdb") ||
	     cli_strbcasestr(dent->d_name, ".ndb") ||
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
	ret = listdir(freshdbdir());

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
    mprintf("    --hex-dump                             convert data from stdin to a hex\n");
    mprintf("                                           string and print it on stdout\n");
    mprintf("    --md5 [FILES]                          generate MD5 checksum from stdin\n");
    mprintf("                                           or MD5 sigs for FILES\n");
    mprintf("    --html-normalise=FILE                  create normalised parts of HTML file\n");
    mprintf("    --info=FILE            -i FILE         print database information\n");
    mprintf("    --build=NAME           -b NAME         build a CVD file\n");
    mprintf("    --server=ADDR                          ClamAV Signing Service address\n");
    mprintf("    --unpack=FILE          -u FILE         Unpack a CVD file\n");
    mprintf("    --unpack-current=NAME                  Unpack local CVD\n");
    mprintf("    --list-sigs[=FILE]     -l[FILE]        List signature names\n");
    mprintf("\n");

    exit(0);
}
