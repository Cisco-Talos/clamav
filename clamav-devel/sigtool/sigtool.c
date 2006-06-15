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

#include "vba.h"

#include "shared/options.h"
#include "shared/memory.h"
#include "shared/output.h"
#include "shared/cfgparser.h"
#include "shared/misc.h"

#include "libclamav/cvd.h"
#include "libclamav/others.h"
#include "libclamav/str.h"
#include "libclamav/ole2_extract.h"
#include "libclamav/htmlnorm.h"


static int hexdump(void)
{
	char buffer[FILEBUFF], *pt;
	int bytes;


    while((bytes = read(0, buffer, FILEBUFF)) > 0) {
	pt = cli_str2hex(buffer, bytes);
	if(write(1, pt, 2 * bytes) == -1) {
	    logg("!hexdump: Can't write to stdout\n");
	    free(pt);
	    return -1;
	}
	free(pt);
    }

    if(bytes == -1)
	return -1;

    return 0;
}

static int md5sig(struct optstruct *opt)
{
	char *md5, *filename;
	int i;
	struct stat sb;


    if(opt->filename) {
	for(i = 0; (filename = cli_strtok(opt->filename, i, "\t")); i++) {
	    if(stat(filename, &sb) == -1) {
		logg("!md5sig: Can't access file %s\n", filename);
		perror("md5sig");
		free(filename);
		return -1;
	    } else {
		if((sb.st_mode & S_IFMT) == S_IFREG) {
		    if((md5 = cli_md5file(filename))) {
			logg("%s:%d:%s\n", md5, sb.st_size, filename);
			free(md5);
		    } else {
			logg("!md5sig: Can't generate MD5 checksum for %s\n", filename);
			free(filename);
			return -1;
		    }
		}
	    }

	    free(filename);
	}

    } else { /* stream */
	md5 = cli_md5stream(stdin, NULL);
	if(!md5) {
	    logg("!md5sig: Can't generate MD5 checksum for input stream\n");
	    return -1;
	}
	logg("%s\n", md5);
	free(md5);
    }

    return 0;
}

static int htmlnorm(struct optstruct *opt)
{
	int fd;


    if((fd = open(opt_arg(opt, "html-normalise"), O_RDONLY)) == -1) {
	logg("!htmlnorm: Can't open file %s\n", opt_arg(opt, "html-normalise"));
	return -1;
    }

    html_normalise_fd(fd, ".", NULL);
    close(fd);

    return 0;
}

static unsigned int countlines(const char *filename)
{
	FILE *fd;
	char buff[1024];
	unsigned int lines = 0;


    if((fd = fopen(filename, "r")) == NULL)
	return 0;

    while(fgets(buff, sizeof(buff), fd)) {
	if(buff[0] == '#') continue;
	lines++;
    }

    fclose(fd);
    return lines;
}

static char *getdsig(const char *host, const char *user, const char *data)
{
	char buff[256], cmd[128], *pass, *pt;
        struct sockaddr_in server;
	int sockd, bread, len;


#ifdef PF_INET
    if((sockd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#else
    if((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
#endif
	perror("socket()");
	logg("!getdsig: Can't create socket\n");
	return NULL;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(33101);

    if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) < 0) {
        close(sockd);
	perror("connect()");
	logg("!getdsig: Can't connect to ClamAV Signing Service at %s\n", host);
	return NULL;
    }

    memset(cmd, 0, sizeof(cmd));
    pass = getpass("Password:");
    snprintf(cmd, sizeof(cmd) - 16, "ClamSign:%s:%s:", user, pass);
    len = strlen(cmd);
    pt = cmd + len;
    memcpy(pt, data, 16);
    len += 16;

    if(write(sockd, cmd, len) < 0) {
	logg("!getdsig: Can't write to socket\n");
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
	    logg("!getdsig: Error generating digital signature\n");
	    logg("!getdsig: Answer from remote server: %s\n", buff);
	    close(sockd);
	    return NULL;
	} else {
	    logg("Signature received (length = %d)\n", strlen(buff) - 10);
	}
    }

    close(sockd);
    pt = buff;
    pt += 10;
    return strdup(pt);
}

static int build(struct optstruct *opt)
{
	int ret, itmp;
	size_t bytes;
	unsigned int sigs = 0, lines = 0;
	struct stat foo;
	char buffer[FILEBUFF], *tarfile, *gzfile, header[513],
	     smbuff[30], *pt, *dbdir;
        struct cl_node *root = NULL;
	FILE *tar, *cvd;
	gzFile *gz;
	time_t timet;
	struct tm *brokent;
	struct cl_cvd *oldcvd = NULL;


    if(!opt_check(opt, "server")) {
	logg("!build: --server is required for --build\n");
	return -1;
    }

    if(stat("COPYING", &foo) == -1) {
	logg("!build: COPYING file not found in current working directory.\n");
	return -1;
    }

    if(stat("main.db", &foo) == -1 && stat("daily.db", &foo) == -1 &&
       stat("main.hdb", &foo) == -1 && stat("daily.hdb", &foo) == -1 &&
       stat("main.ndb", &foo) == -1 && stat("daily.ndb", &foo) == -1 &&
       stat("main.zmd", &foo) == -1 && stat("daily.zmd", &foo) == -1 &&
       stat("main.rmd", &foo) == -1 && stat("daily.rmd", &foo) == -1)
    {
	logg("!build: No virus database file  found in current directory\n");
	return -1;
    }

    cl_debug(); /* enable debug messages in libclamav */

    if((ret = cl_loaddbdir(".", &root, &sigs))) {
	logg("!build: Can't load database: %s\n", cl_strerror(ret));
	return -1;
    } else {
	cl_free(root);
    }

    if(!sigs) {
	logg("!build: There are no signatures in database files\n");
    } else {
	logg("Signatures: %d\n", sigs);
	lines = countlines("main.db") + countlines("daily.db") +
		countlines("main.hdb") + countlines("daily.hdb") +
		countlines("main.ndb") + countlines("daily.ndb") +
		countlines("main.zmd") + countlines("daily.zmd") +
		countlines("main.rmd") + countlines("daily.rmd") +
		countlines("main.fp") + countlines("daily.fp");

	if(lines != sigs) {
	    logg("!build: Signatures in database: %d, loaded by libclamav: %d\n", lines, sigs);
	    logg("!build: Please check the current directory and remove unnecessary databases\n");
	    logg("!build: or install the latest ClamAV version.\n");
	    return -1;
	}
    }

    if(!(tarfile = cli_gentemp("."))) {
	logg("!build: Can't generate temporary name for tarfile\n");
	return -1;
    }

    switch(fork()) {
	case -1:
	    logg("!build: Can't fork.\n");
	    free(tarfile);
	    return -1;
	case 0:
	    {
		char *args[] = { "tar", "-cvf", NULL, "COPYING", "main.db",
				 "daily.db", "main.hdb", "daily.hdb",
				 "main.ndb", "daily.ndb", "main.zmd",
				 "daily.zmd", "main.rmd", "daily.rmd",
				 "main.fp", "daily.fp", NULL };
		args[2] = tarfile;
		execv("/bin/tar", args);
		logg("!build: Can't execute tar\n");
		perror("tar");
		free(tarfile);
		return -1;
	    }
	default:
	    wait(NULL);
    }

    if(stat(tarfile, &foo) == -1) {
	logg("!build: Tar archive was not created\n");
	free(tarfile);
	return -1;
    }

    if((tar = fopen(tarfile, "rb")) == NULL) {
	logg("!build: Can't open file %s\n", tarfile);
	free(tarfile);
	return -1;
    }

    if(!(gzfile = cli_gentemp("."))) {
	logg("!build: Can't generate temporary name for gzfile\n");
	free(tarfile);
	fclose(tar);
	return -1;
    }

    if((gz = gzopen(gzfile, "wb")) == NULL) {
	logg("!build: Can't open file %s to write.\n", gzfile);
	free(tarfile);
	fclose(tar);
	free(gzfile);
	return -1;
    }

    while((bytes = fread(buffer, 1, FILEBUFF, tar)) > 0) {
	if(!gzwrite(gz, buffer, bytes)) {
	    logg("!build: Can't gzwrite to %s\n", gzfile);
	    fclose(tar);
	    gzclose(gz);
	    free(tarfile);
	    free(gzfile);
	    return -1;
	}
    }

    fclose(tar);
    gzclose(gz);
    unlink(tarfile);
    free(tarfile);

    /* try to read cvd header of current database */
    dbdir = freshdbdir();
    snprintf(buffer, sizeof(buffer), "%s/%s", dbdir, opt_arg(opt, "build"));
    free(dbdir);
    if((oldcvd = cl_cvdhead(buffer)) == NULL) {
	logg("^build: CAN'T READ CVD HEADER OF CURRENT DATABASE %s\n", buffer);
	sleep(3);
    }

    /* build header */
    strcpy(header, "ClamAV-VDB:");

    /* time */
    time(&timet);
    brokent = localtime(&timet);
    setlocale(LC_TIME, "C");
    strftime(smbuff, sizeof(smbuff), "%d %b %Y %H-%M %z", brokent);
    strcat(header, smbuff);

    /* increment version number by one */
    if(oldcvd) {
	sprintf(smbuff, ":%d:", oldcvd->version + 1);
    } else {
	fflush(stdin);
	logg("Version number: ");
	scanf("%d", &itmp);
	sprintf(smbuff, "%d:", itmp);
    }
    strcat(header, smbuff);

    /* number of signatures */
    sprintf(smbuff, "%d:", sigs);
    strcat(header, smbuff);

    /* functionality level */
    sprintf(smbuff, "%d:", cl_retflevel());
    strcat(header, smbuff);

    /* MD5 */
    if(!(pt = cli_md5file(gzfile))) {
	logg("!build: Can't generate MD5 checksum for gzfile\n");
	unlink(gzfile);
	free(gzfile);
	return -1;
    }
    strcat(header, pt);
    free(pt);
    strcat(header, ":");

    /* ask for builder name */
    fflush(stdin);
    logg("Builder name: ");
    if(fgets(smbuff, sizeof(smbuff), stdin)) {
	cli_chomp(smbuff);
    } else {
	logg("!build: Can't get builder name\n");
	unlink(gzfile);
	free(gzfile);
	return -1;
    }

    /* digital signature */
    if(!(tar = fopen(gzfile, "rb"))) {
	logg("!build: Can't open file %s for reading\n", gzfile);
	unlink(gzfile);
	free(gzfile);
	return -1;
    }

    if(!(pt = cli_md5stream(tar, (unsigned char *) buffer))) {
	logg("!build: Can't generate MD5 checksum for %s\n", gzfile);
	unlink(gzfile);
	free(gzfile);
	return -1;
    }
    free(pt);
    rewind(tar);

    if(!(pt = getdsig(opt_arg(opt, "server"), smbuff, buffer))) {
	logg("!build: Can't get digital signature from remote server\n");
	unlink(gzfile);
	free(gzfile);
	fclose(tar);
	return -1;
    }
    strcat(header, pt);
    free(pt);
    strcat(header, ":");

    /* add builder */
    strcat(header, smbuff);

    /* add current time */
    sprintf(header + strlen(header), ":%d", (int) timet);

    /* fill up with spaces */
    while(strlen(header) < sizeof(header) - 1)
	strcat(header, " ");

    /* build the final database */
    pt = opt_arg(opt, "build");
    if(!(cvd = fopen(pt, "wb"))) {
	logg("!build: Can't create final database %s\n", pt);
	unlink(gzfile);
	free(gzfile);
	fclose(tar);
	return -1;
    }

    if(fwrite(header, 1, 512, cvd) != 512) {
	logg("!build: Can't write to %s\n", pt);
	fclose(cvd);
	fclose(tar);
	unlink(pt);
	unlink(gzfile);
	free(gzfile);
	return -1;
    }

    while((bytes = fread(buffer, 1, FILEBUFF, tar)) > 0) {
	if(fwrite(buffer, 1, bytes, cvd) != bytes) {
	    fclose(tar);
	    fclose(cvd);
	    unlink(pt);
	    logg("!build: Can't write to %s\n", gzfile);
	    unlink(gzfile);
	    free(gzfile);
	    return -1;
	}
    }

    fclose(tar);
    fclose(cvd);
    if(unlink(gzfile) == -1) {
	logg("^build: Can't unlink %s\n", gzfile);
	return -1;
    }
    free(gzfile);

    logg("Database %s created\n", pt);

    return 0;
}

static int unpack(struct optstruct *opt)
{
	char *name, *dbdir;


    if(opt_check(opt, "unpack-current")) {
	dbdir = freshdbdir();
	name = mcalloc(strlen(dbdir) + strlen(opt_arg(opt, "unpack-current")) + 2, sizeof(char));
	sprintf(name, "%s/%s", dbdir, opt_arg(opt, "unpack-current"));
	free(dbdir);
    } else
	name = strdup(opt_arg(opt, "unpack"));

    if(cvd_unpack(name, ".") == -1) {
	logg("!unpack: Can't unpack CVD file %s\n", name);
	free(name);
	return -1;
    }

    free(name);
    return 0;
}

static int cvdinfo(struct optstruct *opt)
{
	struct cl_cvd *cvd;
	char *pt;
	int ret;


    pt = opt_arg(opt, "info");
    if((cvd = cl_cvdhead(pt)) == NULL) {
	logg("!cvdinfo: Can't read/parse CVD header of %s\n", pt);
	return -1;
    }

    pt = strchr(cvd->time, '-');
    *pt = ':';
    logg("Build time: %s\n", cvd->time);
    logg("Version: %d\n", cvd->version);
    logg("Signatures: %d\n", cvd->sigs);
    logg("Functionality level: %d\n", cvd->fl);
    logg("Builder: %s\n", cvd->builder);
    logg("MD5: %s\n", cvd->md5);
    logg("Digital signature: %s\n", cvd->dsig);

#ifndef HAVE_GMP
    logg("^Digital signature support not compiled in.\n");
#endif

    pt = opt_arg(opt, "info");
    if((ret = cl_cvdverify(pt)))
	logg("!cvdinfo: Verification: %s\n", cl_strerror(ret));
    else
	logg("Verification OK.\n");

    cl_cvdfree(cvd);
    return 0;
}

static int listdb(const char *filename);

static int listdir(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	char *dbfile;


    if((dd = opendir(dirname)) == NULL) {
        logg("!listdir: Can't open directory %s\n", dirname);
        return -1;
    }

    while((dent = readdir(dd))) {
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")  ||
	     cli_strbcasestr(dent->d_name, ".hdb") ||
	     cli_strbcasestr(dent->d_name, ".ndb") ||
	     cli_strbcasestr(dent->d_name, ".zmd") ||
	     cli_strbcasestr(dent->d_name, ".rmd") ||
	     cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbfile = (char *) mcalloc(strlen(dent->d_name) + strlen(dirname) + 2, sizeof(char));

		if(!dbfile) {
		    logg("!listdir: Can't allocate memory for dbfile\n");
		    closedir(dd);
		    return -1;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);

		if(listdb(dbfile) == -1) {
		    logg("!listdb: Error listing database %s\n", dbfile);
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

static int listdb(const char *filename)
{
	FILE *fd;
	char *buffer, *pt, *start, *dir;
	int line = 0;
	const char *tmpdir;


    if((fd = fopen(filename, "rb")) == NULL) {
	logg("!listdb: Can't open file %s\n", filename);
	return -1;
    }

    if(!(buffer = (char *) mcalloc(FILEBUFF, 1))) {
	logg("!listdb: Can't allocate memory for buffer\n");
	fclose(fd);
	return -1;
    }

    /* check for CVD file */
    fgets(buffer, 12, fd);
    rewind(fd);

    if(!strncmp(buffer, "ClamAV-VDB:", 11)) {
	free(buffer);
	fclose(fd);

	tmpdir = getenv("TMPDIR");
	if(tmpdir == NULL)
#ifdef P_tmpdir
	    tmpdir = P_tmpdir;
#else
	    tmpdir = "/tmp";
#endif

	if(!(dir = cli_gentemp(tmpdir))) {
	    logg("!listdb: Can't generate temporary name\n");
	    return -1;
	}

	if(mkdir(dir, 0700)) {
	    logg("!listdb: Can't create temporary directory %s\n", dir);
	    free(dir);
	    return -1;
	}

	if(cvd_unpack(filename, dir) == -1) {
	    logg("!listdb: Can't unpack CVD file %s\n", filename);
	    rmdirs(dir);
	    free(dir);
	    return -1;
	}

	/* list extracted directory */
	if(listdir(dir) == -1) {
	    logg("!listdb: Can't unpack CVD file %s\n", filename);
	    rmdirs(dir);
	    free(dir);
	    return -1;
	}

	rmdirs(dir);
	free(dir);

	return 0;
    }

    if(cli_strbcasestr(filename, ".db")) { /* old style database */

	while(fgets(buffer, FILEBUFF, fd)) {
	    line++;
	    pt = strchr(buffer, '=');
	    if(!pt) {
		logg("!listdb: Malformed pattern line %d (file %s)\n", line, filename);
		fclose(fd);
		free(buffer);
		return -1;
	    }

	    start = buffer;
	    *pt = 0;

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    logg("%s\n", start);
	}

    } else if(cli_strbcasestr(filename, ".hdb")) { /* hash database */

	while(fgets(buffer, FILEBUFF, fd)) {
	    line++;
	    cli_chomp(buffer);
	    start = cli_strtok(buffer, 2, ":");

	    if(!start) {
		logg("!listdb: Malformed pattern line %d (file %s)\n", line, filename);
		fclose(fd);
		free(buffer);
		return -1;
	    }

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    logg("%s\n", start);
	    free(start);
	}

    } else if(cli_strbcasestr(filename, ".ndb") || cli_strbcasestr(filename, ".zmd") || cli_strbcasestr(filename, ".rmd")) {

	while(fgets(buffer, FILEBUFF, fd)) {
	    line++;
	    cli_chomp(buffer);
	    start = cli_strtok(buffer, 0, ":");

	    if(!start) {
		logg("!listdb: Malformed pattern line %d (file %s)\n", line, filename);
		fclose(fd);
		free(buffer);
		return -1;
	    }

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    logg("%s\n", start);
	    free(start);
	}
    }

    fclose(fd);
    free(buffer);
    return 0;
}

static int listsigs(struct optstruct *opt)
{
	int ret;
	const char *name;
	char *dbdir;


    mprintf_stdout = 1;

    if((name = opt_arg(opt, "list-sigs"))) {
	ret = listdb(name);
    } else {
	dbdir = freshdbdir();
	ret = listdir(dbdir);
	free(dbdir);
    }

    return ret;
}

static int vbadump(struct optstruct *opt)
{
	int fd, hex_output=0;
	char *dir;


    if(opt_check(opt, "vba-hex"))
	hex_output = 1;
 
    if((fd = open(opt_arg(opt, "vba"), O_RDONLY)) == -1) {
	if((fd = open(opt_arg(opt, "vba-hex"), O_RDONLY)) == -1) {
	    logg("!vbadump: Can't open file %s\n", opt_arg(opt, "vba"));
	    return -1;
	}
    }

    /* generate the temporary directory */
    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	logg("!vbadump: Can't create temporary directory %s\n", dir);
	free(dir);
	close(fd);
        return -1;
    }

    if(cli_ole2_extract(fd, dir, NULL)) {
	cli_rmdirs(dir);
        free(dir);
	close(fd);
        return -1;
    }

    close(fd);
    sigtool_vba_scandir(dir, hex_output);
    rmdirs(dir);
    free(dir);
    return 0;
}

void help(void)
{
    mprintf("\n");
    mprintf("             Clam AntiVirus: Signature Tool (sigtool)  "VERSION"\n");
    mprintf("    (C) 2002 - 2006 ClamAV Team - http://www.clamav.net/team.html\n\n");

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
    mprintf("    --vba=FILE                             Extract VBA/Word6 macro code\n");
    mprintf("    --vba-hex=FILE                         Extract Word6 macro code with hex values\n");
    mprintf("\n");

    return;
}

int main(int argc, char **argv)
{
	int ret = 1;
        struct optstruct *opt;
	const char *short_options = "hvVb:i:u:l::";
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
	    {"quiet", 0, 0, 0},
	    {"debug", 0, 0, 0},
	    {"verbose", 0, 0, 'v'},
	    {"stdout", 0, 0, 0},
	    {"version", 0, 0, 'V'},
	    {"tempdir", 1, 0, 0},
	    {"hex-dump", 0, 0, 0},
	    {"md5", 0, 0, 0},
	    {"html-normalise", 1, 0, 0},
	    {"build", 1, 0, 'b'},
	    {"server", 1, 0, 0},
	    {"unpack", 1, 0, 'u'},
	    {"unpack-current", 1, 0, 0},
	    {"info", 1, 0, 'i'},
	    {"list-sigs", 2, 0, 'l'},
	    {"vba", 1, 0 ,0},
	    {"vba-hex", 1, 0, 0},
	    {0, 0, 0, 0}
    	};


    opt = opt_parse(argc, argv, short_options, long_options, NULL);
    if(!opt) {
	mprintf("!Can't parse the command line\n");
	return 1;
    }

    if(opt_check(opt, "quiet"))
	mprintf_quiet = 1;

    if(opt_check(opt, "stdout"))
	mprintf_stdout = 1;

    if(opt_check(opt, "debug"))
	cl_debug();

    if(opt_check(opt, "version")) {
	print_version();
	opt_free(opt);
	return 0;
    }

    if(opt_check(opt, "help")) {
	opt_free(opt);
    	help();
    }

    if(opt_check(opt, "hex-dump"))
	ret = hexdump();
    else if(opt_check(opt, "md5"))
	ret = md5sig(opt);
    else if(opt_check(opt, "html-normalise"))
	ret = htmlnorm(opt);
    else if(opt_check(opt, "build"))
	ret = build(opt);
    else if(opt_check(opt, "unpack"))
	ret = unpack(opt);
    else if(opt_check(opt, "unpack-current"))
	ret = unpack(opt);
    else if(opt_check(opt, "info"))
	ret = cvdinfo(opt);
    else if(opt_check(opt, "list-sigs"))
	ret = listsigs(opt);
    else if(opt_check(opt, "vba") || opt_check(opt, "vba-hex"))
	ret = vbadump(opt);
    else
	help();


    opt_free(opt);
    return ret ? 1 : 0;
}
