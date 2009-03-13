/*
 *  Copyright (C) 2007 - 2008 Sourcefire, Inc.
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
 *  CDIFF code (C) 2006 Sensory Networks, Inc.
 *  Author: Tomasz Kojm <tkojm@clamav.net>
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
#include <sys/wait.h>
#include <dirent.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#include "vba.h"

#include "shared/output.h"
#include "shared/optparser.h"
#include "shared/misc.h"
#include "shared/cdiff.h"
#include "libclamav/sha256.h"
#include "shared/tar.h"

#include "libclamav/clamav.h"
#include "libclamav/cvd.h"
#include "libclamav/others.h"
#include "libclamav/str.h"
#include "libclamav/ole2_extract.h"
#include "libclamav/htmlnorm.h"
#include "libclamav/default.h"

#define MAX_DEL_LOOKAHEAD   200

/*
 * Force backward compatibility with the cdiff interpreter of clamav < 0.95
 */
#define COMPATIBILITY_LIMIT 980

static const struct dblist_s {
    const char *name;
    unsigned int count;
} dblist[] = {

    /* special files */
    { "COPYING",    0 },
    { "daily.cfg",  0 },
    { "daily.ign",  0 },
    { "daily.ftm",  0 },
    { "main.info",  0 },    { "daily.info", 0 },    { "safebrowsing.info", 0 },

    /* databases */
    { "main.db",    1 },    { "daily.db",   1 },
    { "main.hdb",   1 },    { "daily.hdb",  1 },
    { "main.hdu",   1 },    { "daily.hdu",  1 },
    { "main.mdb",   1 },    { "daily.mdb",  1 },
    { "main.mdu",   1 },    { "daily.mdu",  1 },
    { "main.ndb",   1 },    { "daily.ndb",  1 },
    { "main.ndu",   1 },    { "daily.ndu",  1 },
    { "main.ldb",   1 },    { "daily.ldb",  1 },
    { "main.ldu",   1 },    { "daily.ldu",  1 },
    { "main.sdb",   1 },    { "daily.sdb",  1 },
    { "main.zmd",   1 },    { "daily.zmd",  1 },
    { "main.rmd",   1 },    { "daily.rmd",  1 },
    { "main.fp",    0 },    { "daily.fp",   0 },
    { "main.pdb",   1 },    { "daily.pdb",  1 },    { "safebrowsing.gdb", 1 },
    { "main.wdb",   0 },    { "daily.wdb",  0 },    { "safebrowsing.wdb", 0 },

    { NULL,	    0 }
};

static const char *getdbname(const char *str)
{
    if(strstr(str, "main"))
	return "main";
    else if(strstr(str, "daily"))
	return "daily";
    else if(strstr(str, "safebrowsing"))
	return "safebrowsing";
    else {
	mprintf("!getdbname: Can't extract db name\n");
	return "UNKNOWN";
    }
}

static int hexdump(void)
{
	char buffer[FILEBUFF], *pt;
	int bytes;


    while((bytes = read(0, buffer, FILEBUFF)) > 0) {
	pt = cli_str2hex(buffer, bytes);
	if(write(1, pt, 2 * bytes) == -1) {
	    mprintf("!hexdump: Can't write to stdout\n");
	    free(pt);
	    return -1;
	}
	free(pt);
    }

    if(bytes == -1)
	return -1;

    return 0;
}

static int md5sig(const struct optstruct *opts, unsigned int mdb)
{
	char *md5;
	unsigned int i;
	struct stat sb;


    if(opts->filename) {
	for(i = 0; opts->filename[i]; i++) {
	    if(stat(opts->filename[i], &sb) == -1) {
		mprintf("!md5sig: Can't access file %s\n", opts->filename[i]);
		perror("md5sig");
		return -1;
	    } else {
		if((sb.st_mode & S_IFMT) == S_IFREG) {
		    if((md5 = cli_md5file(opts->filename[i]))) {
			if(mdb)
			    mprintf("%u:%s:%s\n", (unsigned int) sb.st_size, md5, opts->filename[i]);
			else
			    mprintf("%s:%u:%s\n", md5, (unsigned int) sb.st_size, opts->filename[i]);
			free(md5);
		    } else {
			mprintf("!md5sig: Can't generate MD5 checksum for %s\n", opts->filename[i]);
			return -1;
		    }
		}
	    }
	}

    } else { /* stream */
	md5 = cli_md5stream(stdin, NULL);
	if(!md5) {
	    mprintf("!md5sig: Can't generate MD5 checksum for input stream\n");
	    return -1;
	}
	mprintf("%s\n", md5);
	free(md5);
    }

    return 0;
}

static int htmlnorm(const struct optstruct *opts)
{
	int fd;


    if((fd = open(optget(opts, "html-normalise")->strarg, O_RDONLY)) == -1) {
	mprintf("!htmlnorm: Can't open file %s\n", optget(opts, "html-normalise")->strarg);
	return -1;
    }

    html_normalise_fd(fd, ".", NULL, NULL);
    close(fd);

    return 0;
}

static int utf16decode(const struct optstruct *opts)
{
	const char *fname;
	char *newname, buff[512], *decoded;
	int fd1, fd2, bytes;


    fname = optget(opts, "utf16-decode")->strarg;
    if((fd1 = open(fname, O_RDONLY)) == -1) {
	mprintf("!utf16decode: Can't open file %s\n", fname);
	return -1;
    }

    newname = malloc(strlen(fname) + 7);
    if(!newname) {
	mprintf("!utf16decode: Can't allocate memory\n");
	return -1;
    }
    sprintf(newname, "%s.ascii", fname);

    if((fd2 = open(newname, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
	mprintf("!utf16decode: Can't create file %s\n", newname);
	free(newname);
	close(fd1);
	return -1;
    }

    while((bytes = read(fd1, buff, sizeof(buff))) > 0) {
	decoded = cli_utf16toascii(buff, bytes);
	if(decoded) {
	    if(write(fd2, decoded, strlen(decoded)) == -1) {
		mprintf("!utf16decode: Can't write to file %s\n", newname);
		free(decoded);
		unlink(newname);
		free(newname);
		close(fd1);
		close(fd2);
		return -1;
	    }
	    free(decoded);
	}
    }

    free(newname);
    close(fd1);
    close(fd2);

    return 0;
}

static unsigned int countlines(const char *filename)
{
	FILE *fh;
	char buff[1024];
	unsigned int lines = 0;


    if((fh = fopen(filename, "r")) == NULL)
	return 0;

    while(fgets(buff, sizeof(buff), fh)) {
	if(buff[0] == '#') continue;
	lines++;
    }

    fclose(fh);
    return lines;
}

static char *getdsig(const char *host, const char *user, const unsigned char *data, unsigned int datalen, unsigned short mode)
{
	char buff[512], cmd[128], pass[30], *pt;
        struct sockaddr_in server;
	int sockd, bread, len;
#ifdef HAVE_TERMIOS_H
	struct termios old, new;
#endif


    if((pt = getenv("SIGNDPASS"))) {
	strncpy(pass, pt, sizeof(pass));
	pass[sizeof(pass)-1]='\0';
    } else {
	mprintf("Password: ");

#ifdef HAVE_TERMIOS_H
	if(tcgetattr(0, &old)) {
	    mprintf("!getdsig: tcgetattr() failed\n");
	    return NULL;
	}
	new = old;
	new.c_lflag &= ~ECHO;
	if(tcsetattr(0, TCSAFLUSH, &new)) {
	    mprintf("!getdsig: tcsetattr() failed\n");
	    return NULL;
	}
#endif
	if(scanf("%as", &pt) == EOF) {
	    mprintf("!getdsig: Can't get password\n");
#ifdef HAVE_TERMIOS_H
	    tcsetattr(0, TCSAFLUSH, &old);
#endif
	    return NULL;
	}
	strncpy(pass, pt, sizeof(pass));
	pass[sizeof(pass)-1]='\0';
	free(pt);

#ifdef HAVE_TERMIOS_H
	if(tcsetattr(0, TCSAFLUSH, &old)) {
	    mprintf("!getdsig: tcsetattr() failed\n");
	    memset(pass, 0, sizeof(pass));
	    return NULL;
	}
#endif
	mprintf("\n");
    }

    if((sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket()");
	mprintf("!getdsig: Can't create socket\n");
	memset(pass, 0, sizeof(pass));
	return NULL;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(33101);

    if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) < 0) {
        close(sockd);
	perror("connect()");
	mprintf("!getdsig: Can't connect to ClamAV Signing Service at %s\n", host);
	memset(pass, 0, sizeof(pass));
	return NULL;
    }
    memset(cmd, 0, sizeof(cmd));

    if(mode == 1)
	snprintf(cmd, sizeof(cmd) - datalen, "ClamSignPSS:%s:%s:", user, pass);
    else
	snprintf(cmd, sizeof(cmd) - datalen, "ClamSign:%s:%s:", user, pass);

    len = strlen(cmd);
    pt = cmd + len;
    memcpy(pt, data, datalen);
    len += datalen;

    if(write(sockd, cmd, len) < 0) {
	mprintf("!getdsig: Can't write to socket\n");
	close(sockd);
	memset(cmd, 0, sizeof(cmd));
	memset(pass, 0, sizeof(pass));
	return NULL;
    }

    memset(cmd, 0, sizeof(cmd));
    memset(pass, 0, sizeof(pass));
    memset(buff, 0, sizeof(buff));

    if((bread = cli_readn(sockd, buff, sizeof(buff))) > 0) {
	if(!strstr(buff, "Signature:")) {
	    mprintf("!getdsig: Error generating digital signature\n");
	    mprintf("!getdsig: Answer from remote server: %s\n", buff);
	    close(sockd);
	    return NULL;
	} else {
	    mprintf("Signature received (length = %lu)\n", strlen(buff) - 10);
	}
    } else {
	mprintf("!getdsig: Communication error with remote server\n");
	close(sockd);
	return NULL;
    }

    close(sockd);

    pt = buff;
    pt += 10;
    return strdup(pt);
}

static int writeinfo(const char *dbname, const char *header)
{
	FILE *fh;
	unsigned int i;
	char file[32], *md5;


    snprintf(file, sizeof(file), "%s.info", dbname);
    if(!access(file, R_OK)) {
	if(unlink(file) == -1) {
	    mprintf("!writeinfo: Can't unlink %s\n", file);
	    return -1;
	}
    }

    if(!(fh = fopen(file, "w"))) {
	mprintf("!writeinfo: Can't create file %s\n", file);
	return -1;
    }

    if(fprintf(fh, "%s\n", header) < 0) {
	mprintf("!writeinfo: Can't write to %s\n", file);
	fclose(fh);
	return -1;
    }

    for(i = 0; dblist[i].name; i++) {
	if(!cli_strbcasestr(dblist[i].name, ".info") && strstr(dblist[i].name, dbname) && !access(dblist[i].name, R_OK)) {
	    if(!(md5 = cli_md5file(dblist[i].name))) {
		mprintf("!writeinfo: Can't generate MD5 checksum for %s\n", file);
		fclose(fh);
		return -1;
	    }
	    if(fprintf(fh, "%s:%s\n", dblist[i].name, md5) < 0) {
		mprintf("!writeinfo: Can't write to info file\n");
		fclose(fh);
		free(md5);
		return -1;
	    }
	    free(md5);
	}
    }

    fclose(fh);
    return 0;
}

static int diffdirs(const char *old, const char *new, const char *patch);
static int verifydiff(const char *diff, const char *cvd, const char *incdir);

static int script2cdiff(const char *script, const char *builder, const struct optstruct *opts)
{
	char *cdiff, *pt, buffer[FILEBUFF];
	unsigned char digest[32];
	SHA256_CTX ctx;
	struct stat sb;
	FILE *scripth, *cdiffh;
	gzFile *gzh;
	unsigned int ver, osize;
	int bytes;


    if(stat(script, &sb) == -1) {
	mprintf("!script2diff: Can't stat file %s\n", script);
	return -1;
    }
    osize = (unsigned int) sb.st_size;

    cdiff = strdup(script);
    pt = strstr(cdiff, ".script");
    if(!pt) {
	mprintf("!script2cdiff: Incorrect file name (no .script extension)\n");
	free(cdiff);
	return -1;
    }
    strcpy(pt, ".cdiff");

    if(!(pt = strchr(script, '-'))) {
	mprintf("!script2cdiff: Incorrect file name syntax\n");
	free(cdiff);
	return -1;
    }

    if(sscanf(++pt, "%u.script", &ver) == EOF) {
	mprintf("!script2cdiff: Incorrect file name syntax\n");
	free(cdiff);
	return -1;
    }

    if(!(cdiffh = fopen(cdiff, "wb"))) {
	mprintf("!script2cdiff: Can't open %s for writing\n", cdiff);
	free(cdiff);
	return -1;
    }

    if(fprintf(cdiffh, "ClamAV-Diff:%u:%u:", ver, osize) < 0) {
	mprintf("!script2cdiff: Can't write to %s\n", cdiff);
	fclose(cdiffh);
	free(cdiff);
	return -1;
    }
    fclose(cdiffh);

    if(!(scripth = fopen(script, "rb"))) {
	mprintf("!script2cdiff: Can't open file %s for reading\n", script);
	unlink(cdiff);
	free(cdiff);
	return -1;
    }

    if(!(gzh = gzopen(cdiff, "ab"))) {
	mprintf("!script2cdiff: Can't open file %s for appending\n", cdiff);
	unlink(cdiff);
	free(cdiff);
	fclose(scripth);
	return -1;
    }

    while((bytes = fread(buffer, 1, sizeof(buffer), scripth)) > 0) {
	if(!gzwrite(gzh, buffer, bytes)) {
	    mprintf("!script2cdiff: Can't gzwrite to %s\n", cdiff);
	    unlink(cdiff);
	    free(cdiff);
	    fclose(scripth);
	    gzclose(gzh);
	    return -1;
	}
    }
    fclose(scripth);
    gzclose(gzh);

    if(!(cdiffh = fopen(cdiff, "rb"))) {
	mprintf("!script2cdiff: Can't open %s for reading/writing\n", cdiff);
	unlink(cdiff);
	free(cdiff);
	return -1;
    }

    sha256_init(&ctx);

    while((bytes = fread(buffer, 1, sizeof(buffer), cdiffh)))
	sha256_update(&ctx, (unsigned char *) buffer, bytes);

    fclose(cdiffh);
    sha256_final(&ctx, digest);

    if(!(pt = getdsig(optget(opts, "server")->strarg, builder, digest, 32, 1))) {
	mprintf("!script2cdiff: Can't get digital signature from remote server\n");
	unlink(cdiff);
	free(cdiff);
	return -1;
    }

    if(!(cdiffh = fopen(cdiff, "ab"))) {
	mprintf("!script2cdiff: Can't open %s for appending\n", cdiff);
	unlink(cdiff);
	free(cdiff);
	return -1;
    }
    fprintf(cdiffh, ":%s", pt);
    free(pt);
    fclose(cdiffh);

    mprintf("Created %s\n", cdiff);
    free(cdiff);

    return 0;
}

static int build(const struct optstruct *opts)
{
	int ret;
	size_t bytes;
	unsigned int i, sigs = 0, oldsigs = 0, lines = 0, version, real_header, fl;
	struct stat foo;
	unsigned char buffer[FILEBUFF];
	char *tarfile, header[513], smbuff[32], builder[32], *pt, olddb[512], patch[32], broken[32];
	const char *dbname, *newcvd;
        struct cl_engine *engine;
	FILE *cvd, *fh;
	gzFile *tar;
	time_t timet;
	struct tm *brokent;
	struct cl_cvd *oldcvd;


    if(!optget(opts, "server")->enabled) {
	mprintf("!build: --server is required for --build\n");
	return -1;
    }

    if(stat("COPYING", &foo) == -1) {
	mprintf("!build: COPYING file not found in current working directory.\n");
	return -1;
    }

    dbname = getdbname(optget(opts, "build")->strarg);

    if(!(engine = cl_engine_new())) {
	mprintf("!build: Can't initialize antivirus engine\n");
	return 50;
    }

    if((ret = cl_load(".", engine, &sigs, CL_DB_STDOPT | CL_DB_PUA))) {
	mprintf("!build: Can't load database: %s\n", cl_strerror(ret));
	cl_engine_free(engine);
	return -1;
    }
    cl_engine_free(engine);

    if(!sigs) {
	mprintf("!build: There are no signatures in database files\n");
    } else {
	for(i = 0; dblist[i].name; i++)
	    if(dblist[i].count && strstr(dblist[i].name, dbname) && !access(dblist[i].name, R_OK))
		lines += countlines(dblist[i].name);

	if(lines != sigs)
	    mprintf("^build: Signatures in %s db files: %u, loaded by libclamav: %u\n", dbname, lines, sigs);

	if(!lines || (sigs > lines && sigs - lines >= 1000)) {
	    mprintf("!Bad number of signatures in database files\n");
	    return -1;
	}
    }

    /* try to read cvd header of current database */
    if(opts->filename) {
	if(cli_strbcasestr(opts->filename[0], ".cvd") || cli_strbcasestr(opts->filename[0], ".cld")) {
	    strncpy(olddb, opts->filename[0], sizeof(olddb));
	    olddb[sizeof(olddb)-1]='\0';
	} else {
	    mprintf("!build: Not a CVD/CLD file\n");
	    return -1;
	}

    } else {
	pt = freshdbdir();
	snprintf(olddb, sizeof(olddb), "%s/%s.cvd", pt, dbname);
	if(access(olddb, R_OK))
	    snprintf(olddb, sizeof(olddb), "%s/%s.cld", pt, dbname);
	free(pt);
    }

    if(!(oldcvd = cl_cvdhead(olddb))) {
	mprintf("^build: CAN'T READ CVD HEADER OF CURRENT DATABASE %s (wait 3 s)\n", olddb);
	sleep(3);
    }

    if(oldcvd) {
	version = oldcvd->version + 1;
	oldsigs = oldcvd->sigs;
	cl_cvdfree(oldcvd);
    } else {
	mprintf("Version number: ");
	if(scanf("%u", &version) == EOF) {
	    mprintf("!build: scanf() failed\n");
	    return -1;
	}
    }

    mprintf("Total sigs: %u\n", sigs);
    if(sigs > oldsigs)
	mprintf("New sigs: %u\n", sigs - oldsigs);

    strcpy(header, "ClamAV-VDB:");

    /* time */
    time(&timet);
    brokent = localtime(&timet);
    setlocale(LC_TIME, "C");
    strftime(smbuff, sizeof(smbuff), "%d %b %Y %H-%M %z", brokent);
    strcat(header, smbuff);

    /* version */
    sprintf(header + strlen(header), ":%u:", version);

    /* number of signatures */
    sprintf(header + strlen(header), "%u:", sigs);

    /* functionality level */
    if(!strcmp(dbname, "main")) {
	mprintf("Functionality level: ");
	if(scanf("%u", &fl) == EOF || !fl || fl > 99) {
	    mprintf("!build: Incorrect functionality level\n");
	    return -1;
	}
    } else {
	fl = cl_retflevel();
    }
    sprintf(header + strlen(header), "%u:", fl);

    real_header = strlen(header);

    /* add fake MD5 and dsig (for writeinfo) */
    strcat(header, "X:X:");

    if((pt = getenv("SIGNDUSER"))) {
	strncpy(builder, pt, sizeof(builder));
	builder[sizeof(builder)-1]='\0';
    } else {
	mprintf("Builder name: ");
	if(scanf("%as", &pt) == EOF) {
	    mprintf("!build: Can't get builder name\n");
	    return -1;
	}
	strncpy(builder, pt, sizeof(builder));
	builder[sizeof(builder)-1]='\0';
	free(pt);
    }

    /* add builder */
    strcat(header, builder);

    /* add current time */
    sprintf(header + strlen(header), ":%u", (unsigned int) timet);

    if(writeinfo(dbname, header) == -1) {
	mprintf("!build: Can't generate info file\n");
	return -1;
    }

    header[real_header] = 0;

    if(!(tarfile = cli_gentemp("."))) {
	mprintf("!build: Can't generate temporary name for tarfile\n");
	return -1;
    }

    if((tar = gzopen(tarfile, "wb")) == NULL) {
	mprintf("!build: Can't open file %s for writing\n", tarfile);
	free(tarfile);
	return -1;
    }

    if(tar_addfile(-1, tar, "COPYING") == -1) {
	mprintf("!build: Can't add COPYING to tar archive\n");
	gzclose(tar);
	unlink(tarfile);
	free(tarfile);
	return -1;
    }

    for(i = 0; dblist[i].name; i++) {
	if(strstr(dblist[i].name, dbname) && !access(dblist[i].name, R_OK)) {
	    if(tar_addfile(-1, tar, dblist[i].name) == -1) {
		gzclose(tar);
		unlink(tarfile);
		free(tarfile);
		return -1;
	    }
	}
    }
    gzclose(tar);

    /* MD5 + dsig */
    if(!(fh = fopen(tarfile, "rb"))) {
	mprintf("!build: Can't open file %s for reading\n", tarfile);
	unlink(tarfile);
	free(tarfile);
	return -1;
    }

    if(!(pt = cli_md5stream(fh, buffer))) {
	mprintf("!build: Can't generate MD5 checksum for %s\n", tarfile);
	fclose(fh);
	unlink(tarfile);
	free(tarfile);
	return -1;
    }
    rewind(fh);
    sprintf(header + strlen(header), "%s:", pt);
    free(pt);

    if(!(pt = getdsig(optget(opts, "server")->strarg, builder, buffer, 16, 0))) {
	mprintf("!build: Can't get digital signature from remote server\n");
	fclose(fh);
	unlink(tarfile);
	free(tarfile);
	return -1;
    }
    sprintf(header + strlen(header), "%s:", pt);
    free(pt);

    /* add builder */
    strcat(header, builder);

    /* add current time */
    sprintf(header + strlen(header), ":%u", (unsigned int) timet);

    /* fill up with spaces */
    while(strlen(header) < sizeof(header) - 1)
	strcat(header, " ");

    /* build the final database */
    newcvd = optget(opts, "build")->strarg;
    if(!(cvd = fopen(newcvd, "wb"))) {
	mprintf("!build: Can't create final database %s\n", newcvd);
	fclose(fh);
	unlink(tarfile);
	free(tarfile);
	return -1;
    }

    if(fwrite(header, 1, 512, cvd) != 512) {
	mprintf("!build: Can't write to %s\n", newcvd);
	fclose(fh);
	unlink(tarfile);
	free(tarfile);
	fclose(cvd);
	unlink(newcvd);
	return -1;
    }

    while((bytes = fread(buffer, 1, FILEBUFF, fh)) > 0) {
	if(fwrite(buffer, 1, bytes, cvd) != bytes) {
	    mprintf("!build: Can't write to %s\n", newcvd);
	    fclose(fh);
	    unlink(tarfile);
	    free(tarfile);
	    fclose(cvd);
	    unlink(newcvd);
	    return -1;
	}
    }

    fclose(fh);
    fclose(cvd);

    if(unlink(tarfile) == -1) {
	mprintf("^build: Can't unlink %s\n", tarfile);
	unlink(tarfile);
	free(tarfile);
	unlink(newcvd);
	return -1;
    }
    free(tarfile);

    mprintf("Created %s\n", newcvd);

    if(optget(opts, "no-cdiff")->enabled) {
	mprintf("Skipping .cdiff creation\n");
	return 0;
    }

    /* generate patch */
    if(!(pt = cli_gentemp(NULL))) {
	mprintf("!build: Can't generate temporary name\n");
	unlink(newcvd);
	return -1;
    }

    if(mkdir(pt, 0700)) {
	mprintf("!build: Can't create temporary directory %s\n", pt);
	free(pt);
	unlink(newcvd);
	return -1;
    }

    if(cli_cvdunpack(olddb, pt) == -1) {
	mprintf("!build: Can't unpack CVD file %s\n", olddb);
	cli_rmdirs(pt);
	free(pt);
	unlink(newcvd);
	return -1;
    }
    strncpy(olddb, pt, sizeof(olddb));
    olddb[sizeof(olddb)-1]='\0';
    free(pt);

    if(!(pt = cli_gentemp(NULL))) {
	mprintf("!build: Can't generate temporary name\n");
	cli_rmdirs(olddb);
	unlink(newcvd);
	return -1;
    }

    if(mkdir(pt, 0700)) {
	mprintf("!build: Can't create temporary directory %s\n", pt);
	free(pt);
	cli_rmdirs(olddb);
	unlink(newcvd);
	return -1;
    }

    if(cli_cvdunpack(newcvd, pt) == -1) {
	mprintf("!build: Can't unpack CVD file %s\n", newcvd);
	cli_rmdirs(pt);
	free(pt);
	cli_rmdirs(olddb);
	unlink(newcvd);
	return -1;
    }

    snprintf(patch, sizeof(patch), "%s-%u.script", dbname, version);
    ret = diffdirs(olddb, pt, patch);

    cli_rmdirs(pt);
    free(pt);

    if(ret == -1) {
	cli_rmdirs(olddb);
	unlink(newcvd);
	return -1;
    }

    ret = verifydiff(patch, NULL, olddb);
    cli_rmdirs(olddb);

    if(ret == -1) {
	snprintf(broken, sizeof(broken), "%s.broken", patch);
	if(rename(patch, broken)) {
	    unlink(patch);
	    mprintf("!Generated file is incorrect, removed");
	} else {
	    mprintf("!Generated file is incorrect, renamed to %s\n", broken);
	}
    } else {
	ret = script2cdiff(patch, builder, opts);
    }

    return ret;
}

static int unpack(const struct optstruct *opts)
{
	char name[512], *dbdir;


    if(optget(opts, "unpack-current")->enabled) {
	dbdir = freshdbdir();
	snprintf(name, sizeof(name), "%s/%s.cvd", dbdir, optget(opts, "unpack-current")->strarg);
	if(access(name, R_OK)) {
	    snprintf(name, sizeof(name), "%s/%s.cld", dbdir, optget(opts, "unpack-current")->strarg);
	    if(access(name, R_OK)) {
		mprintf("!unpack: Couldn't find %s CLD/CVD database\n", optget(opts, "unpack-current")->strarg);
		free(dbdir);
		return -1;
	    }
	}
	free(dbdir);

    } else {
	strncpy(name, optget(opts, "unpack")->strarg, sizeof(name));
	name[sizeof(name)-1]='\0';
    }

    if(cli_cvdunpack(name, ".") == -1) {
	mprintf("!unpack: Can't unpack file %s\n", name);
	return -1;
    }

    return 0;
}

static int cvdinfo(const struct optstruct *opts)
{
	struct cl_cvd *cvd;
	char *pt;
	int ret;


    pt = optget(opts, "info")->strarg;
    if((cvd = cl_cvdhead(pt)) == NULL) {
	mprintf("!cvdinfo: Can't read/parse CVD header of %s\n", pt);
	return -1;
    }
    mprintf("File: %s\n", pt);

    pt = strchr(cvd->time, '-');
    *pt = ':';
    mprintf("Build time: %s\n", cvd->time);
    mprintf("Version: %u\n", cvd->version);
    mprintf("Signatures: %u\n", cvd->sigs);
    mprintf("Functionality level: %u\n", cvd->fl);
    mprintf("Builder: %s\n", cvd->builder);

    pt = optget(opts, "info")->strarg;
    if(cli_strbcasestr(pt, ".cvd")) {
	mprintf("MD5: %s\n", cvd->md5);
	mprintf("Digital signature: %s\n", cvd->dsig);
	cl_cvdfree(cvd);
	if((ret = cl_cvdverify(pt))) {
	    mprintf("!cvdinfo: Verification: %s\n", cl_strerror(ret));
	    return -1;
	} else {
	    mprintf("Verification OK.\n");
	    return 0;
	}
    }

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
        mprintf("!listdir: Can't open directory %s\n", dirname);
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
	     cli_strbcasestr(dent->d_name, ".hdu") ||
	     cli_strbcasestr(dent->d_name, ".mdb") ||
	     cli_strbcasestr(dent->d_name, ".mdu") ||
	     cli_strbcasestr(dent->d_name, ".ndb") ||
	     cli_strbcasestr(dent->d_name, ".ndu") ||
	     cli_strbcasestr(dent->d_name, ".ldb") ||
	     cli_strbcasestr(dent->d_name, ".ldu") ||
	     cli_strbcasestr(dent->d_name, ".sdb") ||
	     cli_strbcasestr(dent->d_name, ".zmd") ||
	     cli_strbcasestr(dent->d_name, ".rmd") ||
	     cli_strbcasestr(dent->d_name, ".cld") ||
	     cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbfile = (char *) malloc(strlen(dent->d_name) + strlen(dirname) + 2);
		if(!dbfile) {
		    mprintf("!listdir: Can't allocate memory for dbfile\n");
		    closedir(dd);
		    return -1;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);

		if(listdb(dbfile) == -1) {
		    mprintf("!listdb: Error listing database %s\n", dbfile);
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
	FILE *fh;
	char *buffer, *pt, *start, *dir;
	unsigned int line = 0;
	const char *tmpdir;


    if((fh = fopen(filename, "rb")) == NULL) {
	mprintf("!listdb: Can't open file %s\n", filename);
	return -1;
    }

    if(!(buffer = (char *) malloc(FILEBUFF))) {
	mprintf("!listdb: Can't allocate memory for buffer\n");
	fclose(fh);
	return -1;
    }

    /* check for CVD file */
    if(!fgets(buffer, 12, fh)) {
	mprintf("!listdb: fgets failed\n");
	fclose(fh);
	return -1;
    }
    rewind(fh);

    if(!strncmp(buffer, "ClamAV-VDB:", 11)) {
	free(buffer);
	fclose(fh);

	tmpdir = getenv("TMPDIR");
	if(tmpdir == NULL)
#ifdef P_tmpdir
	    tmpdir = P_tmpdir;
#else
	    tmpdir = "/tmp";
#endif

	if(!(dir = cli_gentemp(tmpdir))) {
	    mprintf("!listdb: Can't generate temporary name\n");
	    return -1;
	}

	if(mkdir(dir, 0700)) {
	    mprintf("!listdb: Can't create temporary directory %s\n", dir);
	    free(dir);
	    return -1;
	}

	if(cli_cvdunpack(filename, dir) == -1) {
	    mprintf("!listdb: Can't unpack CVD file %s\n", filename);
	    cli_rmdirs(dir);
	    free(dir);
	    return -1;
	}

	/* list extracted directory */
	if(listdir(dir) == -1) {
	    mprintf("!listdb: Can't list directory %s\n", filename);
	    cli_rmdirs(dir);
	    free(dir);
	    return -1;
	}

	cli_rmdirs(dir);
	free(dir);

	return 0;
    }

    if(cli_strbcasestr(filename, ".db")) { /* old style database */

	while(fgets(buffer, FILEBUFF, fh)) {
	    line++;
	    pt = strchr(buffer, '=');
	    if(!pt) {
		mprintf("!listdb: Malformed pattern line %u (file %s)\n", line, filename);
		fclose(fh);
		free(buffer);
		return -1;
	    }

	    start = buffer;
	    *pt = 0;

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    mprintf("%s\n", start);
	}

    } else if(cli_strbcasestr(filename, ".hdb") || cli_strbcasestr(filename, ".hdu") || cli_strbcasestr(filename, ".mdb") || cli_strbcasestr(filename, ".mdu")) { /* hash database */

	while(fgets(buffer, FILEBUFF, fh)) {
	    line++;
	    cli_chomp(buffer);
	    start = cli_strtok(buffer, 2, ":");

	    if(!start) {
		mprintf("!listdb: Malformed pattern line %u (file %s)\n", line, filename);
		fclose(fh);
		free(buffer);
		return -1;
	    }

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    mprintf("%s\n", start);
	    free(start);
	}

    } else if(cli_strbcasestr(filename, ".ndb") || cli_strbcasestr(filename, ".ndu") || cli_strbcasestr(filename, ".ldb") || cli_strbcasestr(filename, ".ldu") || cli_strbcasestr(filename, ".sdb") || cli_strbcasestr(filename, ".zmd") || cli_strbcasestr(filename, ".rmd")) {

	while(fgets(buffer, FILEBUFF, fh)) {
	    line++;
	    cli_chomp(buffer);

	    if(cli_strbcasestr(filename, ".ldb") || cli_strbcasestr(filename, ".ldu"))
		start = cli_strtok(buffer, 0, ";");
	    else
		start = cli_strtok(buffer, 0, ":");

	    if(!start) {
		mprintf("!listdb: Malformed pattern line %u (file %s)\n", line, filename);
		fclose(fh);
		free(buffer);
		return -1;
	    }

	    if((pt = strstr(start, " (Clam)")))
		*pt = 0;

	    mprintf("%s\n", start);
	    free(start);
	}
    }
    fclose(fh);
    free(buffer);
    return 0;
}

static int listsigs(const struct optstruct *opts)
{
	int ret;
	const char *name;
	char *dbdir;
	struct stat sb;


    name = optget(opts, "list-sigs")->strarg;
    if(stat(name, &sb) == -1) {
	mprintf("--list-sigs: Can't get status of %s\n", name);
	return -1;
    }

    mprintf_stdout = 1;
    if(S_ISDIR(sb.st_mode)) {
	if(!strcmp(name, DATADIR)) {
	    dbdir = freshdbdir();
	    ret = listdir(dbdir);
	    free(dbdir);
	} else {
	    ret = listdir(name);
	}
    } else {
	ret = listdb(name);
    }

    return ret;
}

static int vbadump(const struct optstruct *opts)
{
	int fd, hex_output;
	char *dir;
	const char *pt;
	struct uniq *vba = NULL;


    if(optget(opts, "vba-hex")->enabled) {
	hex_output = 1;
	pt = optget(opts, "vba-hex")->strarg;
    } else {
	hex_output = 0;
	pt = optget(opts, "vba")->strarg;
    }
 
    if((fd = open(pt, O_RDONLY)) == -1) {
	mprintf("!vbadump: Can't open file %s\n", pt);
	return -1;
    }

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(NULL))) {
	mprintf("!vbadump: Can't generate temporary name\n");
	close(fd);
	return -1;
    }

    if(mkdir(dir, 0700)) {
	mprintf("!vbadump: Can't create temporary directory %s\n", dir);
	free(dir);
	close(fd);
        return -1;
    }

    if(cli_ole2_extract(fd, dir, NULL, &vba)) {
	cli_rmdirs(dir);
        free(dir);
	close(fd);
        return -1;
    }
    close(fd);
    if (vba) 
      sigtool_vba_scandir(dir, hex_output, vba);
    cli_rmdirs(dir);
    free(dir);
    return 0;
}

static int comparemd5(const char *dbname)
{
	char info[32], buff[256], *md5, *pt;
	FILE *fh;
	int ret = 0;


    snprintf(info, sizeof(info), "%s.info", getdbname(dbname));

    if(!(fh = fopen(info, "r"))) {
	mprintf("!verifydiff: Can't open %s\n", info);
	return -1;
    }

    if(!fgets(buff, sizeof(buff), fh) || strncmp(buff, "ClamAV-VDB", 10)) {
	mprintf("!verifydiff: Incorrect info file %s\n", info);
	fclose(fh);
	return -1;
    }

    while(fgets(buff, sizeof(buff), fh)) {
	cli_chomp(buff);
	if(!(pt = strchr(buff, ':'))) {
	    mprintf("!verifydiff: Incorrect format of %s\n", info);
	    ret = -1;
	    break;
	}
	*pt++ = 0;
	if(!(md5 = cli_md5file(buff))) {
	    mprintf("!verifydiff: Can't generate MD5 for %s\n", buff);
	    ret = -1;
	    break;
	}
	if(strcmp(pt, md5)) {
	    mprintf("!verifydiff: %s has incorrect checksum\n", buff);
	    ret = -1;
	    free(md5);
	    break;
	}
	free(md5);
    }

    fclose(fh);
    return ret;
}


static int rundiff(const struct optstruct *opts)
{
	int fd, ret;
	unsigned short mode;
	const char *diff;


    diff = optget(opts, "run-cdiff")->strarg;
    if(strstr(diff, ".cdiff")) {
	mode = 1;
    } else if(strstr(diff, ".script")) {
	mode = 0;
    } else {
	mprintf("!rundiff: Incorrect file name (no .cdiff/.script extension)\n");
	return -1;
    }

    if((fd = open(diff, O_RDONLY)) == -1) {
	mprintf("!rundiff: Can't open file %s\n", diff);
	return -1;
    }

    ret = cdiff_apply(fd, mode);
    close(fd);

    if(!ret)
	ret = comparemd5(diff);

    return ret;
}

static int compare(const char *oldpath, const char *newpath, FILE *diff)
{
	FILE *old, *new;
	char obuff[CLI_DEFAULT_LSIG_BUFSIZE + 1], nbuff[CLI_DEFAULT_LSIG_BUFSIZE + 1], tbuff[CLI_DEFAULT_LSIG_BUFSIZE + 1], *pt, *omd5, *nmd5;
	unsigned int oline = 0, tline, found, i;
	long opos;


    if(!(new = fopen(newpath, "r"))) {
	mprintf("!compare: Can't open file %s for reading\n", newpath);
	return -1;
    }

    if((omd5 = cli_md5file(oldpath))) {
	if(!(nmd5 = cli_md5file(newpath))) {
	    mprintf("!compare: Can't get MD5 checksum of %s\n", newpath);
	    free(omd5);
	    return -1;
	}
	if(!strcmp(omd5, nmd5)) {
	    free(omd5);
	    free(nmd5);
	    return 0;
	}
	free(omd5);
	free(nmd5);
    }

    fprintf(diff, "OPEN %s\n", newpath);

    old = fopen(oldpath, "r");

    while(fgets(nbuff, sizeof(nbuff), new)) {
	i = strlen(nbuff);
	if(i >= 2 && (nbuff[i - 1] == '\r' || (nbuff[i - 1] == '\n' && nbuff[i - 2] == '\r'))) {
	    mprintf("!compare: New %s file contains lines terminated with CRLF or CR\n", newpath);
	    if(old)
		fclose(old);
	    return -1;
	}
	cli_chomp(nbuff);
	if(!old) {
	    fprintf(diff, "ADD %s\n", nbuff);
	} else {
	    if(fgets(obuff, sizeof(obuff), old)) {
		oline++;
		cli_chomp(obuff);
		if(!strcmp(nbuff, obuff)) {
		    continue;
		} else {
		    tline = 0;
		    found = 0;
		    opos = ftell(old);
		    while(fgets(tbuff, sizeof(tbuff), old)) {
			tline++;
			cli_chomp(tbuff);

			if(tline > MAX_DEL_LOOKAHEAD)
			    break;

			if(!strcmp(tbuff, nbuff)) {
			    found = 1;
			    break;
			}
		    }
		    fseek(old, opos, SEEK_SET);

		    if(found) {
			strncpy(tbuff, obuff, sizeof(tbuff));
			tbuff[sizeof(tbuff)-1]='\0';
			for(i = 0; i < tline; i++) {
			    tbuff[16] = 0;
			    if((pt = strchr(tbuff, ' ')))
				*pt = 0;
			    fprintf(diff, "DEL %u %s\n", oline + i, tbuff);
			    if(!fgets(tbuff, sizeof(tbuff), old))
				break;
			}
			oline += tline;

		    } else {
			obuff[16] = 0;
			if((pt = strchr(obuff, ' ')))
			    *pt = 0;
			fprintf(diff, "XCHG %u %s %s\n", oline, obuff, nbuff);
		    }
		}
	    } else {
		fclose(old);
		old = NULL;
		fprintf(diff, "ADD %s\n", nbuff);
	    }
	}
#ifdef COMPATIBILITY_LIMIT
       if(strlen(nbuff) > COMPATIBILITY_LIMIT) {
           mprintf("!compare: COMPATIBILITY_LIMIT: Found too long line in new %s\n", newpath);
           if(old)
               fclose(old);
           return -1;
       }
#endif
    }

    if(old) {
	while(fgets(obuff, sizeof(obuff), old)) {
	    oline++;
	    obuff[16] = 0;
	    if((pt = strchr(obuff, ' ')))
		*pt = 0;
	    fprintf(diff, "DEL %u %s\n", oline, obuff);
	}
	fclose(old);
    }

    fprintf(diff, "CLOSE\n");
    return 0;
}

static int dircopy(const char *src, const char *dest)
{
	DIR *dd;
	struct dirent *dent;
	struct stat sb;
	char spath[512], dpath[512];


    if(stat(dest, &sb) == -1) {
	if(mkdir(dest, 0755)) {
	    /* mprintf("!dircopy: Can't create temporary directory %s\n", dest); */
	    return -1;
	}
    }

    if((dd = opendir(src)) == NULL) {
        /* mprintf("!dircopy: Can't open directory %s\n", src); */
        return -1;
    }

    while((dent = readdir(dd))) {
#if (!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	if(dent->d_ino)
#endif
	{
	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
		continue;

	    snprintf(spath, sizeof(spath), "%s/%s", src, dent->d_name);
	    snprintf(dpath, sizeof(dpath), "%s/%s", dest, dent->d_name);

	    if(filecopy(spath, dpath) == -1) {
		/* mprintf("!dircopy: Can't copy %s to %s\n", spath, dpath); */
		cli_rmdirs(dest);
		closedir(dd);
		return -1;
	    }
	}
    }

    closedir(dd);
    return 0;
}

static int verifydiff(const char *diff, const char *cvd, const char *incdir)
{
	char *tempdir, cwd[512];
	int ret = 0, fd;
	unsigned short mode;


    if(strstr(diff, ".cdiff")) {
	mode = 1;
    } else if(strstr(diff, ".script")) {
	mode = 0;
    } else {
	mprintf("!verifydiff: Incorrect file name (no .cdiff/.script extension)\n");
	return -1;
    }

    tempdir = cli_gentemp(NULL);
    if(!tempdir) {
	mprintf("!verifydiff: Can't generate temporary name for tempdir\n");
	return -1;
    }

    if(mkdir(tempdir, 0700) == -1) {
	mprintf("!verifydiff: Can't create directory %s\n", tempdir);
	free(tempdir);
	return -1;
    }

    if(cvd) {
	if(cli_cvdunpack(cvd, tempdir) == -1) {
	    mprintf("!verifydiff: Can't unpack CVD file %s\n", cvd);
	    cli_rmdirs(tempdir);
	    free(tempdir);
	    return -1;
	}
    } else {
	if(dircopy(incdir, tempdir) == -1) {
	    mprintf("!verifydiff: Can't copy dir %s to %s\n", incdir, tempdir);
	    cli_rmdirs(tempdir);
	    free(tempdir);
	    return -1;
	}
    }

    if((fd = open(diff, O_RDONLY)) == -1) {
	mprintf("!verifydiff: Can't open diff file %s\n", diff);
	cli_rmdirs(tempdir);
	free(tempdir);
	return -1;
    }

    if(!getcwd(cwd, sizeof(cwd))) {
	mprintf("!verifydiff: getcwd() failed\n");
	cli_rmdirs(tempdir);
	free(tempdir);
	return -1;
    }

    if(chdir(tempdir) == -1) {
	mprintf("!verifydiff: Can't chdir to %s\n", tempdir);
	cli_rmdirs(tempdir);
	free(tempdir);
	close(fd);
	return -1;
    }

    if(cdiff_apply(fd, mode) == -1) {
	mprintf("!verifydiff: Can't apply %s\n", diff);
	if(chdir(cwd) == -1)
	    mprintf("^verifydiff: Can't chdir to %s\n", cwd);
	cli_rmdirs(tempdir);
	free(tempdir);
	close(fd);
	return -1;
    }
    close(fd);

    ret = comparemd5(diff);

    if(chdir(cwd) == -1)
	mprintf("^verifydiff: Can't chdir to %s\n", cwd);
    cli_rmdirs(tempdir);
    free(tempdir);

    if(!ret) {
	if(cvd)
	    mprintf("Verification: %s correctly applies to %s\n", diff, cvd);
	else
	    mprintf("Verification: %s correctly applies to the previous version\n", diff);
    }

    return ret;
}

static int diffdirs(const char *old, const char *new, const char *patch)
{
	FILE *diff;
	DIR *dd;
	struct dirent *dent;
	char cwd[512], path[1024];


    if(!getcwd(cwd, sizeof(cwd))) {
	mprintf("!diffdirs: getcwd() failed\n");
	return -1;
    }

    if(!(diff = fopen(patch, "w"))) {
        mprintf("!diffdirs: Can't open %s for writing\n", patch);
	return -1;
    }

    if(chdir(new) == -1) {
	mprintf("!diffdirs: Can't chdir to %s\n", new);
	fclose(diff);
	return -1;
    }

    if((dd = opendir(new)) == NULL) {
        mprintf("!diffdirs: Can't open directory %s\n", new);
	fclose(diff);
	return -1;
    }

    while((dent = readdir(dd))) {
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
		continue;

	    snprintf(path, sizeof(path), "%s/%s", old, dent->d_name);
	    if(compare(path, dent->d_name, diff) == -1) {
		if(chdir(cwd) == -1)
		    mprintf("^diffdirs: Can't chdir to %s\n", cwd);
		fclose(diff);
		unlink(patch);
		closedir(dd);
		return -1;
	    }
	}
    }
    closedir(dd);

    /* check for removed files */
    if((dd = opendir(old)) == NULL) {
        mprintf("!diffdirs: Can't open directory %s\n", old);
	fclose(diff);
	return -1;
    }

    while((dent = readdir(dd))) {
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
		continue;

	    snprintf(path, sizeof(path), "%s/%s", new, dent->d_name);
	    if(access(path, R_OK))
		fprintf(diff, "UNLINK %s\n", dent->d_name);
	}
    }
    closedir(dd);

    fclose(diff);
    mprintf("Generated diff file %s\n", patch);
    if(chdir(cwd) == -1)
	mprintf("^diffdirs: Can't chdir to %s\n", cwd);

    return 0;
}

static int makediff(const struct optstruct *opts)
{
	char *odir, *ndir, name[32], broken[32];
	struct cl_cvd *cvd;
	unsigned int oldver, newver;
	int ret;


    if(!opts->filename) {
	mprintf("!makediff: --diff requires two arguments\n");
	return -1;
    }

    if(!(cvd = cl_cvdhead(opts->filename[0]))) {
	mprintf("!makediff: Can't read CVD header from %s\n", opts->filename[0]);
	return -1;
    }
    newver = cvd->version;
    free(cvd);

    if(!(cvd = cl_cvdhead(optget(opts, "diff")->strarg))) {
	mprintf("!makediff: Can't read CVD header from %s\n", optget(opts, "diff")->strarg);
	return -1;
    }
    oldver = cvd->version;
    free(cvd);

    if(oldver + 1 != newver) {
	mprintf("!makediff: The old CVD must be %u\n", newver - 1);
	return -1;
    }

    odir = cli_gentemp(NULL);
    if(!odir) {
	mprintf("!makediff: Can't generate temporary name for odir\n");
	return -1;
    }

    if(mkdir(odir, 0700) == -1) {
	mprintf("!makediff: Can't create directory %s\n", odir);
	free(odir);
	return -1;
    }

    if(cli_cvdunpack(optget(opts, "diff")->strarg, odir) == -1) {
	mprintf("!makediff: Can't unpack CVD file %s\n", optget(opts, "diff")->strarg);
	cli_rmdirs(odir);
	free(odir);
	return -1;
    }

    ndir = cli_gentemp(NULL);
    if(!ndir) {
	mprintf("!makediff: Can't generate temporary name for ndir\n");
	cli_rmdirs(odir);
	free(odir);
	return -1;
    }

    if(mkdir(ndir, 0700) == -1) {
	mprintf("!makediff: Can't create directory %s\n", ndir);
	free(ndir);
	cli_rmdirs(odir);
	free(odir);
	return -1;
    }

    if(cli_cvdunpack(opts->filename[0], ndir) == -1) {
	mprintf("!makediff: Can't unpack CVD file %s\n", opts->filename[0]);
	cli_rmdirs(odir);
	cli_rmdirs(ndir);
	free(odir);
	free(ndir);
	return -1;
    }

    snprintf(name, sizeof(name), "%s-%u.script", getdbname(opts->filename[0]), newver);
    ret = diffdirs(odir, ndir, name);

    cli_rmdirs(odir);
    cli_rmdirs(ndir);
    free(odir);
    free(ndir);

    if(ret == -1)
	return -1;

    if(verifydiff(name, optget(opts, "diff")->strarg, NULL) == -1) {
	snprintf(broken, sizeof(broken), "%s.broken", name);
	if(rename(name, broken)) {
	    unlink(name);
	    mprintf("!Generated file is incorrect, removed");
	} else {
	    mprintf("!Generated file is incorrect, renamed to %s\n", broken);
	}
	return -1;
    }

    return 0;
}

static void help(void)
{
    mprintf("\n");
    mprintf("             Clam AntiVirus: Signature Tool (sigtool)  %s\n", get_version());
    printf("           By The ClamAV Team: http://www.clamav.net/team\n");
    printf("           (C) 2007-2009 Sourcefire, Inc. et al.\n\n");

    mprintf("    --help                 -h              show help\n");
    mprintf("    --version              -V              print version number and exit\n");
    mprintf("    --quiet                                be quiet, output only error messages\n");
    mprintf("    --debug                                enable debug messages\n");
    mprintf("    --stdout                               write to stdout instead of stderr\n");
    mprintf("    --hex-dump                             convert data from stdin to a hex\n");
    mprintf("                                           string and print it on stdout\n");
    mprintf("    --md5 [FILES]                          generate MD5 checksum from stdin\n");
    mprintf("                                           or MD5 sigs for FILES\n");
    mprintf("    --mdb [FILES]                          generate .mdb sigs\n");
    mprintf("    --html-normalise=FILE                  create normalised parts of HTML file\n");
    mprintf("    --utf16-decode=FILE                    decode UTF16 encoded files\n");
    mprintf("    --info=FILE            -i FILE         print database information\n");
    mprintf("    --build=NAME [cvd] -b NAME             build a CVD file\n");
    mprintf("    --no-cdiff                             Don't generate .cdiff file\n");
    mprintf("    --server=ADDR                          ClamAV Signing Service address\n");
    mprintf("    --unpack=FILE          -u FILE         Unpack a CVD/CLD file\n");
    mprintf("    --unpack-current=SHORTNAME             Unpack local CVD/CLD into cwd\n");
    mprintf("    --list-sigs[=FILE]     -l[FILE]        List signature names\n");
    mprintf("    --vba=FILE                             Extract VBA/Word6 macro code\n");
    mprintf("    --vba-hex=FILE                         Extract Word6 macro code with hex values\n");
    mprintf("    --diff=OLD NEW         -d OLD NEW      Create diff for OLD and NEW CVDs\n");
    mprintf("    --run-cdiff=FILE       -r FILE         Execute update script FILE in cwd\n");
    mprintf("    --verify-cdiff=DIFF CVD/CLD            Verify DIFF against CVD/CLD\n");
    mprintf("\n");

    return;
}

int main(int argc, char **argv)
{
	int ret = 1;
        struct optstruct *opts;
	struct stat sb;

    opts = optparse(NULL, argc, argv, 1, OPT_SIGTOOL, 0, NULL);
    if(!opts) {
	mprintf("!Can't parse command line options\n");
	return 1;
    }

    if(optget(opts, "quiet")->enabled)
	mprintf_quiet = 1;

    if(optget(opts, "stdout")->enabled)
	mprintf_stdout = 1;

    if(optget(opts, "debug")->enabled)
	cl_debug();

    if(optget(opts, "version")->enabled) {
	print_version(NULL);
	optfree(opts);
	return 0;
    }

    if(optget(opts, "help")->enabled) {
	optfree(opts);
    	help();
	return 0;
    }

    if(optget(opts, "hex-dump")->enabled)
	ret = hexdump();
    else if(optget(opts, "md5")->enabled)
	ret = md5sig(opts, 0);
    else if(optget(opts, "mdb")->enabled)
	ret = md5sig(opts, 1);
    else if(optget(opts, "html-normalise")->enabled)
	ret = htmlnorm(opts);
    else if(optget(opts, "utf16-decode")->enabled)
	ret = utf16decode(opts);
    else if(optget(opts, "build")->enabled)
	ret = build(opts);
    else if(optget(opts, "unpack")->enabled)
	ret = unpack(opts);
    else if(optget(opts, "unpack-current")->enabled)
	ret = unpack(opts);
    else if(optget(opts, "info")->enabled)
	ret = cvdinfo(opts);
    else if(optget(opts, "list-sigs")->active)
	ret = listsigs(opts);
    else if(optget(opts, "vba")->enabled || optget(opts, "vba-hex")->enabled)
	ret = vbadump(opts);
    else if(optget(opts, "diff")->enabled)
	ret = makediff(opts);
    else if(optget(opts, "run-cdiff")->enabled)
	ret = rundiff(opts);
    else if(optget(opts, "verify-cdiff")->enabled) {
	if(!opts->filename) {
	    mprintf("!--verify-cdiff requires two arguments\n");
	    ret = -1;
	} else {
	    if(stat(opts->filename[0], &sb) == -1) {
		mprintf("--verify-cdiff: Can't get status of %s\n", opts->filename[0]);
		ret = -1;
	    } else {
		if(S_ISDIR(sb.st_mode))
		    ret = verifydiff(optget(opts, "verify-cdiff")->strarg, NULL, opts->filename[0]);
		else
		    ret = verifydiff(optget(opts, "verify-cdiff")->strarg, opts->filename[0], NULL);
	    }
	}
    } else
	help();

    optfree(opts);
    return ret ? 1 : 0;
}
