/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <time.h>
#include <locale.h>
#include <clamav.h>

#include "options.h"
#include "others.h"
#include "shared.h"
#include "strings.h"

#define LINE 1024

#define MIN_LENGTH 15
#define MAX_LENGTH 200

void help(void);

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
	    return 1; /* found */
	}
    }

    free(command);
    fclose(pd);
    return 0; /* substring not found */
}

char *cut(const char *file, long int start, long int end)
{
	char *fname = NULL, buffer[FBUFFSIZE];
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

    while((bytes = fread(buffer, 1, FBUFFSIZE, rd)) > 0) {
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
	char *fname = NULL, buffer[FBUFFSIZE];
	int bytes, size, sum, ch;
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

    while((bytes = fread(buffer, 1, FBUFFSIZE, rd)) > 0)
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
	    char buffer[FBUFFSIZE];
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

	while((bytes = read(0, buffer, FBUFFSIZE)) > 0) {
	    pt = cl_str2hex(buffer, bytes);
	    write(1, pt, 2 * bytes);
	    free(pt);
	}

    } else if(optc(opt, 'b')) {

	build(opt);

    } else if(optc(opt, 'i')) {

	cvdinfo(opt);

    } else {
	    int jmp, lastjmp, start, end, found = 0, exec = 0, pos, filesize,
		maxsize = 0, ret;
	    char *c, *s, *f, *tmp, *signame, *bsigname, *f2;
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

		unlink(tmp);
		free(tmp);
	    }

	}

	/* find signature beginning */
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
			    mprintf(" *** Found signature's start at %d\n", pos);
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
	mprintf("The signature length is %d, so the length of the hex string should be %d\n", end - pos, 2 * (end - pos));

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

	while((bytes = fread(buffer, 1, FBUFFSIZE, fd)) > 0) {
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

int build(struct optstruct *opt)
{
	int ret, no = 0, bytes, itmp;
	struct stat foo;
	char buffer[BUFFSIZE], *tarfile = NULL, *gzfile = NULL, header[257],
	     smbuff[25], *pt;
        struct cl_node *root = NULL;
	FILE *tar, *cvd;
	gzFile *gz;
	time_t timet;
	struct tm *brokent;

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

    if((ret = cl_loaddbdir(cl_retdbdir(), &root, &no))) {
	mprintf("!Can't load database: %s\n", cl_strerror(ret));
        exit(1);
    }

    cl_freetrie(root);

    mprintf("Database properly parsed.\n");

    if(!no)
	mprintf("WARNING: There are no signatures in the database(s).\n");
    else
	mprintf("Signatures: %d\n", no);

    tarfile = cl_gentemp(".");

    switch(fork()) {
	case -1:
	    mprintf("!Can't fork.\n");
	    exit(1);
	case 0:
	    {
		char *args[] = { "tar", "-cvf", tarfile, "COPYING", "viruses.db", "viruses.db2", NULL };
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

    while((bytes = fread(buffer, 1, BUFFSIZE, tar)) > 0)
	gzwrite(gz, buffer, bytes);

    fclose(tar);
    unlink(tarfile);
    free(tarfile);

    gzclose(gz);

    /* generate header */

    /* magic string */

    strcpy(header, "ClamAV-VDB:");

    /* time */

    time(&timet);
    brokent = localtime(&timet);
    setlocale(LC_TIME, "C");
    strftime(smbuff, 24, "%b-%d %H-%M %Z:", brokent);
    strcat(header, smbuff);

    /* version number */

    /* ... increment version number by one */

    mprintf("!Can't read database version number from current local database\n");
    fflush(stdin);
    mprintf("Please enter a version number for the new database: ");
    scanf("%d", &itmp);
    sprintf(smbuff, "%d:", itmp);
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
    strcat(header, ":");

    /* digital signature */
    strcat(header, ":");

    /* builder */
    fflush(stdin);
    mprintf("Builder name: ");
    fscanf(stdin, "%s:", &smbuff);
    strcat(header, smbuff);

    /* fill up with spaces */
    if(strlen(header) > 512) {
	mprintf("!Generated signature is too long.\n");
	exit(1);
    }

    while(strlen(header) < 512)
	strcat(header, " ");

    /* build the final database */

    pt = getargc(opt, 'b');
    if((cvd = fopen(pt, "wb")) == NULL) {
	mprintf("!Can't write the final database %s\n", pt);
	exit(1);
    }

    fwrite(header, 1, 512, cvd);

    if((tar = fopen(gzfile, "rb")) == NULL) {
	mprintf("!Can't open file %s for reading.\n", gzfile);
	exit(1);
    }

    while((bytes = fread(buffer, 1, BUFFSIZE, tar)) > 0)
	fwrite(buffer, 1, bytes, cvd);

    fclose(tar);
    fclose(cvd);

    unlink(gzfile);
    free(gzfile);

    mprintf("Database %s created.\n", pt);

    /* try to load final cvd */
}

void cvdinfo(struct optstruct *opt)
{
	struct cl_cvd *cvd;
	char *pt;
	int ret;

    pt = getargc(opt, 'i');
    if((cvd = cl_cvdhead(pt)) == NULL) {
	mprintf("!Can't read CVD header from %s\n", pt);
	exit(1);
    }

    mprintf("Creation time: %s\n", cvd->time);
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

void help(void)
{
    mprintf("\n");
    mprintf("		   Clam AntiVirus: Signature Tool (sigtool)  "VERSION"\n");
    mprintf("	       (c) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>\n");
    mprintf("\n");
    mprintf("   --help		    -h		show help\n");
    mprintf("   --version		    -V		print version number and exit\n");
    mprintf("   --quiet				be quiet, output only error messages\n");
    mprintf("   --debug				enable debug messages\n");
    mprintf("   --stdout				write to stdout instead of stderr\n");
    mprintf("					(this help is always written to stdout)\n");
    mprintf("   --hex-dump				convert data from stdin to hex\n");
    mprintf("					string and send it to stdout\n");
    mprintf("   --command		    -c		scanner command string, with options\n");
    mprintf("   --string		    -s		'virus found' string in scan. output\n");
    mprintf("   --file		    -f		infected file\n");
    mprintf("	--info FILE	    -i FILE	print database information\n");
    mprintf("   --build NAME	    -b NAME		Build database\n");

    exit(0);
}
