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
#include <clamav.h>

#include "options.h"
#include "others.h"
#include "shared.h"
#include "strings.h"

#define LINE 1024
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
	char *fname, buffer[FBUFFSIZE];
	int bytes, size, sum;
	FILE *rd, *wd;


    if((rd = fopen(file, "rb")) == NULL) {
	mprintf("!File %s doesn't exist.\n", file);
	exit(13);
    }

    fname = gentemp(".");
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
	    //fwrite(buffer, 1, size - bytes, wd);
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
	char *fname, buffer[BUFFSIZE];
	int bytes, size, sum, ch;
	FILE *rd, *wd;


    if((rd = fopen(file, "rb")) == NULL) {
	mprintf("!File %s doesn't exist.\n", file);
	exit(13);
    }

    fname = gentemp(".");
    if((wd = fopen(fname, "wb+")) == NULL) {
	mprintf("!Can't create temporary file %s\n", fname);
	exit(14);
    }

    while((bytes = fread(buffer, 1, BUFFSIZE, rd)) > 0)
	fwrite(buffer, 1, bytes, wd);

    fclose(rd);

    fflush(wd);
    fseek(wd, x, SEEK_SET);
    ch = fgetc(wd);
    fseek(wd, -1, SEEK_CUR);
    fputc(++ch, wd);
    fclose(wd);
    return fname;
}

void sigtool(struct optstruct *opt)
{
	    char buffer[BUFFSIZE];
	    int bytes;
	    char *pt;


    if(optl(opt, "quiet")) mprintf_quiet = 1;
    else mprintf_quiet = 0;

    if(optl(opt, "stdout")) mprintf_stdout = 1;
    else mprintf_stdout = 0;

    if(optc(opt, 'V')) {
	mprintf("sigtool / ClamAV version "VERSION"\n");
	exit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }


    if(optl(opt, "hex-dump")) {

	while((bytes = read(0, buffer, BUFFSIZE)) > 0) {
	    pt = cl_str2hex(buffer, bytes);
	    write(1, pt, 2 * bytes);
	    free(pt);
	}

    } else {
	    int jmp, start, end, found = 0, exec = 0, pos, filesize;
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

	/* find signature's END */
	while(1) {
	    tmp = cut(f, 0, end);
	    exec++;
	    if(scanfile(c, s, tmp) == 1) {
		if(!end) {
		    mprintf("end == 0, stopping loop\n");
		    unlink(tmp);
		    free(tmp);
		    break;
		}
		mprintf("Detected, decreasing end %d -> %d\n", end, end - jmp);
		end -= jmp;
		unlink(tmp);
		free(tmp);
	    } else {
		mprintf("Not detected at %d, moving forward.\n", end);
		if(jmp == 1) {
		    unlink(tmp);
		    free(tmp);
		    //mprintf("Starting precise loop\n");
		    while(end < filesize) {
			tmp = cut(f, 0, end);
			exec++;
			if(scanfile(c, s, tmp) == 1) {
			    mprintf(" *** Found signature's end at %d\n", end);
			    found = 1;
		//	    unlink(tmp);
			    f2 = strdup(tmp);
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

	// zamazuj 1 bajt ruszajac do tylu i sprawdzaj czy wykrywa dalej wirusa
	// - znajdz pierwsyz bajt, po ktorego zamazaniu wirus nie jest wykrywany
	/* now we go backward as long as signature can be detected */

	jmp = 50;
	pos = end - jmp;

	while(1) {
	    if(pos < 0) //!!!!!!????
		pos = 0;

	    tmp = change(f2, pos);
	    exec++;
	    if(scanfile(c, s, tmp) != 1) {
		mprintf("Not detected, moving backward %d -> %d\n", pos, pos - jmp);
		pos -= jmp;
		unlink(tmp);
		free(tmp);

	    } else {
		mprintf("Detected at %d, moving forward.\n", pos);
		if(jmp == 1) {
		    unlink(tmp);
		    free(tmp);
		    //mprintf("Starting precise loop\n");
		    while(pos < end) {
			tmp = change(f2, pos);
			exec++;
			if(scanfile(c, s, tmp) == 1) {
			    mprintf(" *** Found signature's start at %d\n", pos);
			    unlink(tmp);
			    free(tmp);
			    found = 1;
			    break;
			} else {
			    unlink(tmp);
			    free(tmp);
			    mprintf("Moving forward %d -> %d\n", pos, pos + 1);
			}
			pos++;
		    }
		    if(found) break;
		}
		if(jmp)
		    jmp--;
		jmp = jmp/2 + 1; //??????????????
		pos += jmp;

		if(pos > end)
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

	if(end - pos < 8) {
	    mprintf("\nWARNING: THE SIGNATURE IS TO SMALL (PROBABLY ONLY A PART OF THE REAL SIGNATURE).\n");
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
	    signame = gentemp(".");
	}

	bsigname = (char *) mcalloc(strlen(f) + 10, sizeof(char));
	sprintf(bsigname, "%s.bsig", f);
	if(fileinfo(bsigname, 1) != -1) {
	    mprintf("File %s exists.\n", bsigname);
	    free(bsigname);
	    bsigname = gentemp(".");
	}

	if((wd = fopen(signame, "wb")) == NULL) {
	    mprintf("Can't write to %s\n", signame);
	    unlink(tmp);
	    free(tmp);
	    exit(15);
	}

	mprintf("Saving signature in %s file.\n", signame);

	while((bytes = fread(buffer, 1, BUFFSIZE, fd)) > 0) {
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

    //free_opt(opt);
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
    mprintf("   --stdout				write to stdout instead of stderr\n");
    mprintf("					(this help is always written to stdout)\n");
    mprintf("   --hex-dump				convert data from stdin to hex\n");
    mprintf("					string and send it to stdout\n");
    mprintf("   --command		    -c		scanner command string, with options\n");
    mprintf("   --string		    -s		'virus found' string in scan. output\n");
    mprintf("   --file		    -f		infected file\n\n");

    exit(0);
}
