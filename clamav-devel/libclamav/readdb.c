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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "cvd.h"
#include "strings.h"
#include "matcher.h"
#include "others.h"
#include "str.h"
#include "defaults.h"

int cli_parse_add(struct cl_node *root, const char *virname, const char *hexstr, int sigid, int parts, int partno)
{
	struct cli_patt *new;
	const char *pt;
	int ret, virlen;

    /* decode a hexstring and prepare a new entry */

    if((new = (struct cli_patt *) cli_calloc(1, sizeof(struct cli_patt))) == NULL)
	return CL_EMEM;

    new->sigid = sigid;
    new->parts = parts;
    new->partno = partno;

    new->length = strlen(hexstr) / 2;

    if(new->length > root->maxpatlen)
	root->maxpatlen = new->length;

    if((new->pattern = cl_hex2str(hexstr)) == NULL) {
	free(new);
	return CL_EMALFDB;
    }

    if((pt = strstr(virname, "(Clam)")))
	virlen = strlen(virname) - strlen(pt) - 1;
    else
	virlen = strlen(virname);

    if((new->virname = cli_calloc(virlen + 1, sizeof(char))) == NULL)
	return CL_EMEM;
    strncpy(new->virname, virname, virlen);

    if((ret = cli_addpatt(root, new)))
	return ret;

    return 0;
}

/* this functions returns a pointer to the root of trie */

int cl_loaddb(const char *filename, struct cl_node **root, int *virnum)
{
	FILE *fd;
	char buffer[BUFFSIZE], *pt, *start, *pt2;
	int line = 0, ret, parts, i, sigid = 0;


    if((fd = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cl_loaddb(): Can't open file %s\n", filename);
	return CL_EOPEN;
    }

    cli_dbgmsg("Loading %s\n", filename);

    /* check for CVD file */
    fgets(buffer, 12, fd);
    rewind(fd);

    if(!strncmp(buffer, "ClamAV-VDB:", 11)) {
	cli_dbgmsg("%s: CVD file detected\n", filename);
	ret = cli_cvdload(fd, root, virnum);
	fclose(fd);
	return ret;
    }

    while(fgets(buffer, BUFFSIZE, fd)) {

	/* for forward compatibility */
	if(strchr(buffer, '{') || strchr(buffer, '}')) {
	    cli_dbgmsg("Not suported signature type detected at line %d. Skipping.\n", line);
	    continue;
	}

	line++;
	cli_chomp(buffer);

	pt = strchr(buffer, '=');
	if(!pt) {
	    cli_errmsg("readdb(): Malformed pattern line %d (file %s).\n", line, filename);
	    return CL_EMALFDB;
	}

	start = buffer;
	*pt++ = 0;

	if(*pt == '=') continue;

	if(!*root) {
	    cli_dbgmsg("Initializing trie.\n");
	    *root = (struct cl_node *) cli_calloc(1, sizeof(struct cl_node));
	    if(!*root)
		return CL_EMEM;
	    (*root)->maxpatlen = 0;
	}

	if(strchr(pt, '*')) { /* new type signature */
	    (*root)->partsigs++;
	    sigid++;
	    parts = 0;
	    for(i = 0; i < strlen(pt); i++)
		if(pt[i] == '*')
		    parts++;

	    if(parts) /* there's always one part more */
		parts++;
	    for(i = 1; i <= parts; i++) {
		pt2 = cli_tok(pt, i, '*');
		if((ret = cli_parse_add(*root, start, pt2, sigid, parts, i))) {
		    cli_dbgmsg("parse_add() return code: %d\n", ret);
		    cli_errmsg("readdb(): Malformed pattern line %d (file %s).\n", line, filename);
		    return ret;
		}
		//cli_dbgmsg("Added part %d of partial signature (id %d)\n", i, sigid);
		free(pt2);
	    }

	} else { /* old type */
	    if((ret = cli_parse_add(*root, start, pt, 0, 0, 0))) {
		cli_dbgmsg("parse_add() return code: %d\n", ret);
		cli_errmsg("readdb(): Malformed pattern line %d (file %s).\n", line, filename);
		return ret;
	    }
	}
    }

    fclose(fd);
    if(virnum != NULL)
	*virnum += line;

    return 0;
}

char *cl_retdbdir(void)
{
    return DATADIR;
}

int cl_loaddbdir(const char *dirname, struct cl_node **root, int *virnum)
{
	DIR *dd;
	struct dirent *dent;
	char *dbfile;
	int ret;


    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cl_loaddbdir(): Can't open directory %s\n", dirname);
        return CL_EOPEN;
    }

    cli_dbgmsg("Loading databases from %s\n", dirname);

    while((dent = readdir(dd))) {
	if(dent->d_ino) {
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")  ||
	     cli_strbcasestr(dent->d_name, ".db2") ||
	     cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbfile = (char *) cli_calloc(strlen(dent->d_name) + strlen(dirname) + 2, sizeof(char));

		if(!dbfile) {
		    cli_dbgmsg("cl_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);
		if((ret = cl_loaddb(dbfile, root, virnum))) {
		    cli_dbgmsg("cl_loaddbdir(): error loading database %s\n", dbfile);
		    free(dbfile);
		    closedir(dd);
		    return ret;
		}
		free(dbfile);
	    }
	}
    }

    closedir(dd);
    return 0;
}

int cl_statinidir(const char *dirname, struct cl_stat *dbstat)
{
	DIR *dd;
	struct dirent *dent;
        char *fname;


    if(dbstat) {
	dbstat->no = 0;
	dbstat->stattab = NULL;
	dbstat->dir = strdup(dirname);
    } else {
        cli_errmsg("cl_statdbdir(): Null argument passed.\n");
	return CL_ENULLARG;
    }

    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cl_statdbdir(): Can't open directory %s\n", dirname);
        return CL_EOPEN;
    }

    cli_dbgmsg("Stat()ing files in %s\n", dirname);

    while((dent = readdir(dd))) {
	if(dent->d_ino) {
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && (cli_strbcasestr(dent->d_name, ".db") || cli_strbcasestr(dent->d_name, ".db2"))) {

		dbstat->no++;
		dbstat->stattab = (struct stat *) realloc(dbstat->stattab, dbstat->no * sizeof(struct stat));
                fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		sprintf(fname, "%s/%s", dirname, dent->d_name);
		stat(fname, &dbstat->stattab[dbstat->no - 1]);
		free(fname);
	    }
	}
    }

    closedir(dd);
    return 0;
}

int cl_statchkdir(const struct cl_stat *dbstat)
{
	DIR *dd;
	struct dirent *dent;
	struct stat sb;
	int i, found;
	char *fname;


    if(!dbstat || !dbstat->dir) {
        cli_errmsg("cl_statdbdir(): Null argument passed.\n");
	return CL_ENULLARG;
    }

    if((dd = opendir(dbstat->dir)) == NULL) {
        cli_errmsg("cl_statdbdir(): Can't open directory %s\n", dbstat->dir);
        return CL_EOPEN;
    }

    cli_dbgmsg("Stat()ing files in %s\n", dbstat->dir);

    while((dent = readdir(dd))) {
	if(dent->d_ino) {
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && (cli_strbcasestr(dent->d_name, ".db") || cli_strbcasestr(dent->d_name, ".db2"))) {

                fname = cli_calloc(strlen(dbstat->dir) + strlen(dent->d_name) + 2, sizeof(char));
		sprintf(fname, "%s/%s", dbstat->dir, dent->d_name);
		stat(fname, &sb);
		free(fname);

		found = 0;
		for(i = 0; i < dbstat->no; i++)
		    if(dbstat->stattab[i].st_ino == sb.st_ino) {
			found = 1;
			if(dbstat->stattab[i].st_mtime != sb.st_mtime)
			    return 1;
		    }

		if(!found)
		    return 1;
	    }
	}
    }

    closedir(dd);
    return 0;
}

int cl_statfree(struct cl_stat *dbstat)
{

    if(dbstat) {
	free(dbstat->stattab);
	dbstat->stattab = NULL;
	dbstat->no = 0;
	if(dbstat->dir)
	    free(dbstat->dir);
    } else {
        cli_errmsg("cl_statfree(): Null argument passed.\n");
	return CL_ENULLARG;
    }

    return 0;
}
