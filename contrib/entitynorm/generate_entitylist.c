/*
 *  Copyright (C) 2006 Török Edvin <edwin@clamav.net>
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
 *
 */


#include <clamav-config.h>
#include <others.h>
#include <htmlnorm.h>
#include <hashtab.h>
#include <entconv.h>
#include <regex.h>
#include <sys/types.h>
#include <dirent.h>

#define MAX_LINE 1024
/* ------------ generating entity tables from .ent files ---------------- */
/* TODO: move this into contrib/entitynorm/ ------------*/


static char* extract_str(const char* l,const regmatch_t* pmatch)
{
   const int len = pmatch->rm_eo - pmatch->rm_so;	 
   char* s ;
   if(pmatch->rm_so==-1)
	   return NULL;
   s = malloc(len+1); 
   strncpy(s, l+pmatch->rm_so, len);
   s[len] = '\0';
   return s;
}

static regex_t entity_regex;
static const char ent_head[]="<!ENTITY";
static const size_t ent_head_size = sizeof(ent_head);
static int entity_extract(const char* line,char* entity_name,int* entity_value)
{
	regmatch_t pmatch[5];

	if(regexec(&entity_regex,line,5,pmatch,0)==0) {
		const char* entity_val;
		strncpy(entity_name,extract_str(line,&pmatch[1]),MAX_LINE);
		entity_val  = extract_str(line,&pmatch[3]);
		if(entity_val[0] == 'x') {
			if(sscanf(entity_val+1,"%x",entity_value)!=1)
				return -2;
		}
		else {
			if(sscanf( entity_val,"%d",entity_value)!=1)
				return -2;
		}
		if(*entity_value > 65535) {
			fprintf(stderr,"Entity value outside of utf-16 range:%u; %s\n",*entity_value,line);
			return 0;
		}
		return 1;
	}
	else {
		if(strncmp(line,ent_head,ent_head_size-1)==0) {
			fprintf(stderr,"Unable to interpret entity decl:%s\n",line);
		}
		return 0;	
	}
}
static void loadEntitiesFromFile(const char* file,struct hashtable* s,char* xt[])
{
	char line[MAX_LINE];
	FILE* f = fopen(file,"rt");
	if(!f) {
		fprintf(stderr,"Unable to open file:%s",file);
		exit(3);
	}

	while( fgets(line,MAX_LINE,f) ) {
		unsigned char name[MAX_LINE];
		int val;
		int rc = entity_extract(line,name,&val);
		if(rc<0) {
			printf("error during extraction:%s!",line);
			exit(3);
		}
	        else if(rc) {
			struct element* elem;
			if(elem = hashtab_find(s,name,strlen(name))) {
				if(elem->data != val)
					cli_dbgmsg("Overriding entity value for %s: %d -> %d\n", name, elem->data, val);
				else {
					cli_dbgmsg("Duplicate entity value for %s:%d\n",name, elem->data);
					continue;
				}
			}
			if(xt[val] && strcmp(xt[val],name))
				cli_dbgmsg("Duplicate entity reference to same code:%s->%d<-%s\n",name,val,xt[val]);
			else if(xt[val]) {
				fprintf(stderr,"Impossible: element not found in hashtable, but we did add it!! %s:%d:%s:%p\n",xt[val],val,name,elem);
				abort();
			}
			xt[val] = strdup(name);
			hashtab_insert(s,name,strlen(name),val);
		}
	}
	fclose(f);
}


static void init_entity_parser(void)
{
	int rc;
	char errbuff[MAX_LINE];
	if(( rc = regcomp(&entity_regex,".*<!ENTITY +([^ \t]+) +\" *&(#38;)?#(([0-9]+)|x([0-9a-fA-F])+); *\" *>.*",REG_EXTENDED) )) {
		regerror(rc,&entity_regex,errbuff,MAX_LINE);
		fprintf(stderr,"Error compiling regex:%s\n",errbuff);
		exit(1);
	}
}


int main(int argc, char* argv[])
{
	struct entity_conv conv;
	const char* ent_dir;
	struct dirent* entry;
	struct hashtable ht;
	char* xt[65536];

	memset(xt,0,65536*sizeof(xt[0]));
	cl_debug();
	init_entity_parser();
	hashtab_init(&ht,512);

	if(argc<2) {
		fprintf(stderr,"Usage: %s <entity directory>\n",argv[0]);
		return 1;
	}

	ent_dir = argv[1];
	DIR* dir = opendir(ent_dir);
	if(!dir) {
		cli_errmsg("Can't open directory\n");
		return 2;
	}
	do {
		entry = readdir(dir);
		if(entry) {
			char buffer[4096];
			snprintf(buffer,4095,"%s/%s",ent_dir,entry->d_name);
			buffer[4095] = '\0';
			cli_dbgmsg("Loading entities from:%s\n", entry->d_name);
			loadEntitiesFromFile(buffer,&ht,xt);
		}
	} while(entry);
	closedir(dir);
#if 0	
	FILE* f1=fopen("/tmp/test.out","w");
	hashtab_store(&ht,f1);
	fclose(f1);
	init_entity_converter(&conv,UNKNOWN,8192);	
	FILE* f = fopen(argv[1],"rb");
	if(!f) {
		perror("FIle not found!\n");
		exit(1);
	}
	/*
	int c;
	while((c=fgetc(f))!=EOF) {
		const char* x = process_byte(&conv,c);
		if(x)
			printf("%s",x);
	}
	*/
	unsigned char* s;
	do{
		s = encoding_norm_readline(&conv, f, NULL, 8192);
		if(s)
			printf("%s",s);
		free(s);
	} while(s);
	encoding_norm_done(&conv);
	fflush(stdout);
#endif	
	hashtab_generate_c(&ht,"entities_htable");
	return 0;
}

