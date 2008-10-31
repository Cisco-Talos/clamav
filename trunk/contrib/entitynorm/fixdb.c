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
#include <stdio.h>
#include <stdlib.h>
#include <clamav.h>
#include <str.h>
#include <ctype.h>
#include <string.h>
#include <others.h>
#include <htmlnorm.h>

static int dehex(int c)
{
	int l;

    if(!isascii(c))
    	return -1;

    if(isdigit(c))
	return c - '0';

    l = tolower(c);
    if((l >= 'a') && (l <= 'f'))
	return l + 10 - 'a';

    cli_errmsg("hex2int() translation problem (%d)\n", l);
    return -1;
}

static const char* red = "\033[1;31m";
static const char* blue = "\033[1;34m";
static const char* green = "\033[1;32m";
static const char* magenta = "\033[1;35m";
static const char* yellow = "\033[1;33m";
static const char* color_off = "\033[0;0m";

/* TODO: for each uppercase letter add a lowercase alternative */
static const unsigned char* normalize_sig(unsigned char* sig,size_t len)
{
	const unsigned char* ret = NULL;
	const unsigned char* dir = cli_gentempdir("/tmp"); 
	unsigned char* filenam;
	FILE* f;

	html_normalise_mem(sig, len, dir , NULL);

	filenam = cli_malloc(strlen(dir)+20);
	strcpy(filenam, dir);
	strcat(filenam,"/");
	strcat(filenam,"comment.html");

	f = fopen(filenam,"rb");
	if(f) {
		long siz;
		unsigned char* buff;
		size_t iread;

		fseek(f,0,SEEK_END);
		siz = ftell(f);
		buff = cli_malloc(siz);

		fseek(f,0, SEEK_SET);

		iread = fread(buff, 1, siz, f);

		if(ferror(f))
			perror("Error while reading file!");
		fclose(f);

		ret = cli_str2hex(buff,iread);	
		free(buff);

	}
	else
		cli_dbgmsg("Unable to open:%s",filenam);

	free(filenam);		
	cli_rmdirs(dir);

	return ret;
}


static int cleanup_sig(const char* newsig, const char* sig)
{
	int up = 0;
	size_t i,j;
	cli_chomp(newsig);
	cli_chomp(sig);
	for(i=0, j=0;j < strlen(sig);) {
		int new_val;
		int old_val;
		if(!isxdigit(newsig[i]) && !isxdigit(sig[j]) && newsig[i] == sig[j]) {
			switch(sig[j]) {
				case '{':
					while (sig[j] != '}') {
						putc(sig[j++],stdout);
						i++;
					}
					putc(sig[j++],stdout);
					i++;
					break;
				case '(':
					while(sig[j] != ')') {
						putc(sig[j++],stdout);
						i++;
					}
					putc(sig[j++],stdout);
					i++;
					break;
				default:
					putc(sig[j++],stdout);
					i++;
					break;
			}
			continue;
		}

		if(isxdigit(newsig[i]) && isxdigit(newsig[i+1]) && !isxdigit(sig[j])) {
			printf("%s%c%c%s",blue,newsig[i],newsig[i+1],color_off);
			up = 1;
			i += 2;
			continue;
		}

		if(isxdigit(sig[j]) && isxdigit(sig[j+1]) && !isxdigit(newsig[i])) {
			if( (sig[j] == '2' && sig[j+1] == '0') || (sig[j]=='2' && sig[j+1] == '6'))
				printf("%c%c",sig[j],sig[j+1]);/* space, and ampersand is normal to be stripped before {,(... */
			else {
				printf("%s{-1}%s",red,color_off);
				up = 1;
			}
			j += 2;
			continue;
		}

		new_val= (dehex(newsig[i])<<4) + dehex(newsig[i+1]);
		old_val = (dehex(sig[j])<<4) + dehex(sig[j+1]);

		if(old_val != new_val || old_val==0x26 ) {/* 0x26 needs resync always*/
			int resync_needed = 0;

			if(new_val - old_val == 'a'-'A') {
				printf("%s(%02x|%02x)%s",green,old_val,new_val,color_off);
				up = 1;
				i += 2;
				j += 2;
				continue;
			}

			switch(old_val) {
				case 0x09:
				case 0x0a:
				case 0x0d:
					printf("%s{-1}%s",blue,color_off);
					/* TODO: check why this got stripped */
					j += 2;
					up = 1;
					break;
				case 0x20:
					/*strip extra space*/
					j += 2;
					break;
				case 0x26:
					resync_needed = 1;					
					break;
				default:
					switch(new_val) {
						case 0x20:
							printf("%s{-1}%s",blue,color_off);
							i += 2;
							/*TODO:implement*/
							up = 1;
							break;
						default:
							resync_needed = 1;
					}
			}/*switch old_val */
			
			if(resync_needed) {
				if(old_val >= 0x80 && new_val == 0x26) {
					int cnt = 2;
					i += 2;
					up = 1;
					j += 2;

					if(i < strlen(newsig)) {
						old_val = (dehex(sig[j])<<4) + dehex(sig[j+1]);
						new_val = (dehex(newsig[i])<<4) + dehex(newsig[i+1]);
						if(old_val >=0x80) old_val = 0x26;
						while(i < strlen(newsig) && new_val != 0x3b )  {
							i += 2;
							cnt++;
							if(i<strlen(newsig))
								new_val = (dehex(newsig[i])<<4) + dehex(newsig[i+1]);
						}
						i += 2;
						printf("%s{1-%d}%s",red, cnt, color_off);
					}
				}
				else if(old_val == '&' && new_val == '&') {
					int cnt=0;
					printf("26");
					i += 2;
					j += 2;
					while(i < strlen(newsig) && j < strlen(sig) && old_val != ';' && new_val != ';') {						
						old_val = (dehex(sig[j])<<4) + dehex(sig[j+1]);
						new_val = (dehex(newsig[i])<<4) + dehex(newsig[i+1]);
						if(old_val == new_val) {
							printf("%02x",old_val);
						}
						else  {
							printf("%s(%02x|%02x)%s",red,old_val,new_val,color_off);
							up = 1;
						}
						i += 2;
						j += 2;
						
					}
					while(old_val != 0x3b && j < strlen(sig)) {
						old_val = (dehex(sig[j])<<4) + dehex(sig[j+1]);
						j += 2;
						cnt++;
					}
					if(cnt) {
						printf("%s{0-%d}%s",red,cnt,color_off);
						up = 1;
					}
					else {
						while(new_val != 0x3b && i < strlen(newsig)) {
							new_val = (dehex(newsig[i])<<4)+ dehex(newsig[i+1]);
							i += 2;
							cnt++;
						}
						if(cnt) {
							printf("%s{0-%d}%s",red,cnt+1,color_off);
							up = 1;
						}
/*						else if(old_val == new_val) {
 *						no operation needed
						}*/
					}
				}
				else if(old_val == '&') {
					const size_t sig_len = strlen(sig);
					int cnt = 2;
					/*printf("%s(%02x|%02x)%s", red, old_val, new_val, color_off);
					i += 2;*/
					up = 1;
					j += 2;
					while(j < sig_len && old_val != 0x3b ) {
							j += 2;
							if(j < sig_len) 
								old_val = (dehex(sig[j])<<4) + dehex(sig[j+1]);
							cnt++; 
					}
					j += 2;
					printf("%s{-%d}%s",red,cnt,color_off);
				}
				else if (new_val == '&') {
					const size_t sig_len = strlen(sig);
					int cnt = 2;
					i += 2;
					up = 1;
					j += 2;
					while(j < sig_len && old_val != 0x3b ) {
							j += 2;
							if(j < sig_len) 
								old_val = (dehex(sig[j])<<4) + dehex(sig[j+1]);
							cnt++; 
					}
					j += 2;
					printf("%s{1-%d}%s",red,cnt,color_off);
				}
				else if(new_val - old_val == 'a' - 'A') {
					printf("%s(%02x|%02x)%s",green,old_val,new_val,color_off);
					i += 2;
					up = 1;
					j += 2;
				}
				else	{
					printf("%s(%02x|%02x)%s",red, old_val,new_val,color_off);
					i += 2;
					up = 1;
					j += 2;
				}
			}
		}
		else {
			printf("%02x",old_val);
			i += 2;
			j += 2;
		}
	}
	if(newsig[i]) {
		printf("%s",red);
		while(newsig[i]) {
			putc(newsig[i++],stdout);
			up = 1;
		}
		printf("%s\n",color_off);
	}
	return up;
}

int main(int argc,char* argv[])
{
	char* line=NULL;
	size_t n;
	size_t i;
	cl_debug();
	while(getline(&line,&n,stdin)!=-1) {

		const char* signame = cli_strtok(line, 0, ":");
		const char* sigtype = cli_strtok(line,1,":");
		const char* x = cli_strtok(line,2,":");
		const char* sig = cli_strtok(line,3,":");
		if(sigtype[0] == '3') {
			const size_t len = strlen(sig);
			size_t real_len = 0;
			size_t up_len = 0;
			unsigned char* outbuff = cli_malloc(len);
			unsigned char* upgraded_sig = cli_malloc(20*len);

			cli_dbgmsg("Verifying signature:%s\n",signame); 

			for(i=0; i < len ; i++) {
				if(isxdigit(sig[i])) {
					unsigned char val = (dehex(sig[i])<<4) + dehex(sig[i+1]);
					i++;
					outbuff[real_len++] = val;
				}
				else {
					const unsigned char* up = normalize_sig(outbuff, real_len);
					strncpy(upgraded_sig+up_len, up, strlen(up));
					up_len += strlen(up);
					real_len = 0;

					if(sig[i] == '{') {
						while(sig[i] != '}') {
							upgraded_sig[up_len++] = sig[i++];
						}
						upgraded_sig[up_len++] = sig[i];
					}
					else
						upgraded_sig[up_len++] = sig[i];
				}
			}

			if(real_len) {
					const unsigned char* up = normalize_sig(outbuff, real_len);
					strncpy(upgraded_sig+up_len, up, strlen(up));
					up_len += strlen(up);
					real_len = 0;
			}

			upgraded_sig[up_len] = '\0';
			printf("%s:%s:%s:",signame, sigtype, x);
			if(cleanup_sig(upgraded_sig, sig)) {
				printf("\n");
				printf("%s%s:%s:%s:%s%s\n",magenta, signame, sigtype, x, sig, color_off);
				printf("%s%s:%s:%s:%s%s\n",yellow, signame, sigtype, x, upgraded_sig, color_off);
			}
			else
				printf("\n");
			printf("\n");
#if 0			
			start =0 ;
			for(i=0, j=0;j < strlen(sig);j++) {
				if(!isxdigit(upgraded_sig[i]) && !isxdigit(sig[j])) {
					i++;
					continue;
				}
/*				cli_dbgmsg("%c%c==%c%c(%d,%d)\n",upgraded_sig[i],upgraded_sig[i+1],sig[j],sig[j+1],i,j);*/
				if(upgraded_sig[i] != sig[j] || (isxdigit(upgraded_sig[i+1]) && isxdigit(sig[j+1]) && upgraded_sig[i+1] != sig[j+1])) {
					if(((sig[j]=='2' && sig[j+1]=='0') || (sig[j] == '0' && sig[j+1] == 'a') || (sig[j] == '0' && sig[j+1]=='d') || (sig[j]=='0' && sig[j+1]=='9')|| 
								((!isxdigit(upgraded_sig[i]) &&  (sig[j]=='2' && sig[j+1]=='6'))))) 
						j++;
					else if(upgraded_sig[i]=='2' && upgraded_sig[i+1]=='0') {
						i+=2;
						j--;
					}
					else {
						cli_dbgmsg("Upgrade is needed for this signature, difference at:%ld: %c%c!=%c%c\n",i,upgraded_sig[i],upgraded_sig[i+1],sig[j],sig[j+1]);
/*						printf("%s:%s:%s:%s",signame, sigtype, x, sig);*/

						printf("%s:%s:%s:%s",signame, sigtype, x, cleanup_sig(upgraded_sig,sig) );
						break;
					}
					start = 0;
				}
				else {
					if(isxdigit(upgraded_sig[i+1]) && isxdigit(sig[j+1]))
						i++,j++;
					i++;
				}

			}
#endif			
			free(upgraded_sig);
		}
		free(signame);
		free(sig);
		free(x);
		free(line);
		line=NULL;
	}
	return 0;
}
