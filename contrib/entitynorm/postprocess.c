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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <clamav.h>

int main(int argc,char* argv[])
{
	char* line = NULL;
	size_t n = 0;
	int linecnt = 0;
	int line_wanted;
	int strip_color = 0;

	if(argc<2) {
		fprintf(stderr,"Usage: %s <line_wanted>|nocolor\n",argv[0]);
	}
	if(strcmp(argv[1],"nocolor")==0) 
		strip_color = 1;
	else
		line_wanted = atoi(argv[1]);

	cl_debug();
	while(getline(&line,&n,stdin)!=-1) {
		if(strchr(line,'\033')) {
			linecnt++;
			if(linecnt == line_wanted || strip_color) {
				if(strip_color) {
					do {
						char* col = strchr(line,'\033');
						if(col) {
							*col++ = '\0';
							printf("%s",line);
								line = strchr(col,'m');
								if(line) line++;
						}
						else {
							printf("%s",line);
							line = NULL;
						}
					} while(line);
				}
				else
					printf("%s",line);
			}
		}
		else {
			if(strip_color)
				printf("%s",line);
			linecnt = 0;
		}
		line=NULL;
	}

	return 0;
}

