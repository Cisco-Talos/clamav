/*
 *   Phishing detection automated testing & tools.
 *
 *  Copyright (C) 2006 Torok Edvin <edwintorok@gmail.com>
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
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include "whitelist.h"
void show_time(struct timeval tv1,struct timeval tv2)
{
	struct timeval diff;
	diff.tv_sec = tv2.tv_sec-tv1.tv_sec;
	diff.tv_usec = tv2.tv_usec-tv1.tv_usec;
	if(diff.tv_usec>0) {
		diff.tv_sec += diff.tv_usec/1000000;
		diff.tv_usec %= 1000000;
	}
	else {
		int x = diff.tv_usec/1000000;//<0
		diff.tv_sec += x-1;
		diff.tv_usec -= (x-1)*1000000;
	}
	printf("%d.%06d,",diff.tv_sec,diff.tv_usec);
}
int main(int argc,char* argv[])
{
	if(argc<2)
		return 1;
	FILE* f=fopen("whitelist.wdb","rb");
	init_whitelist();
	printf("%d,",load_whitelist(f));
	struct timeval tv0,tv01;
	gettimeofday(&tv0,NULL);
	build_whitelist();
	gettimeofday(&tv01,NULL);
	show_time(tv0,tv01);
	fclose(f);
	FILE* f2=fopen(argv[1],"rb");
	fseek(f2,0,SEEK_END);
	long p=ftell(f2);
	fseek(f2,0,SEEK_SET);
	char* x = malloc(p+1);
	if(fread(x,p,1,f2)!=1)
		return 2;
	x[p]=0;
	fclose(f2);
	struct timeval tv1,tv2,diff;
	gettimeofday(&tv1,NULL);
	int rc=whitelist_match(x,"test",0);
	gettimeofday(&tv2,NULL);
	show_time(tv1,tv2);
	printf("%d\n",rc);
	free(x);
	whitelist_done();
/*	const char* real = "http://pics.ebaystatic.com/";
	const char* display = "http://www.ebay.com/";
	printf("%d\n",whitelist_match(real,display,0));*/
	return 0;
}
