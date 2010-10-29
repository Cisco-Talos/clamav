/*
 *  mactrans.c  -- Hack filter used to generate MPW files 
 *    with special characters from pure ASCII, denoted "%nn" 
 *    where nn is hex. (except for "%%", which is literal '%').
 *
 *  calling sequence:
 *
 *    catenate file | mactrans [-toascii | -fromascii] > output
 *
 *    Written by: Niles Ritter.
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void to_ascii(void);
void from_ascii(void);

main(int argc, char *argv[])
{
	if (argc<2 || argv[1][1]=='f') from_ascii();
	else to_ascii();
	exit (0);
}

void from_ascii(void)
{
    char c;
    int d;
    while ((c=getchar())!=EOF)
    {
    	if (c!='%' || (c=getchar())=='%') putchar(c);
	else
	{
		ungetc(c,stdin);
		scanf("%2x",&d);
		*((unsigned char *)&c) = d;
		putchar(c);
	}
    }
}

void to_ascii(void)
{
    char c;
    int d;
    while ((c=getchar())!=EOF)
    {
    	if (isascii(c)) putchar (c);
	else
	{
		d = *((unsigned char *)&c);
		printf("%%%2x",d);
	}
    }
}
