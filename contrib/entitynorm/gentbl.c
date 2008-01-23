#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char* argv[])
{
	int i;
	uint8_t tbl[256];
	if(argc < 3) {
		fprintf(stderr, "Usage: %s <variable-name> <character-range|single-char> ...\n", argv[0]);
		return 1;
	}
	memset(tbl, 0, sizeof(tbl));
	for(i=2;i<argc;i++) {
		const char* v = argv[i];
		tbl[*v] = 1;
		if(v[1] == '-') {
			int j;
			for(j=v[0]+1;j<=v[2];j++) {
				tbl[j]=1;
			}
		} else if(v[1]){
			fprintf(stderr,"Invalid char range spec:%s\n",v);
			return 2;
		}
	}
	printf("/*");
	for(i=0;i<sizeof(tbl);i++) {
		if(tbl[i]) putc(i, stdout);
	}
	printf("*/\n");
	printf("static const uint8_t %s[256] = {\n\t", argv[1]);
	for(i=0;i<sizeof(tbl);i++) {
		printf("%d",tbl[i]);
		if(i!=sizeof(tbl)-1) {
			putc(',', stdout);
			if(i%16==15)
				fputs("\n\t",stdout);
			else
				putc(' ', stdout);
		} else {
			putc('\n',stdout);
		}
	}
	printf("};\n");

	return 0;
}
