#ifndef __CACHE_H
#define __CACHE_H

#include "others.h"

int cache_init(unsigned int entries);
int cache_check(unsigned char *md5, cli_ctx *ctx);
void cache_add(unsigned char *md5, cli_ctx *ctx);
int cache_chekdesc(int desc, size_t size, unsigned char *hash, cli_ctx *ctx);

#endif
