/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * See md5.c for more information.
 */

#ifndef __MD5_H
#define __MD5_H

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} cli_md5_ctx;

extern void cli_md5_init(cli_md5_ctx *ctx);
extern void cli_md5_update(cli_md5_ctx *ctx, void *data, unsigned long size);
extern void cli_md5_final(unsigned char *result, cli_md5_ctx *ctx);

#endif
