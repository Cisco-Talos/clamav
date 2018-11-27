/*
 * Author: 웃 Sebastian Andrzej Siewior
 * Summary: Glue code for libmspack handling.
 * 
 * Acknowledgements: ClamAV uses Stuart Caie's libmspack to parse as number of 
 *                   Microsoft file formats.
 * ✉ sebastian @ breakpoint ̣cc
 */

#ifndef __LIBMSPACK_H__
#define __LIBMSPACK_H__

int cli_scanmscab(cli_ctx *ctx, off_t sfx_offset);
int cli_scanmschm(cli_ctx *ctx);

#endif
