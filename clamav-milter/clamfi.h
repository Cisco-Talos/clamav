#ifndef _CLAMFI_H
#define _CLAMFI_H

#include <libmilter/mfapi.h>

uint64_t maxfilesize;

sfsistat clamfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t len);
sfsistat clamfi_eom(SMFICTX *ctx);
sfsistat clamfi_header(SMFICTX *ctx, char *headerf, char *headerv);
#endif
