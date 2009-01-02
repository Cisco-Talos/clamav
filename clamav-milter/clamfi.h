#ifndef _CLAMFI_H
#define _CLAMFI_H

#include "shared/optparser.h"
#include <libmilter/mfapi.h>

extern uint64_t maxfilesize;
extern int addxvirus;
extern char xvirushdr[255];


sfsistat clamfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t len);
sfsistat clamfi_eom(SMFICTX *ctx);
sfsistat clamfi_header(SMFICTX *ctx, char *headerf, char *headerv);
sfsistat clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
sfsistat clamfi_envfrom(SMFICTX *ctx, char **argv);
sfsistat clamfi_envrcpt(SMFICTX *ctx, char **argv);
int init_actions(struct optstruct *opts);

#endif
