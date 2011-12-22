#ifndef __CRTMGR_H
#define __CRTMGR_H

#include <time.h>

#include "bignum.h"
#include "sha1.h"

typedef enum { CLI_SHA1RSA, CLI_MD5RSA } cli_crt_hashtype;


typedef struct cli_crt_t {
    uint8_t subject[SHA1_HASH_SIZE];
    uint8_t issuer[SHA1_HASH_SIZE];
    uint8_t tbshash[SHA1_HASH_SIZE];
    mp_int n;
    mp_int e;
    mp_int sig;
    time_t not_before;
    time_t not_after;
    cli_crt_hashtype hashtype;
    struct cli_crt_t *prev;
    struct cli_crt_t *next;
} cli_crt;

typedef struct {
    cli_crt *crts;
} crtmgr;


int cli_crt_init(cli_crt *x509);
void cli_crt_clear(cli_crt *x509);
int crtmgr_add(crtmgr *m, cli_crt *x509);
cli_crt *crtmgr_lookup(crtmgr *m, cli_crt *x509);
int crtmgr_verify(crtmgr *m, cli_crt *x509);
int crtmgr_add_roots(crtmgr *m);

#endif
