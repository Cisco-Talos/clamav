#ifndef __CRTMGR_H
#define __CRTMGR_H

#include <time.h>

#include "bignum.h"
#include "sha1.h"

typedef enum { CLI_SHA1RSA, CLI_MD5RSA } cli_crt_hashtype;


typedef struct {
    uint8_t subject[SHA1_HASH_SIZE];
    uint8_t issuer[SHA1_HASH_SIZE];
    mp_int n;
    mp_int e;
    mp_int sig;
    time_t not_before;
    time_t not_after;
    cli_crt_hashtype hashtype;
} cli_crt;

int cli_crt_init(cli_crt *x509);
void cli_crt_clear(cli_crt *x509);

#endif
