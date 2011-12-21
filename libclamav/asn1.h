#ifndef __ASN1_H
#define __ASN1_H

#include <stdio.h>
#include <time.h>

#include "fmap.h"
#include "sha1.h"
#include "crtmgr.h"

struct cli_asn1 {
    uint8_t type;
    unsigned int size;
    void *content;
    void *next;
};

int asn1_get_obj(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj);
int asn1_expect_objtype(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj, uint8_t type);
int asn1_expect_obj(fmap_t *map, void *asn1data, unsigned int *asn1len, struct cli_asn1 *obj, uint8_t type, unsigned int size, const void *content);
int asn1_expect_algo(fmap_t *map, void **asn1data, unsigned int *asn1len, unsigned int algo_size, const void *algo);
int ms_asn1_get_sha1(fmap_t *map, void *asn1data, unsigned int avail, unsigned int emb, uint8_t sha1[SHA1_HASH_SIZE], unsigned int *len);
int asn1_get_time(fmap_t *map, void **asn1data, unsigned int *size, time_t *time);
int asn1_get_rsa_pubkey(fmap_t *map, void **asn1data, unsigned int *size, cli_crt *x509);
int asn1_get_x509(fmap_t *map, void **asn1data, unsigned int *size, cli_crt *x509);
int asn1_parse_mscat(FILE *f, crtmgr *c);

#endif
