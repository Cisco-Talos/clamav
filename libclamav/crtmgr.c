#include "crtmgr.h"

int cli_crt_init(cli_crt *x509) {
    if(mp_init_multi(&x509->n, &x509->e, &x509->sig, NULL))
	return 1;
    x509->not_before = x509->not_after = 0;
    return 0;
}

void cli_crt_clear(cli_crt *x509) {
    mp_clear_multi(&x509->n, &x509->e, &x509->sig, NULL);
}

/* typedef struct { */
/*     cli_crt *certs; */
/*     unsigned int ncerts; */
/* } *crtmgr;  */

/*     /\* if(mp_init(&n) || mp_read_signed_bin(&n, obj.content, obj.size)) *\/ */


/* void crt_destroy(cli_crt *crt) { */
/*     mp_clear_multi(&crt->n, &crt->e); */
/*     free(crt); */
/* } */

/* void crt_set_issuer(cli_crt *crt, const char issuer[SHA1_HASH_SIZE]) { */
/*     memcpy(crt->issuer, issuer, sizeof(issuer)); */
/* } */

/* int crt_set_rsa(cli_crt *crt, int exp, void *bn, unsigned int bn_len) { */
/*     if(mp_read_signed_bin(exp ? &crt->e : &crt->n, bn, bn_len)) */
/* 	return 1; */
/*     return 0; */
/* } */

/* void crt_set_validity(cli_crt *crt, int before, time_t t) { */
/*     if(before) */
/* 	crt->not_before = t; */
/*     else */
/* 	crt->not_after = t; */
/* } */


