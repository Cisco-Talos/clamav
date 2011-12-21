#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "crtmgr.h"
#include "others.h"

int cli_crt_init(cli_crt *x509) {
    if(mp_init_multi(&x509->n, &x509->e, &x509->sig, NULL))
	return 1;
    x509->not_before = x509->not_after = 0;
    x509->prev = x509->next = NULL;
    return 0;
}

void cli_crt_clear(cli_crt *x509) {
    mp_clear_multi(&x509->n, &x509->e, &x509->sig, NULL);
}

int crtmgr_add(crtmgr *m, cli_crt *x509) {
    cli_crt *i = m->crts;
    while(i) {
	if(x509->not_before == i->not_before && x509->not_after == i->not_after && !memcmp(x509->subject, i->subject, sizeof(i->subject))) {
	    if(mp_cmp(&x509->n, &i->n) || mp_cmp(&x509->e, &i->e))
		cli_dbgmsg("crtmgr_add: conflicting pk for the same cert\n");
	    return 0;
	}
	i = i->next;
    }
    i = cli_malloc(sizeof(*i));
    if(!i)
	return 1;

    if(mp_init_multi(&i->n, &i->e, &i->sig, NULL)) {
	free(i);
	return 1;
    }
    if(mp_copy(&x509->n, &i->n) || mp_copy(&x509->e, &i->e) || mp_copy(&x509->sig, &i->sig)) {
	cli_crt_clear(i);
	free(i);
	return 1;
    }
    memcpy(i->subject, x509->subject, sizeof(i->subject));
    memcpy(i->issuer, x509->issuer, sizeof(i->issuer));
    i->not_before = x509->not_before;
    i->not_after = x509->not_after;
    i->hashtype = x509->hashtype;
    i->next = m->crts;
    i->prev = NULL;
    if(m->crts)
	m->crts->prev = i;
    m->crts = i;
    cli_dbgmsg("crtmgr_add: added cert\n");
    return 0;
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


