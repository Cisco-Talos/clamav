/*
 *  Copyright (C)2008 Sourcefire, Inc.
 *
 *  Author: aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libmilter/mfapi.h>

#include "shared/output.h"

#include "connpool.h"
#include "netcode.h"

uint64_t maxfilesize;

#define CLAMFIBUFSZ 1424

struct CLAMFI {
    char buffer[CLAMFIBUFSZ];
    int local;
    int main;
    int alt;
    unsigned int totsz;
    unsigned int bufsz;
};


static sfsistat sendchunk(struct CLAMFI *cf, unsigned char *bodyp, size_t len, SMFICTX *ctx) {
    if(cf->totsz >= maxfilesize)
	return SMFIS_CONTINUE; /* FIXME: SMFIS_SKIP needs negotiation (only for _body() */

    if(cf->totsz + len > maxfilesize)
	len = maxfilesize - cf->totsz;

    if(cf->local) {
	while(len) {
	    int n = write(cf->alt, bodyp, len);

	    if (n==-1) {
		logg("!Failed to write temporary file\n");
		close(cf->main);
		close(cf->alt);
		smfi_setpriv(ctx, NULL);
		free(cf);
		return SMFIS_TEMPFAIL;
	    }
	    len -= n;
	    bodyp += n;
	}
    } else {
	int sendfailed = 0;

	if(len < CLAMFIBUFSZ - cf->bufsz) {
	    memcpy(&cf->buffer[cf->bufsz], bodyp, len);
	    cf->bufsz += len;
	} else if(len < CLAMFIBUFSZ) {
	    memcpy(&cf->buffer[cf->bufsz], bodyp, CLAMFIBUFSZ - cf->bufsz);
	    sendfailed = nc_send(cf->alt, cf->buffer, CLAMFIBUFSZ);
	    len -= (CLAMFIBUFSZ - cf->bufsz);
	    memcpy(cf->buffer, &bodyp[CLAMFIBUFSZ - cf->bufsz], len);
	    cf->bufsz = len;
	} else {
	    if(nc_send(cf->alt, cf->buffer, cf->bufsz) || nc_send(cf->alt, bodyp, len))
		sendfailed = 1;
	    cf->bufsz = 0;
	}
	if(sendfailed) {
	    logg("!Streaming failed\n");
	    close(cf->main);
	    smfi_setpriv(ctx, NULL);
	    free(cf);
	    return SMFIS_TEMPFAIL;
	}
    }
    cf->totsz += len;
    return SMFIS_CONTINUE;
}


sfsistat clamfi_header(SMFICTX *ctx, char *headerf, char *headerv) {
    struct CLAMFI *cf;
    sfsistat ret;

    if(!(cf = (struct CLAMFI *)smfi_getpriv(ctx))) {
	cf = (struct CLAMFI *)malloc(sizeof(*cf));
	if(!cf) {
	    logg("!Failed to allocate CLAMFI struct\n");
	    return SMFIS_TEMPFAIL;
	}
	cf->totsz = 0;
	cf->bufsz = 0;
	if(nc_connect_rand(&cf->main, &cf->alt, &cf->local)) {
	    logg("!Failed to initiate streaming/fdpassing\n");
	    free(cf);
	    return SMFIS_TEMPFAIL;
	}
	smfi_setpriv(ctx, (void *)cf);
	if((ret = sendchunk(cf, (unsigned char *)"From clamav-milter\n", 19, ctx)) != SMFIS_CONTINUE)
	    return ret;
    }
    if((ret = sendchunk(cf, (unsigned char *)headerf, strlen(headerf), ctx)) != SMFIS_CONTINUE)
	return ret;
    if((ret = sendchunk(cf, (unsigned char *)": ", 2, ctx)) != SMFIS_CONTINUE)
	return ret;
    if((ret = sendchunk(cf, (unsigned char *)headerv, strlen(headerv), ctx)) != SMFIS_CONTINUE)
	return ret;
    return sendchunk(cf, (unsigned char *)"\r\n", 2, ctx);
}


sfsistat clamfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t len) {
    struct CLAMFI *cf;

    if(!(cf = (struct CLAMFI *)smfi_getpriv(ctx)))
	return SMFIS_CONTINUE; /* whatever */
    return sendchunk(cf, bodyp, len, ctx);
}


sfsistat clamfi_eom(SMFICTX *ctx) {
    struct CLAMFI *cf;
    char *reply;
    int len, ret;

    if(!(cf = (struct CLAMFI *)smfi_getpriv(ctx)))
	return SMFIS_CONTINUE; /* whatever */

    if(cf->local) {
	if(nc_send(cf->main, "nFILDES\n", 8)) {
	    logg("!FD scan request failed\n");
	    close(cf->alt);
	    smfi_setpriv(ctx, NULL);
	    free(cf);
	    return SMFIS_TEMPFAIL;
	}

	lseek(cf->alt, 0, SEEK_SET);

	if(nc_sendmsg(cf->main, cf->alt) == -1) {
	    logg("!FD send failed\n");
	    close(cf->alt);
	    smfi_setpriv(ctx, NULL);
	    free(cf);
	    return SMFIS_TEMPFAIL;
	}
    } else {
	if(cf->bufsz && nc_send(cf->alt, cf->buffer, cf->bufsz)) {
	    logg("!Failed to flush STREAM\n");
	    close(cf->main);
	    smfi_setpriv(ctx, NULL);
	    free(cf);
	    return SMFIS_TEMPFAIL;
	}
	close(cf->alt);
    }

    reply = nc_recv(cf->main);

    if(cf->local)
	close(cf->alt);

    if(!reply) {
	logg("!No reply from clamd\n");
	smfi_setpriv(ctx, NULL);
	free(cf);
	return SMFIS_TEMPFAIL;
    }
    close(cf->main);
    smfi_setpriv(ctx, NULL);
    free(cf);

    len = strlen(reply);
    if(len>5 && !strcmp(reply + len - 5, ": OK\n"))
	ret = SMFIS_ACCEPT;
    else if (len>7 && !strcmp(reply + len - 7, " FOUND\n"))
	ret = SMFIS_REJECT;
    else {
	logg("!Unknown reply from clamd\n");
	ret = SMFIS_TEMPFAIL;
    }

    free(reply);
    return ret;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */
