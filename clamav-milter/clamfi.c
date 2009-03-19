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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#include <libmilter/mfapi.h>

#include "shared/optparser.h"
#include "shared/output.h"

#include "connpool.h"
#include "netcode.h"
#include "whitelist.h"
#include "clamfi.h"

#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#define _UNUSED_ __attribute__ ((__unused__))
#else
#define _UNUSED_
#endif

uint64_t maxfilesize;

static sfsistat FailAction;
static sfsistat (*CleanAction)(SMFICTX *ctx);
static sfsistat (*InfectedAction)(SMFICTX *ctx);
static char *rejectfmt = NULL;

int addxvirus = 0;
char xvirushdr[255];
enum {
    LOGINF_NONE,
    LOGINF_BASIC,
    LOGINF_FULL
} loginfected;

#define CLAMFIBUFSZ 1424

struct CLAMFI {
    char buffer[CLAMFIBUFSZ];
    const char *virusname;
    char *msg_subj;
    char *msg_date;
    char *msg_id;
    int local;
    int main;
    int alt;
    unsigned int totsz;
    unsigned int bufsz;
    unsigned int all_whitelisted;
};


static void add_x_header(SMFICTX *ctx, char *st) {
    smfi_chgheader(ctx, (char *)"X-Virus-Scanned", 1, xvirushdr);
    smfi_chgheader(ctx, (char *)"X-Virus-Status", 1, st);
}

enum CFWHAT {
    CF_NONE, /* 0 */
    CF_MAIN, /* 1 */
    CF_ALT,  /* 2 */
    CF_BOTH, /* 3 */
    CF_ANY   /* 4 */
};


void makesanehdr(char *hdr) {
    while(*hdr) {
	if(*hdr=='\'' || *hdr=='\t' || *hdr=='\r' || *hdr=='\n' || !isprint(*hdr))
	    *hdr = ' ';
	hdr++;
    }
}

static void nullify(SMFICTX *ctx, struct CLAMFI *cf, enum CFWHAT closewhat) {
    if(closewhat & CF_MAIN || ((closewhat & CF_ANY) && cf->main >= 0))
	close(cf->main);
    if(closewhat & CF_ALT || ((closewhat & CF_ANY) && cf->alt >= 0))
	close(cf->alt);
    if(cf->msg_subj) free(cf->msg_subj);
    if(cf->msg_date) free(cf->msg_date);
    if(cf->msg_id) free(cf->msg_id);
    smfi_setpriv(ctx, NULL);
    free(cf);
}


static sfsistat sendchunk(struct CLAMFI *cf, unsigned char *bodyp, size_t len, SMFICTX *ctx) {
    if(cf->totsz >= maxfilesize)
	return SMFIS_CONTINUE;

    if(cf->totsz + len > maxfilesize)
	len = maxfilesize - cf->totsz;

    cf->totsz += len;
    if(cf->local) {
	while(len) {
	    int n = write(cf->alt, bodyp, len);

	    if (n==-1) {
		logg("!Failed to write temporary file\n");
		nullify(ctx, cf, CF_BOTH);
		return FailAction;
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
	    nullify(ctx, cf, CF_MAIN);
	    return FailAction;
	}
    }
    return SMFIS_CONTINUE;
}


sfsistat clamfi_header(SMFICTX *ctx, char *headerf, char *headerv) {
    struct CLAMFI *cf;
    sfsistat ret;

    if(!(cf = (struct CLAMFI *)smfi_getpriv(ctx)))
	return SMFIS_CONTINUE; /* whatever */

    if(loginfected == LOGINF_FULL) {
	if(headerf && !strcasecmp(headerf, "Subject") && !cf->msg_subj)
	    cf->msg_subj = strdup(headerv);
	if(headerf && !strcasecmp(headerf, "Date") && !cf->msg_date)
	    cf->msg_date = strdup(headerv);
	if(headerf && !strcasecmp(headerf, "Message-ID") && !cf->msg_id)
	    cf->msg_id = strdup(headerv);
    }

    if(!cf->totsz) {
	if(cf->all_whitelisted) {
	    logg("*Skipping scan (all destinations whitelisted)\n");
	    nullify(ctx, cf, CF_NONE);
	    return SMFIS_ACCEPT;
	}
	if(nc_connect_rand(&cf->main, &cf->alt, &cf->local)) {
	    logg("!Failed to initiate streaming/fdpassing\n");
	    nullify(ctx, cf, CF_NONE);
	    return FailAction;
	}
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


sfsistat clamfi_abort(SMFICTX *ctx) {
    struct CLAMFI *cf;

    if((cf = (struct CLAMFI *)smfi_getpriv(ctx)))
	nullify(ctx, cf, CF_ANY);
    return SMFIS_CONTINUE;
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
	    nullify(ctx, cf, CF_ALT);
	    return FailAction;
	}

	lseek(cf->alt, 0, SEEK_SET);

	if(nc_sendmsg(cf->main, cf->alt) == -1) {
	    logg("!FD send failed\n");
	    nullify(ctx, cf, CF_ALT);
	    return FailAction;
	}
    } else {
	if(cf->bufsz && nc_send(cf->alt, cf->buffer, cf->bufsz)) {
	    logg("!Failed to flush STREAM\n");
	    nullify(ctx, cf, CF_MAIN);
	    return FailAction;
	}
	close(cf->alt);
    }

    reply = nc_recv(cf->main);

    if(cf->local)
	close(cf->alt);

    cf->alt = -1;

    if(!reply) {
	logg("!No reply from clamd\n");
	nullify(ctx, cf, CF_NONE);
	return FailAction;
    }

    len = strlen(reply);
    if(len>5 && !strcmp(reply + len - 5, ": OK\n")) {
	if(addxvirus) add_x_header(ctx, "Clean");
	ret = CleanAction(ctx);
    } else if (len>7 && !strcmp(reply + len - 7, " FOUND\n")) {
	cf->virusname = NULL;
	if(loginfected || addxvirus || rejectfmt) {
	    char *vir;

	    reply[len-7] = '\0';
	    vir = strrchr(reply, ' ');
	    if(vir) {
		vir++;

		if(rejectfmt)
		    cf->virusname = vir;

		if(addxvirus) {
		    char msg[255];
		    snprintf(msg, sizeof(msg), "Infected (%s)", vir);
		    msg[sizeof(msg)-1] = '\0';
		    add_x_header(ctx, msg);
		}

		if(loginfected) {
		    const char *from = smfi_getsymval(ctx, "{mail_addr}"), *to = smfi_getsymval(ctx, "{rcpt_addr}");
		    
		    if(!from) from = "UNKNOWN";
		    if(!to) to = "UNKNOWN";
		    
		    if(loginfected == LOGINF_FULL) {
			const char *id = smfi_getsymval(ctx, "{i}");

			makesanehdr(cf->msg_subj);
			makesanehdr(cf->msg_date);
			makesanehdr(cf->msg_id);
			logg("~Message %s from <%s> to <%s> with subject '%s' message-id '%s' date '%s' infected by %s\n", id ? id : "UNKNOWN", from, to, cf->msg_subj, cf->msg_id, cf->msg_date, vir);
		    } else logg("~Message from <%s> to <%s> infected by %s\n", from, to, vir);
		}
	    }
	}
	ret = InfectedAction(ctx);
    } else {
	logg("!Unknown reply from clamd\n");
	ret = FailAction;
    }

    nullify(ctx, cf, CF_MAIN);

    free(reply);
    return ret;
}


sfsistat clamfi_connect(_UNUSED_ SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
    while(1) {
	/* Postfix doesn't seem to honor passing a NULL hostaddr and hostname
	   set to "localhost" for non-smtp messages (they still appear as SMTP
	   messages from 127.0.0.1). Here's a small workaround. */
	if(hostaddr) {
	    if(islocalnet_sock(hostaddr)) {
		logg("*Skipping scan for %s (in LocalNet)\n", hostname);
		return SMFIS_ACCEPT;
	    }
	    break;
	}
	if(!strcasecmp(hostname, "localhost"))
	    hostname = NULL;
	if(islocalnet_name(hostname)) {
	    logg("*Skipping scan for %s (in LocalNet)\n", hostname ? hostname : "local");
	    return SMFIS_ACCEPT;
	}
	break;
    }
    return SMFIS_CONTINUE;
}


static int parse_action(char *action) {
    if(!strcasecmp(action, "Accept"))
	return 0;
    if(!strcasecmp(action, "Defer"))
	return 1;
    if(!strcasecmp(action, "Reject"))
	return 2;
    if(!strcasecmp(action, "Blackhole"))
	return 3;
    if(!strcasecmp(action, "Quarantine"))
	return 4;
    logg("!Unknown action %s\n", action);
    return -1;
}


static sfsistat action_accept(_UNUSED_ SMFICTX *ctx) {
    return SMFIS_ACCEPT;
}
static sfsistat action_defer(_UNUSED_ SMFICTX *ctx) {
    return SMFIS_TEMPFAIL;
}
static sfsistat action_reject(_UNUSED_ SMFICTX *ctx) {
    return SMFIS_REJECT;
}
static sfsistat action_blackhole(_UNUSED_ SMFICTX *ctx)  {
    return SMFIS_DISCARD;
}
static sfsistat action_quarantine(SMFICTX *ctx) {
    if(smfi_quarantine(ctx, "quarantined by clamav-milter") != MI_SUCCESS) {
	logg("^Failed to quarantine message\n");
	return SMFIS_TEMPFAIL;
    }
    return SMFIS_ACCEPT;
}
static sfsistat action_reject_msg(SMFICTX *ctx) {
    struct CLAMFI *cf;
    char buf[1024];

    if(!rejectfmt || !(cf = (struct CLAMFI *)smfi_getpriv(ctx)))
	return SMFIS_REJECT;

    snprintf(buf, sizeof(buf), rejectfmt, cf->virusname);
    buf[sizeof(buf)-1] = '\0';
    smfi_setreply(ctx, "550", "5.7.1", buf);
    return SMFIS_REJECT;
}

int init_actions(struct optstruct *opts) {
    const struct optstruct *opt;

    if(!(opt = optget(opts, "LogInfected"))->enabled || !strcasecmp(opt->strarg, "Off"))
	loginfected = LOGINF_NONE;
    else if(!strcasecmp(opt->strarg, "Basic"))
	loginfected = LOGINF_BASIC;
    else if(!strcasecmp(opt->strarg, "Full"))
	loginfected = LOGINF_FULL;
    else {
	logg("!Invalid setting %s for option LogInfected\n", opt->strarg);
	return 1;
    }

    if((opt = optget(opts, "OnFail"))->enabled) {
	switch(parse_action(opt->strarg)) {
	case 0:
	    FailAction = SMFIS_ACCEPT;
	    break;
	case 1:
	    FailAction = SMFIS_TEMPFAIL;
	    break;
	case 2:
	    FailAction = SMFIS_REJECT;
	    break;
	default:
	    logg("!Invalid action %s for option OnFail\n", opt->strarg);
	    return 1;
	}
    } else FailAction = SMFIS_TEMPFAIL;

    if((opt = optget(opts, "OnClean"))->enabled) {
	switch(parse_action(opt->strarg)) {
	case 0:
	    CleanAction = action_accept;
	    break;
	case 1:
	    CleanAction = action_defer;
	    break;
	case 2:
	    CleanAction = action_reject;
	    break;
	case 3:
	    CleanAction = action_blackhole;
	    break;
	case 4:
	    CleanAction = action_quarantine;
	    break;
	default:
	    logg("!Invalid action %s for option OnClean\n", opt->strarg);
	    return 1;
	}
    } else CleanAction = action_accept;

    if((opt = optget(opts, "OnInfected"))->enabled) {
	switch(parse_action(opt->strarg)) {
	case 0:
	    InfectedAction = action_accept;
	    break;
	case 1:
	    InfectedAction = action_defer;
	    break;
	case 3:
	    InfectedAction = action_blackhole;
	    break;
	case 4:
	    InfectedAction = action_quarantine;
	    break;
	case 2:
	    InfectedAction = action_reject_msg;
	    if((opt = optget(opts, "RejectMsg"))->enabled) {
		const char *src = opt->strarg;
		char *dst, c;
		int gotpctv = 0;

		rejectfmt = dst = malloc(strlen(src) * 4 + 1);
		if(!dst) {
		    logg("!Failed to allocate memory for RejectMsg\n");
		    return 1;
		}
		while ((c = *src++)) {
		    if(!isprint(c)) {
			logg("!RejectMsg contains non printable characters\n");
			free(rejectfmt);
			return 1;
		    }
		    *dst++ = c;
		    if(c == '%') {
			if(*src == 'v') {
			    if(gotpctv) {
				logg("!%%v may appear at most once in RejectMsg\n");
				free(rejectfmt);
				return 1;
			    }
			    gotpctv |= 1;
			    src++;
			    *dst++ = 's';
			} else {
			    dst[0] = dst[1] = dst[2] = '%';
			    dst += 3;
			}
		    }
		}
		*dst = '\0';
	    }
	    break;
	default:
	    logg("!Invalid action %s for option OnInfected\n", opt->strarg);
	    return 1;
	}
    } else InfectedAction = action_quarantine;
    return 0;
}


sfsistat clamfi_envfrom(SMFICTX *ctx, char **argv) {
    struct CLAMFI *cf;

    if(whitelisted(argv[0], 1)) {
	logg("*Skipping scan for %s (whitelisted from)\n", argv[0]);
	return SMFIS_ACCEPT;
    }
    
    if(!(cf = (struct CLAMFI *)malloc(sizeof(*cf)))) {
	logg("!Failed to allocate CLAMFI struct\n");
	return FailAction;
    }
    cf->totsz = 0;
    cf->bufsz = 0;
    cf->main = cf->alt = -1;
    cf->all_whitelisted = 1;
    cf->msg_subj = cf->msg_date = cf->msg_id = NULL;
    smfi_setpriv(ctx, (void *)cf);

    return SMFIS_CONTINUE;
}


sfsistat clamfi_envrcpt(SMFICTX *ctx, char **argv) {
    struct CLAMFI *cf;

    if(!(cf = (struct CLAMFI *)smfi_getpriv(ctx)))
	return SMFIS_CONTINUE; /* whatever */

    if(cf->all_whitelisted)
	cf->all_whitelisted &= whitelisted(argv[0], 0);
    return SMFIS_CONTINUE;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */
