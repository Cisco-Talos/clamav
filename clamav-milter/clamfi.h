/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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

#ifndef _CLAMFI_H
#define _CLAMFI_H

#include "shared/optparser.h"
#include <libmilter/mfapi.h>

extern uint64_t maxfilesize;
extern int addxvirus;
extern char xvirushdr[255];
extern int multircpt;


sfsistat clamfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t len);
sfsistat clamfi_abort(SMFICTX *ctx);
sfsistat clamfi_eom(SMFICTX *ctx);
sfsistat clamfi_header(SMFICTX *ctx, char *headerf, char *headerv);
sfsistat clamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
sfsistat clamfi_envfrom(SMFICTX *ctx, char **argv);
sfsistat clamfi_envrcpt(SMFICTX *ctx, char **argv);
int init_actions(struct optstruct *opts);

#endif
