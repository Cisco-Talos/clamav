#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CLAMUKO
/* Dazuko Interface. Interace with Dazuko 1.x for file access control.
   Written by John Ogness <jogness@antivir.de>

   Copyright (c) 2003, 2004 H+BEDV Datentechnik GmbH
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. Neither the name of Dazuko nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef DAZUKOIO_COMPAT12_H
#define DAZUKOIO_COMPAT12_H

#include "dazukoio_xp.h"
#include "dazukoio.h"

int dazukoRegister_TS_compat12_wrapper(struct dazuko_id **dazuko_id, const char *groupName);
int dazukoRegister_TS_compat12(struct dazuko_id *dazuko, const char *groupName);
int dazukoSetAccessMask_TS_compat12(struct dazuko_id *dazuko, unsigned long accessMask);
int dazuko_set_path_compat12(struct dazuko_id *dazuko, const char *path, int command);
int dazukoAddIncludePath_TS_compat12(struct dazuko_id *dazuko, const char *path);
int dazukoAddExcludePath_TS_compat12(struct dazuko_id *dazuko, const char *path);
int dazukoRemoveAllPaths_TS_compat12(struct dazuko_id *dazuko);
int dazukoGetAccess_TS_compat12_wrapper(struct dazuko_id *dazuko, struct dazuko_access **acc);
int dazukoGetAccess_TS_compat12(struct dazuko_id *dazuko, struct access_compat12 *acc);
int dazukoReturnAccess_TS_compat12_wrapper(struct dazuko_id *dazuko, struct dazuko_access **acc, int return_access, int free_access);
int dazukoReturnAccess_TS_compat12(struct dazuko_id *dazuko, struct access_compat12 *acc);
int dazukoUnregister_TS_compat12_wrapper(struct dazuko_id **dazuko_id);
int dazukoUnregister_TS_compat12(struct dazuko_id *dazuko);

#endif
#endif
