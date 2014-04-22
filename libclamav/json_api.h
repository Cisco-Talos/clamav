/*
 * JSON Object API
 * 
 * Copyright (C) 2014 Cisco Systems, Inc.
 * 
 * Authors: Kevin Lin
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __JSON_C_H__
#define __JSON_C_H__

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "cltypes.h"
#include "others.h"

#ifdef HAVE_JSON
int cli_jsonnull(json_object *obj, const char* key);
int cli_jsonstr(json_object *obj, const char* key, const char* s);
int cli_jsonint(json_object *obj, const char* key, int32_t val);
int cli_jsonint64(json_object *obj, const char* key, int64_t i);
int cli_jsonbool(json_object *obj, const char* key, int i);
int cli_jsondouble(json_object *obj, const char* key, double d);
#else
#define cli_jsonnull(o,n)     cli_dbgmsg("%s: null\n", n)
#define cli_jsonstr(o,n,s)    cli_dbgmsg("%s: \"%s\"\n", n, s)
#define cli_jsonint(o,n,i)    cli_dbgmsg("%s: %d [%x]\n", n, i, i)
#define cli_jsonint64(o,n,i)  cli_dbgmsg("%s: %lld [%llx]\n", n, i, i)
#define cli_jsonbool(o,n,b)   cli_dbgmsg("%s: %s\n", n, b ? "true":"false")
#define cli_jsondouble(o,n,d) cli_dbgmsg("%s: %f\n", n, d)
#endif

#endif /*__JSON_C_H__*/
