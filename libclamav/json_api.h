/*
 * JSON Object API
 * 
 * Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if HAVE_JSON
#include "json.h"
#endif

#include "clamav-types.h"
#include "others.h"

#if HAVE_JSON
#define JSON_TIMEOUT_SKIP_CYCLES 3

int cli_json_timeout_cycle_check(cli_ctx *ctx, int *toval);
int cli_json_parse_error(json_object *root, const char *errstr);

int cli_jsonnull(json_object *obj, const char* key);
int cli_jsonstr(json_object *obj, const char* key, const char* s);
int cli_jsonstrlen(json_object *obj, const char* key, const char* s, int len);
int cli_jsonint(json_object *obj, const char* key, int32_t i);
int cli_jsonint64(json_object *obj, const char* key, int64_t i);
int cli_jsonbool(json_object *obj, const char* key, int i);
int cli_jsondouble(json_object *obj, const char* key, double d);

json_object *cli_jsonarray(json_object *obj, const char *key);
int cli_jsonint_array(json_object *obj, int32_t val);
json_object *cli_jsonobj(json_object *obj, const char *key);
int cli_json_addowner(json_object *owner, json_object *child, const char *key, int idx);
int cli_json_delowner(json_object *owner, const char *key, int idx);
#define cli_json_delobj(obj)  json_object_put(obj)

#if HAVE_DEPRECATED_JSON
int json_object_object_get_ex(struct json_object *obj, const char *key, struct json_object **value);
#endif

#define JSON_KEY_FILETYPE   "FileType"
#define JSON_KEY_FILESIZE   "FileSize"

#define JSON_VALUE_FILETYPE_PDF     "CL_TYPE_PDF"
#define JSON_VALUE_FILETYPE_PPT     "CL_TYPE_MSPPT"
#define JSON_VALUE_FILETYPE_WORD    "CL_TYPE_WORD"
#define JSON_VALUE_FILETYPE_EXCEL   "CL_TYPE_MSXLS"

#else
#define nojson_func cli_dbgmsg

/* internal functions */
int cli_json_nojson(void);

int cli_jsonnull_nojson(const char* key);
int cli_jsonstr_nojson(const char* key, const char* s);
int cli_jsonstrlen_nojson(const char* key, const char* s, int len);
int cli_jsonint_nojson(const char* key, int32_t i);
int cli_jsonint64_nojson(const char* key, int64_t i);
int cli_jsonbool_nojson(const char* key, int i);
int cli_jsondouble_nojson(const char* key, double d);
void *cli_jsonarray_nojson(const char *key);
int cli_jsonint_array_nojson(int32_t val);

#define cli_jsonnull(o,n)          cli_jsonnull_nojson(n)
#define cli_jsonstr(o,n,s)         cli_jsonstr_nojson(n,s)
#define cli_jsonstrlen(o,n,s,len)  cli_jsonstrlen_nojson(n,s,len)
#define cli_jsonint(o,n,i)         cli_jsonint_nojson(n,i)
#define cli_jsonint64(o,n,i)       cli_jsonint64_nojson(n,i)
#define cli_jsonbool(o,n,b)        cli_jsonbool_nojson(n,b)
#define cli_jsondouble(o,n,d)      cli_jsondouble_nojson(n,d)
#define cli_jsonarray(o,k)         cli_jsonarray_nojson(k)
#define cli_jsonint_array(o,v)     cli_jsonint_array_nojson(v)
#define cli_json_addowner(o,c,k,i) cli_json_nojson()
#define cli_json_delowner(o,k,i)   cli_json_nojson()
#define cli_json_delobj(o)         cli_json_nojson()

#endif

#endif /*__JSON_C_H__*/
