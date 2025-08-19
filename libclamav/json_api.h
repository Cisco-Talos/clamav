/*
 * JSON Object API
 *
 * Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include "json.h"

#include "clamav-types.h"
#include "others.h"

#define JSON_TIMEOUT_SKIP_CYCLES 3

cl_error_t cli_json_timeout_cycle_check(cli_ctx *ctx, int *toval);
cl_error_t cli_json_parse_error(json_object *root, const char *errstr);

cl_error_t cli_jsonnull(json_object *obj, const char *key);
cl_error_t cli_jsonstr(json_object *obj, const char *key, const char *s);
cl_error_t cli_jsonstrlen(json_object *obj, const char *key, const char *s, int len);
cl_error_t cli_jsonint(json_object *obj, const char *key, int32_t i);
cl_error_t cli_jsonint64(json_object *obj, const char *key, int64_t i);
cl_error_t cli_jsonuint64(json_object *obj, const char *key, uint64_t i);
cl_error_t cli_jsonbool(json_object *obj, const char *key, int i);
cl_error_t cli_jsondouble(json_object *obj, const char *key, double d);

json_object *cli_jsonarray(json_object *obj, const char *key);
cl_error_t cli_jsonint_array(json_object *obj, int32_t val);
json_object *cli_jsonobj(json_object *obj, const char *key);
cl_error_t cli_json_delowner(json_object *owner, const char *key, int idx);
#define cli_json_delobj(obj) json_object_put(obj)

#define JSON_KEY_FILETYPE "FileType"
#define JSON_KEY_FILESIZE "FileSize"

#define JSON_VALUE_FILETYPE_PDF "CL_TYPE_PDF"
#define JSON_VALUE_FILETYPE_PPT "CL_TYPE_MSPPT"
#define JSON_VALUE_FILETYPE_WORD "CL_TYPE_WORD"
#define JSON_VALUE_FILETYPE_EXCEL "CL_TYPE_MSXLS"

#endif /*__JSON_C_H__*/
