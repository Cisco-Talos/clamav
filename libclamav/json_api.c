/*
 * JSON Object API
 * 
 * Copyright (C) 2014 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "json_api.h"

#ifdef HAVE_JSON
int cli_json_timeout_cycle_check(cli_ctx *ctx, int *toval)
{
    if (ctx->options & CL_SCAN_FILE_PROPERTIES) {
        if (*toval <= 0) {
            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_errmsg("cli_json_timeout_cycle_check: timeout!\n");
                return CL_ETIMEOUT;
            }
            (*toval)++;
        }
        if (*toval > JSON_TIMEOUT_SKIP_CYCLES) {
            (*toval) = 0;
        }
    }
    return CL_SUCCESS;
}

int cli_json_parse_error(json_object *root, const char *errstr)
{
    json_object *perr;

    if (!root)
        return CL_SUCCESS; /* CL_ENULLARG? */

    perr = cli_jsonarray(root, "ParseErrors");
    if (perr == NULL) {
        return CL_EMEM;
    }

    return cli_jsonstr(perr, NULL, errstr);
}

int cli_jsonnull(json_object *obj, const char* key)
{
    json_type objty;
    json_object *fpobj = NULL;
    if (NULL == obj) {
        cli_dbgmsg("json: null 'obj' specified to cli_jsonnull\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsonnull\n");
            return CL_ENULLARG;
        }

        json_object_object_add(obj, key, fpobj);
    }
    else if (objty == json_type_array) {
        json_object_array_add(obj, fpobj);
    }

    return CL_SUCCESS;
}

int cli_jsonstr(json_object *obj, const char* key, const char* s)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: null 'obj' specified to cli_jsonstr\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as 'key' to cli_jsonstr\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    if (NULL == s) {
        cli_dbgmsg("json: null string specified as 's' to  cli_jsonstr\n");
        return CL_ENULLARG;
    }

    fpobj = json_object_new_string(s);
    if (NULL == fpobj) {
        cli_errmsg("json: no memory for json string object\n");
        return CL_EMEM;
    }

    if (objty == json_type_object)
        json_object_object_add(obj, key, fpobj);
    else if (objty == json_type_array)
        json_object_array_add(obj, fpobj);

    return CL_SUCCESS;
}

int cli_jsonstrlen(json_object *obj, const char* key, const char* s, int len)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: null 'obj' specified to cli_jsonstr\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as 'key' to cli_jsonstr\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    if (NULL == s) {
        cli_dbgmsg("json: null string specified as 's' to  cli_jsonstr\n");
        return CL_ENULLARG;
    }

    fpobj = json_object_new_string_len(s, len);
    if (NULL == fpobj) {
        cli_errmsg("json: no memory for json string object\n");
        return CL_EMEM;
    }

    if (objty == json_type_object)
        json_object_object_add(obj, key, fpobj);
    else if (objty == json_type_array)
        json_object_array_add(obj, fpobj);

    return CL_SUCCESS;
}

int cli_jsonint(json_object *obj, const char* key, int32_t i)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: no parent object specified to cli_jsonint\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {    
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsonint\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    fpobj = json_object_new_int(i);
    if (NULL == fpobj) {
        cli_errmsg("json: no memory for json int object\n");
        return CL_EMEM;
    }

    if (objty == json_type_object)
        json_object_object_add(obj, key, fpobj);
    else if (objty == json_type_array)
        json_object_array_add(obj, fpobj);

    return CL_SUCCESS;
}

#ifdef JSON10
int cli_jsonint64(json_object *obj, const char* key, int64_t i)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: no parent object specified to cli_jsonint64\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsonint64\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    fpobj = json_object_new_int64(i);
    if (NULL == fpobj) {
        cli_errmsg("json: no memory for json int object.\n");
        return CL_EMEM;
    }

    if (objty == json_type_object)
        json_object_object_add(obj, key, fpobj);
    else if (objty == json_type_array)
        json_object_array_add(obj, fpobj);

    return CL_SUCCESS;
}
#else
int cli_jsonint64(json_object *obj, const char* key, int64_t i)
{
    json_type objty;
    int32_t li, hi;
    json_object *fpobj0, *fpobj1;
    json_object *fparr;
    if (NULL == obj) {
        cli_dbgmsg("json: no parent object specified to cli_jsonint64\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsonint64\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    fparr = json_object_new_array();
    if (NULL == fparr) {
        cli_errmsg("json: no memory for json array object.\n");
        return CL_EMEM;
    }

    hi = (uint32_t)((i & 0xFFFFFFFF00000000) >> 32);
    li = (uint32_t)(i & 0xFFFFFFFF);

    fpobj0 = json_object_new_int(li);
    if (NULL == fpobj0) {
        cli_errmsg("json: no memory for json int object.\n");
        json_object_put(fparr);
        return CL_EMEM;
    }
    fpobj1 = json_object_new_int(hi);
    if (NULL == fpobj1) {
        cli_errmsg("json: no memory for json int object.\n");
        json_object_put(fparr);
        json_object_put(fpobj0);
        return CL_EMEM;
    }

    /* little-endian array */
    json_object_array_add(fparr, fpobj0);
    json_object_array_add(fparr, fpobj1);
    if (objty == json_type_object)
        json_object_object_add(obj, key, fparr);
    else if (objty == json_type_array)
        json_object_array_add(obj, fparr);

    return CL_SUCCESS;
}
//#define cli_jsonint64(o,n,i) cli_dbgmsg("%s: %lld [%llx]\n", n, i, i)
#endif

int cli_jsonbool(json_object *obj, const char* key, int i)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: no parent object specified to cli_jsonbool\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsonbool\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    fpobj = json_object_new_boolean(i);
    if (NULL == fpobj) {
        cli_errmsg("json: no memory for json boolean object.\n");
        return CL_EMEM;
    }

    if (objty == json_type_object)
        json_object_object_add(obj, key, fpobj);
    else if (objty == json_type_array)
        json_object_array_add(obj, fpobj);

    return CL_SUCCESS;
}

int cli_jsondouble(json_object *obj, const char* key, double d)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: no parent object specified to cli_jsondouble\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsondouble\n");
            return CL_ENULLARG;
        }
    }
    else if (objty != json_type_array) {
        return CL_EARG;
    }

    fpobj = json_object_new_double(d);
    if (NULL == fpobj) {
        cli_errmsg("json: no memory for json double object.\n");
        return CL_EMEM;
    }

    if (objty == json_type_object)
        json_object_object_add(obj, key, fpobj);
    else if (objty == json_type_array)
        json_object_array_add(obj, fpobj);

    return CL_SUCCESS;
}

json_object *cli_jsonarray(json_object *obj, const char *key)
{
    json_object *newobj;

    /* First check to see if this key exists */
    if (obj && key && json_object_object_get_ex(obj, key, &newobj)) {
        return json_object_is_type(newobj, json_type_array) ? newobj : NULL;
    }

    newobj = json_object_new_array();
    if (!(newobj))
        return NULL;

    if (obj && key) {
        json_object_object_add(obj, key, newobj);
        if (!json_object_object_get_ex(obj, key, &newobj))
            return NULL;
    }

    return newobj;
}

int cli_jsonint_array(json_object *obj, int32_t val)
{
    return cli_jsonint(obj, NULL, val);
}

json_object *cli_jsonobj(json_object *obj, const char *key)
{
    json_object *newobj;

    if (obj && key && json_object_object_get_ex(obj, key, &newobj))
        return json_object_is_type(newobj, json_type_object) ? newobj : NULL;

    newobj = json_object_new_object();
    if (!(newobj))
        return NULL;

    if (obj && key) {
        json_object_object_add(obj, key, newobj);
        if (!json_object_object_get_ex(obj, key, &newobj))
            return NULL;
    }

    return newobj;
}

#if HAVE_DEPRECATED_JSON
int json_object_object_get_ex(struct json_object *obj, const char *key, struct json_object **value)
{
    struct json_object *res;

    if (value != NULL)
        *value = NULL;

    if (obj == NULL)
        return 0;

    if (json_object_get_type(obj) != json_type_object)
        return 0;

    res = json_object_object_get(obj, key);
    if (value != NULL) {
        *value = res;
        return (res != NULL);
    }

    return (res != NULL);
}
#endif

#else

int cli_json_nojson()
{
    nojson_func("nojson: json needs to be enabled for this feature\n");
    return CL_SUCCESS;
}

int cli_jsonnull_nojson(const char* key)
{
    nojson_func("nojson: %s: null\n", key);
    return CL_SUCCESS;
}

int cli_jsonstr_nojson(const char* key, const char* s)
{
    nojson_func("nojson: %s: %s\n", key, s);
    return CL_SUCCESS;
}

int cli_jsonstrlen_nojson(const char* key, const char* s, int len)
{
    char *sp = cli_malloc(len+1);
    strncpy(sp, s, len);
    sp[len] = '\0';

    nojson_func("nojson: %s: %s\n", key, sp);

    free(sp);
    return CL_SUCCESS;
}

int cli_jsonint_nojson(const char* key, int32_t i)
{
    nojson_func("nojson: %s: %d\n", key, i);
    return CL_SUCCESS;
}

int cli_jsonint64_nojson(const char* key, int64_t i)
{
    nojson_func("nojson: %s: %ld\n", key, (long int)i);
    return CL_SUCCESS;
}

int cli_jsonbool_nojson(const char* key, int i)
{
    nojson_func("nojson: %s: %s\n", key, i ? "true" : "false"); 
    return CL_SUCCESS;
}

int cli_jsondouble_nojson(const char* key, double d)
{
    nojson_func("nojson: %s: %f\n", key, d);
    return CL_SUCCESS;
}

void *cli_jsonarray_nojson(const char *key)
{
    nojson_func("nojson: %s\n", key);
    return NULL;
}

int cli_jsonint_array_nojson(int32_t val)
{
    nojson_func("nojson: %d\n", val);
    return CL_SUCCESS;
}

#endif
