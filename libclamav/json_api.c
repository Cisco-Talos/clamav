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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"
#include "json_api.h"

cl_error_t cli_json_timeout_cycle_check(cli_ctx *ctx, int *toval)
{
    if (SCAN_COLLECT_METADATA) {
        if (*toval <= 0) {
            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_json_timeout_cycle_check: timeout!\n");
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

cl_error_t cli_json_parse_error(json_object *root, const char *errstr)
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

cl_error_t cli_jsonnull(json_object *obj, const char *key)
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
    } else if (objty == json_type_array) {
        json_object_array_add(obj, fpobj);
    }

    return CL_SUCCESS;
}

cl_error_t cli_jsonstr(json_object *obj, const char *key, const char *s)
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
    } else if (objty != json_type_array) {
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

cl_error_t cli_jsonstrlen(json_object *obj, const char *key, const char *s, int len)
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
    } else if (objty != json_type_array) {
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

cl_error_t cli_jsonint(json_object *obj, const char *key, int32_t i)
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
    } else if (objty != json_type_array) {
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

cl_error_t cli_jsonint64(json_object *obj, const char *key, int64_t i)
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
    } else if (objty != json_type_array) {
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

cl_error_t cli_jsonuint64(json_object *obj, const char *key, uint64_t i)
{
    json_type objty;
    json_object *fpobj;
    if (NULL == obj) {
        cli_dbgmsg("json: no parent object specified to cli_jsonuint64\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(obj);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_jsonuint64\n");
            return CL_ENULLARG;
        }
    } else if (objty != json_type_array) {
        return CL_EARG;
    }
#if JSON_C_MINOR_VERSION >= 14
    fpobj = json_object_new_uint64(i);
#else
    if (i > INT64_MAX) {
        cli_dbgmsg("json: uint64 value too large for json int64 object\n");
        return CL_EARG;
    }
    fpobj = json_object_new_int64(i);
#endif
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

cl_error_t cli_jsonbool(json_object *obj, const char *key, int i)
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
    } else if (objty != json_type_array) {
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

cl_error_t cli_jsondouble(json_object *obj, const char *key, double d)
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
    } else if (objty != json_type_array) {
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
    json_type objty;
    json_object *newobj;

    /* First check to see if this key exists */
    if (obj && key && json_object_object_get_ex(obj, key, &newobj)) {
        return json_object_is_type(newobj, json_type_array) ? newobj : NULL;
    }

    newobj = json_object_new_array();
    if (!(newobj))
        return NULL;

    if (obj) {
        objty = json_object_get_type(obj);

        if (key && objty == json_type_object) {
            json_object_object_add(obj, key, newobj);
            if (!json_object_object_get_ex(obj, key, &newobj))
                return NULL;
        } else if (objty == json_type_array) {
            json_object_array_add(obj, newobj);
        }
    }

    return newobj;
}

cl_error_t cli_jsonint_array(json_object *obj, int32_t val)
{
    return cli_jsonint(obj, NULL, val);
}

json_object *cli_jsonobj(json_object *obj, const char *key)
{
    json_type objty;
    json_object *newobj;

    if (obj && key && json_object_object_get_ex(obj, key, &newobj))
        return json_object_is_type(newobj, json_type_object) ? newobj : NULL;

    newobj = json_object_new_object();
    if (!(newobj))
        return NULL;

    if (obj) {
        objty = json_object_get_type(obj);

        if (key && objty == json_type_object) {
            json_object_object_add(obj, key, newobj);
            if (!json_object_object_get_ex(obj, key, &newobj))
                return NULL;
        } else if (objty == json_type_array) {
            json_object_array_add(obj, newobj);
        }
    }

    return newobj;
}

/* deleting an object DOES decrement reference count */
cl_error_t cli_json_delowner(json_object *owner, const char *key, int idx)
{
    json_type objty;
    json_object *obj;
    if (NULL == owner) {
        cli_dbgmsg("json: no owner object specified to cli_json_delowner\n");
        return CL_ENULLARG;
    }
    objty = json_object_get_type(owner);

    if (objty == json_type_object) {
        if (NULL == key) {
            cli_dbgmsg("json: null string specified as key to cli_delowner\n");
            return CL_ENULLARG;
        }

        if (!json_object_object_get_ex(owner, key, &obj)) {
            cli_dbgmsg("json: owner array does not have content with key %s\n", key);
            return CL_EARG;
        }

        json_object_object_del(owner, key);
    } else if (objty == json_type_array) {
        json_object *empty;

        if (NULL == json_object_array_get_idx(owner, idx)) {
            cli_dbgmsg("json: owner array does not have content at idx %d\n", idx);
            return CL_EARG;
        }

        /* allocate the empty object to replace target object */
        empty = cli_jsonobj(NULL, NULL);
        if (NULL == empty)
            return CL_EMEM;

        if (0 != json_object_array_put_idx(owner, idx, empty)) {
            /* this shouldn't be possible */
            cli_dbgmsg("json: cannot delete idx %d of owner array\n", idx);
            return CL_BREAK;
        }
    } else {
        cli_dbgmsg("json: no owner object cannot hold ownership\n");
        return CL_EARG;
    }

    return CL_SUCCESS;
}
