VIRUSNAME_PREFIX("SUBMIT.contains")
VIRUSNAMES("EmbedPE")

/* Target type is 13, internal JSON properties */
TARGET(13)

/* JSON API call will require FUNC_LEVEL_098_5 = 78 */
FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_098_5)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(sig1)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
/* search @offset 0 : '{ "Magic": "CLAMJSON' */
/* this can be readjusted for specific filetypes */
DEFINE_SIGNATURE(sig1, "0:7b20224d61676963223a2022434c414d4a534f4e")
SIGNATURES_END

bool logical_trigger(void)
{
    return matches(Signatures.sig1);
}

#define STR_MAXLEN 256

int entrypoint ()
{
    int i;
    int32_t type, obj, objarr, objit, arrlen, strlen;
    char str[STR_MAXLEN];

    /* check is json is available, alerts on inactive (optional) */
    if (!json_is_active()) {
        return -1;
    }

    /* acquire array of internal contained objects */
    objarr = json_get_object("ContainedObjects", 16, 0);
    type = json_get_type(objarr);
    /* debug print uint (no '\n' or prepended message */
    debug_print_uint(type);

    if (type != JSON_TYPE_ARRAY) {
        return -1;
    }

    /* check array length for iteration over elements */
    arrlen = json_get_array_length(objarr);
    for (i = 0; i < arrlen; ++i) {
        /* acquire json object @ idx i */
        objit = json_get_array_idx(i, objarr);
        if (objit <= 0) continue;

        /* acquire FileType object of the array element @ idx i */
        obj = json_get_object("FileType", 8, objit);
        if (obj <= 0) continue;

        /* acquire and check type */
        type = json_get_type(obj);
        if (type == JSON_TYPE_STRING) {
            /* acquire string length, note +1 is for the NULL terminator */
            strlen = json_get_string_length(obj)+1;
            /* prevent buffer overflow */
            if (strlen > STR_MAXLEN)
                strlen = STR_MAXLEN;
            /* acquire string data, note strlen includes NULL terminator */
            if (json_get_string(str, strlen, obj)) {
                /* debug print str (with '\n' and prepended message */
                debug_print_str(str,strlen);

                /* check the contained object's type */
                if (strlen == 14 && !memcmp(str, "CL_TYPE_MSEXE", 14)) {
                //if (!strcmp(str, strlen, "CL_TYPE_MSEXE", strlen)) {
                    /* alert for submission */
                    foundVirus("EmbedPE");
                    return 0;
                }
            }
        }
    }

    return 0;
}
