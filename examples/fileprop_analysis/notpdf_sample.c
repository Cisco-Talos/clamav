VIRUSNAME_PREFIX("SUBMIT.NotPDF")
VIRUSNAMES("InActive", "Submit")

/* Target type is 0, all relevant files */
TARGET(0)

/* Declares to run bytecode only for preclassification (affecting only preclass files) */
PRECLASS_HOOK_DECLARE

/* JSON API call will require FUNC_LEVEL_098_5 = 78 */
/* PRECLASS_HOOK_DECLARE will require FUNC_LEVEL_098_7 = 80 */
FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_098_7)

#define STR_MAXLEN 256

int entrypoint ()
{
    int32_t type, obj, strlen;
    char str[STR_MAXLEN];

    /* check is json is available, alerts on inactive (optional) */
    if (!json_is_active()) {
        return -1;
    }

    /* acquire array of internal contained objects */
    obj = json_get_object("FileType", 8, 0);
    if (obj <= 0) return -1;

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
            if (!(strlen == 12) || !memcmp(str, "CL_TYPE_PDF", 12)) {
                foundVirus("Submit");
            }
        }
    }

    return 0;
}
