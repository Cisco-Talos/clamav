VIRUSNAME_PREFIX("SUBMIT.filetype")
VIRUSNAMES("CL_TYPE_MSWORD", "CL_TYPE_MSPPT", "CL_TYPE_MSXL",
           "CL_TYPE_OOXML_WORD", "CL_TYPE_OOXML_PPT", "CL_TYPE_OOXML_XL",
           "CL_TYPE_MSEXE", "CL_TYPE_PDF", "CL_TYPE_MSOLE2", "CL_TYPE_UNKNOWN", "InActive")

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
    int32_t objid, type, strlen;
    char str[STR_MAXLEN];

    /* check is json is available, alerts on inactive (optional) */
    if (!json_is_active())
        foundVirus("InActive");

    /* acquire the filetype object */
    objid = json_get_object("FileType", 8, 0);
    if (objid <= 0) {
        debug_print_str("json object has no filetype!", 28);
        return 1;
    }
    type = json_get_type(objid);
    if (type != JSON_TYPE_STRING) {
        debug_print_str("json object filetype property is not string!", 44);
        return 1;
    }

    /* acquire string length, note +1 is for the NULL terminator */
    strlen = json_get_string_length(objid)+1;
    /* prevent buffer overflow */
    if (strlen > STR_MAXLEN)
        strlen = STR_MAXLEN;
    
    /* acquire string data, note strlen includes NULL terminator */
    if (json_get_string(str, strlen, objid)) {
        /* debug print str (with '\n' and prepended message */
        debug_print_str(str,strlen);

        /* check the contained object's filetype */
        if (strlen == 14 && !memcmp(str, "CL_TYPE_MSEXE", 14)) {
            foundVirus("CL_TYPE_MSEXE");
            return 0;
        }
        if (strlen == 12 && !memcmp(str, "CL_TYPE_PDF", 12)) {
            foundVirus("CL_TYPE_PDF");
            return 0;
        }
        if (strlen == 19 && !memcmp(str, "CL_TYPE_OOXML_WORD", 19)) {
            foundVirus("CL_TYPE_OOXML_WORD");
            return 0;
        }
        if (strlen == 18 && !memcmp(str, "CL_TYPE_OOXML_PPT", 18)) {
            foundVirus("CL_TYPE_OOXML_PPT");
            return 0;
        }
        if (strlen == 17 && !memcmp(str, "CL_TYPE_OOXML_XL", 17)) {
            foundVirus("CL_TYPE_OOXML_XL");
            return 0;
        }
        if (strlen == 15 && !memcmp(str, "CL_TYPE_MSWORD", 15)) {
            foundVirus("CL_TYPE_MSWORD");
            return 0;
        }
        if (strlen == 14 && !memcmp(str, "CL_TYPE_MSPPT", 14)) {
            foundVirus("CL_TYPE_MSPPT");
            return 0;
        }
        if (strlen == 13 && !memcmp(str, "CL_TYPE_MSXL", 13)) {
            foundVirus("CL_TYPE_MSXL");
            return 0;
        }
        if (strlen == 15 && !memcmp(str, "CL_TYPE_MSOLE2", 15)) {
            foundVirus("CL_TYPE_MSOLE2");
            return 0;
        }

        foundVirus("CL_TYPE_UNKNOWN");
        return 0;
    }

    return 0;
}
