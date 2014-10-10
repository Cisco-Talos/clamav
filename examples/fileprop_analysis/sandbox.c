VIRUSNAME_PREFIX("SUBMIT")
VIRUSNAMES("Sandbox")

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

int entrypoint ()
{
    return 0;
}
