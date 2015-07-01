VIRUSNAME_PREFIX("SUBMIT")
VIRUSNAMES("Sandbox")

/* Target type is 0, all relevant files */
TARGET(0)

/* Declares to run bytecode only for preclassification (affecting only preclass files) */
PRECLASS_HOOK_DECLARE

/* JSON API call will require FUNC_LEVEL_098_5 = 78 */
/* PRECLASS_HOOK_DECLARE will require FUNC_LEVEL_098_7 = 80 */
FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_098_7)

int entrypoint ()
{
    return 0;
}
