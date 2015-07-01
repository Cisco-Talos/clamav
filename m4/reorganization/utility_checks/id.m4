AC_ARG_ENABLE([id-check],
[AS_HELP_STRING([--enable-id-check], [use id utility instead of /etc/passwd parsing])],
use_id=$enableval, use_id="no")
