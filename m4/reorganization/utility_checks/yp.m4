AC_ARG_ENABLE([yp-check],
[AS_HELP_STRING([--enable-yp-check], [use ypmatch utility instead of /etc/passwd parsing])],
use_yp=$enableval, use_yp="no")
