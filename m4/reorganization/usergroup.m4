AC_ARG_ENABLE([yp-check],
[AS_HELP_STRING([--enable-yp-check], [use ypmatch utility instead of /etc/passwd parsing])],
use_yp=$enableval, use_yp="no")

AC_ARG_WITH([user], 
[AS_HELP_STRING([--with-user@<:@=uid@:>@], [name of the clamav user @<:@default=clamav@:>@])],
clamav_user="$withval", clamav_user="clamav")

AC_ARG_WITH([group], 
[AS_HELP_STRING([--with-group@<:@=gid@:>@], [name of the clamav group @<:@default=clamav@:>@])],
clamav_group="$withval", clamav_group="clamav")

AC_DEFINE_UNQUOTED([CLAMAVUSER],"$clamav_user",[name of the clamav user])
AC_DEFINE_UNQUOTED([CLAMAVGROUP],"$clamav_group",[name of the clamav group])
