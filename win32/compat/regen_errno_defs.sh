#!/bin/bash

IFS='
'
GIT_DIR=$(git rev-parse --git-dir)
if [ -z "$GIT_DIR" ]; then
	echo "run me from a git path"
	exit 1
fi

BASEDIR="$GIT_DIR/.."
pushd "$BASEDIR" > /dev/null

GIT_DIR=$(git rev-parse --git-dir)
BASEDIR="$GIT_DIR/.."

DATE=`date`
OUTFILE="$BASEDIR/win32/compat/w32_errno_defs.c"
INFILE="$BASEDIR/win32/compat/referrno.txt"

if [ ! -f "$INFILE" ]; then
	echo "reference file missing"
	exit 1
fi


cat > "$OUTFILE" <<EOH
/* Automatically generated on $DATE */

#include <errno.h>

static const struct errno_struct {
	int err;
	const char *strerr;
} w32_errnos[] = {
EOH

maxerr=0

for pippo in `cat "$INFILE"`; do
	symbol=`echo $pippo | cut -d'|' -f1`
	value=`echo $pippo | cut -d'|' -f2`
	value=$((value+1000))
	[ $value -gt $maxerr ] && maxerr=$value
	descr=`echo $pippo | cut -d'|' -f3`
	git grep $symbol | egrep -v '(referrno|w32_errno_defs)' > /dev/null
	used=$?
	[ $used -ne 0 ] && echo "#ifdef __ERRNO_INCLUDE_UNUSED" >> "$OUTFILE"
	echo -e "#ifndef $symbol\n#define $symbol $value\n#endif\n{ $symbol, \"$descr\" }," >> "$OUTFILE"
	[ $used -ne 0 ] && echo "#endif /* __ERRNO_INCLUDE_UNUSED */" >> "$OUTFILE"
done
maxerr=$((maxerr+1))
echo -e "#ifndef EBOGUSWSOCK\n#define EBOGUSWSOCK $maxerr\n#endif\n{ EBOGUSWSOCK, \"WinSock error\"}\n};" >> "$OUTFILE"

popd >/dev/null


