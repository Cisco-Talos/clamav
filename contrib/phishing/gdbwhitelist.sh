#!/bin/sh
if test $# -ne 1; then
    echo "Usage: $0 /path/to/sample\n";
    exit 1;
fi

clamscan  --debug $1 >/dev/null 2>debugout
grep "This hash matched" debugout | sed -e 's/.*matched: \(.*\)/S:W:\1/'
