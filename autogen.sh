#!/bin/sh
#
# Generate configure and Makefile.in files
#

# Find the script directory, and cd to it.  When the shell exits, we will be back where we were.
BASEDIR="$( cd "$(dirname "$0")" ; pwd -P )"
echo "Generating autotools files in: $BASEDIR ..."
cd $BASEDIR

# If this is a source checkout then call autoreconf with error as well
if test -d .git; then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi

autoreconf -i -f
rc=$?; if [ $rc != 0 ]; then
  echo "Error: Failed to generate autojunk!"; exit $rc
else
  echo "You can now run ./configure"
fi
