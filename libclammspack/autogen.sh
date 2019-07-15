#!/bin/sh
# Runs the autoreconf tool, creating the configure script

[ -d m4 ] || mkdir m4
autoreconf -i -W all
echo you can now run ./configure
