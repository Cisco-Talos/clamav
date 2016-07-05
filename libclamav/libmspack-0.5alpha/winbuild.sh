#!/bin/sh
cat <<END
!!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 
This builds the libmspack into mspack.dll on
Windows with Microsoft compiler.
After compilation find the library in the 
directory mspack 
!!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 
END

cat >config.h <<END
#define inline __inline
#define HAVE_STRING_H 1
#define HAVE_LIMITS_H 1
#define HAVE_MEMCMP 1
END

cd mspack

cl /O2 -I. /c *.c
link *.obj /DLL /DEF:mspack.def /IMPLIB:mspack.lib

cd ..

ls -l mspack/mspack.dll
ls -l mspack/mspack.lib
