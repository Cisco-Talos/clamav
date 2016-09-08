#!/bin/sh
cat <<END
!!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 
This builds the libmspack into mspack.dll on
Windows with Microsoft compiler.
!!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 
END

cat >config.h <<END
#define inline __inline
#define HAVE_STRING_H 1
#define HAVE_LIMITS_H 1
#define HAVE_MEMCMP 1
END

# Change if your VS 2015 path differs.
VS_PATH="C:\Program Files\Microsoft Visual Studio 14.0\VC"

# Do not change anything below unless you know what you're doing.
LIBMS_PATH=`pwd`
LIBMS_PATH+='/mspack'

compile_for () {
    echo "Configuring windows compiler for $1 ..."

    cd "${VS_PATH}"
    ./vcvarsall.bat $1

    cd "${LIBMS_PATH}"
    cl /O2 -I. /c *.c
    link *.obj /DLL /DEF:mspack.def /IMPLIB:mspack.lib

    cd ..

    echo 'Checking for dll and lib ...'
    ls -l mspack/mspack.dll
    ls -l mspack/mspack.lib

    echo 'Copying over dll and lib ...'
    cp mspack/mspack.dll "C:\\clamdeps\\win$2\\mspack\\lib"
    cp mspack/mspack.lib "C:\\clamdeps\\win$2\\mspack\\lib"
}

copy_lib () {
    echo 'Copying headers and source files ...'

    cd ${LIBMS_PATH}
    cp *.c "C:\\clamdeps\\win$1\\mspack\\include"
    cp *.h "C:\\clamdeps\\win$1\\mspack\\include"
}

if [[ -d 'C:\clamdeps\win32\mspack\include' && -d 'C:\clamdeps\win32\mspack\lib' && -d 'C:\clamdeps\win64\mspack\include' && -d 'C:\clamdeps\win64\mspack\lib' ]]; then

    copy_lib 32
    copy_lib 64

    if [ $(uname -m) == 'x86_64' ]; then
        compile_for amd64_x86 32
        compile_for amd64 64
    else
        compile_for x86 32
        compile_for x86_amd64 64

    fi
else
    echo 'ERROR: C:\clamdeps\winXX\mspack\include and/or C:\clamdeps\winXX\mspack\lib not found.'
fi



