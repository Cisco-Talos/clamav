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
if [ $(uname -m) == 'x86_64' ]; then
	VS_PATH='C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC'
else
	VS_PATH='C:\Program Files\Microsoft Visual Studio 14.0\VC'
fi


# Do not change anything below unless you know what you're doing.
LIBMS_PATH=`pwd`
LIBMS_PATH+='/mspack'

compile_for () {
    echo "Compiling for $1 ..."
    cd "${LIBMS_PATH}"
    ../wincompile.bat "$VS_PATH" $1

    cd ..

    echo 'Checking for dll and lib ...'
    ls -l mspack/mspack.dll
    ls -l mspack/mspack.lib

    echo 'Copying over dll and lib ...'
    cp mspack/mspack.dll "C:\\clamdeps\\win$2\\mspack\\lib"
    cp mspack/mspack.lib "C:\\clamdeps\\win$2\\mspack\\lib"
}

copy_headers () {
    echo 'Copying headers and source files ...'

    cd ${LIBMS_PATH}
    cp *.h "C:\\clamdeps\\win$1\\mspack\\include"
}

if ! [ -d 'C:\clamdeps\win32\mspack\include' ]; then
	mkdir -p 'C:\clamdeps\win32\mspack\include'
fi

if ! [ -d 'C:\clamdeps\win32\mspack\lib' ]; then
	mkdir -p 'C:\clamdeps\win32\mspack\lib'
fi

if ! [ -d 'C:\clamdeps\win64\mspack\include' ]; then
	mkdir -p 'C:\clamdeps\win64\mspack\include'
fi

if ! [ -d 'C:\clamdeps\win64\mspack\lib' ]; then
	mkdir -p 'C:\clamdeps\win64\mspack\lib'
fi

copy_headers 32
copy_headers 64

if [ $(uname -m) == 'x86_64' ]; then
    compile_for 'amd64_x86' 32
    compile_for 'amd64' 64
else
    compile_for 'x86' 32
    compile_for 'x86_amd64' 64

fi
