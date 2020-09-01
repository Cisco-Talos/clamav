
cmake_minimum_required( VERSION 3.13 )

add_compile_definitions(_LARGEFILE_SOURCE)
add_compile_definitions(_LARGEFILE64_SOURCE)
add_compile_definitions(_FILE_OFFSET_BITS=64)

if(WIN32)
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# This is a hack!  We need a config.h
# TODO: either un-vendor mspack, or use new mspack CMake tooling when it merges into the upstream.
configure_file(config.h.in.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# mspack object
add_library( mspack_obj OBJECT )
target_sources( mspack_obj
    PRIVATE
        "mspack/cab.h"
        "mspack/cabc.c"
        "mspack/cabd.c"
        "mspack/chm.h"
        "mspack/chmc.c"
        "mspack/chmd.c"
        "mspack/crc32.c"
        "mspack/crc32.h"
        "mspack/des.h"
        "mspack/hlp.h"
        "mspack/hlpc.c"
        "mspack/hlpd.c"
        "mspack/kwaj.h"
        "mspack/kwajc.c"
        "mspack/kwajd.c"
        "mspack/lit.h"
        "mspack/litc.c"
        "mspack/litd.c"
        "mspack/lzss.h"
        "mspack/lzssd.c"
        "mspack/lzx.h"
        "mspack/lzxc.c"
        "mspack/lzxd.c"
        "mspack/mszip.h"
        "mspack/mszipc.c"
        "mspack/mszipd.c"
        "mspack/oab.h"
        "mspack/oabc.c"
        "mspack/oabd.c"
        "mspack/qtm.h"
        "mspack/qtmd.c"
        "mspack/readbits.h"
        "mspack/readhuff.h"
        "mspack/sha.h"
        "mspack/system.c"
        "mspack/system.h"
        "mspack/szdd.h"
        "mspack/szddc.c"
        "mspack/szddd.c" )
target_include_directories( mspack_obj
    PRIVATE
        "${CMAKE_BINARY_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}"
    PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}/mspack" )

# The mspack shared library.
add_library( mspack SHARED )
set_target_properties(mspack PROPERTIES
    VERSION "0.8.0"
    SOVERSION 0)
if(WIN32)
    set_target_properties(mspack PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()
target_sources( mspack
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/mspack/mspack.h" )
if(WIN32)
    install(TARGETS mspack DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS mspack DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

# Public (forwarded) dependencies.
target_link_libraries( mspack
    PUBLIC
        mspack_obj )

add_library( ClamAV::libmspack ALIAS mspack )
