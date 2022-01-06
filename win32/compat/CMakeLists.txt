# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)
endif()

# The win32_compat object library
add_library( win32_compat_obj OBJECT )
target_sources( win32_compat_obj
    PRIVATE
        dirent.c
        gettimeofday.c
        glob.c
        libgen.c
        net.c
        random.c
        resolv.c
        strptime.c
        utf8_util.c
        w32_errno.c
        w32_errno_defs.c
        w32_stat.c
    PUBLIC
        dirent.h
        gettimeofday.h
        libgen.h
        net.h
        random.h
        resolv.h
        utf8_util.h
        w32_errno.h
        w32_stat.h )
target_include_directories( win32_compat_obj
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
set_target_properties(win32_compat_obj PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")

target_link_libraries( win32_compat_obj
    PUBLIC
        dnsapi
        PThreadW32::pthreadw32 )

# The win32_compat static library.
add_library( win32_compat STATIC )
target_link_libraries( win32_compat
    PUBLIC
        win32_compat_obj )
set_target_properties( win32_compat PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

add_library( ClamAV::win32_compat ALIAS win32_compat )
