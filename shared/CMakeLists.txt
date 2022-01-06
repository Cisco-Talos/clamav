# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The shared object library
add_library( shared_obj OBJECT )
target_sources( shared_obj
    PRIVATE
        cert_util.c
        cdiff.c
        actions.c
        clamdcom.c
        getopt.c
        hostid.c
        idmef_logging.c
        misc.c
        optparser.c
        output.c
        tar.c
    PUBLIC
        cert_util.h
        cdiff.h
        actions.h
        clamdcom.h
        fdpassing.h
        getopt.h
        hostid.h
        idmef_logging.h
        misc.h
        optparser.h
        output.h
        tar.h )
target_include_directories( shared_obj
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
if(FOUND_SYSTEMD)
    target_include_directories( shared_obj
        PRIVATE ${SYSTEMD_INCLUDE_DIRS} )
endif()
set_target_properties( shared_obj PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if(APPLE)
    target_sources( shared_obj PRIVATE mac/cert_util_mac.m )
elseif(WIN32)
    target_sources( shared_obj PRIVATE win/cert_util_win.c )
else()
    target_sources( shared_obj PRIVATE linux/cert_util_linux.c )
endif()

target_link_libraries( shared_obj
    PUBLIC
        ClamAV::libclamav
        ZLIB::ZLIB
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto )
if(WIN32)
    target_link_libraries( shared_obj
        PUBLIC
            crypt32 )
endif()

if(HAVE_SYSTEMD)
    target_link_libraries( shared_obj
        PRIVATE
            SYSTEMD::systemd )
endif()

# The shared static library.
add_library( shared STATIC )

target_link_libraries( shared
    PUBLIC
        shared_obj )
set_target_properties( shared PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
if(WIN32)
    set_target_properties(shared PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

add_library( ClamAV::shared ALIAS shared )
