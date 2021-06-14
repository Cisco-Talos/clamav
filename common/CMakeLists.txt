# Copyright (C) 2020-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The "common" object library
add_library( common_obj OBJECT )
target_sources( common_obj
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

target_include_directories( common_obj
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
if(FOUND_SYSTEMD)
    target_include_directories( common_obj
        PRIVATE ${SYSTEMD_INCLUDE_DIRS} )
endif()
set_target_properties( common_obj PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if(APPLE)
    target_sources( common_obj PRIVATE mac/cert_util_mac.m )
elseif(WIN32)
    target_sources( common_obj PRIVATE service.c PUBLIC service.h )
    target_sources( common_obj PRIVATE win/cert_util_win.c )
else()
    target_sources( common_obj PRIVATE linux/cert_util_linux.c )
endif()

target_link_libraries( common_obj
    PUBLIC
        ClamAV::libclamav
        ZLIB::ZLIB
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto )
if(WIN32)
    target_link_libraries( common_obj
        PUBLIC
            crypt32 )
endif()

if(HAVE_SYSTEMD)
    target_link_libraries( common_obj
        PRIVATE
            SYSTEMD::systemd )
endif()

# The "common" static library.
add_library( common STATIC )

target_link_libraries( common
    PUBLIC
        common_obj )
set_target_properties( common PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
if(WIN32)
    set_target_properties(common PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

add_library( ClamAV::common ALIAS common )
