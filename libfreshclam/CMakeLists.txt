# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The libfreshclam object library
add_library( libfreshclam_obj OBJECT )
target_sources( libfreshclam_obj
    PRIVATE
        libfreshclam.c
        libfreshclam_internal.c
        libfreshclam_internal.h
        dns.c
        dns.h
    PUBLIC
        libfreshclam.h )
target_include_directories( libfreshclam_obj
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
set_target_properties( libfreshclam_obj PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( libfreshclam_obj
    PUBLIC
        ClamAV::shared
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto )
if(APPLE)
    target_link_libraries( libfreshclam_obj
        PUBLIC
            resolv
            ${APPLE_CORE_FOUNDATION}
            ${APPLE_SECURITY} )
elseif(UNIX)
    if(HAVE_RESOLV_H)
        target_link_libraries( libfreshclam_obj
            PUBLIC
                resolv )
    endif()
endif()


if(WIN32)
    target_sources( libfreshclam_obj PRIVATE libfreshclam_main.c)
endif()

if(ENABLE_SHARED_LIB)
    # The libfreshclam shared library.
    add_library( freshclam SHARED )
    target_sources( freshclam
        PUBLIC
            libfreshclam.h )
    target_link_libraries( freshclam
        PUBLIC
            libfreshclam_obj )
    if(WIN32)
        set_target_properties(freshclam PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
    set_target_properties(freshclam PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}"
        VERSION ${LIBFRESHCLAM_VERSION} SOVERSION ${LIBFRESHCLAM_SOVERSION})
    if(WIN32)
        install(TARGETS freshclam DESTINATION ${CMAKE_INSTALL_PREFIX})
    else()
        install(TARGETS freshclam DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()

    add_library( ClamAV::libfreshclam ALIAS freshclam )
endif()

if(ENABLE_STATIC_LIB)
    # The freshclam static library.
    add_library(freshclam_static STATIC)
    target_sources(freshclam_static
        PUBLIC
            libfreshclam.h )
    target_link_libraries(freshclam_static
        PUBLIC
            libfreshclam_obj )
    set_target_properties(freshclam_static PROPERTIES
        ARCHIVE_OUTPUT_NAME freshclam_static
        COMPILE_FLAGS       "${WARNCFLAGS}"
        VERSION ${LIBFRESHCLAM_VERSION} SOVERSION ${LIBFRESHCLAM_SOVERSION})
    target_compile_definitions(freshclam_static PUBLIC freshclam_staticLIB)
    if(WIN32)
        install(TARGETS freshclam_static DESTINATION ${CMAKE_INSTALL_PREFIX})
    else()
        install(TARGETS freshclam_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()

    add_library( ClamAV::libfreshclam_static ALIAS freshclam_static )
endif()

install(
    FILES
        libfreshclam.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
