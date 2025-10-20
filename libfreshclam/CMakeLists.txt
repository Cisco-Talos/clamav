# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# not using an object library for the sake of Xcode compatibility
# See: https://cmake.org/pipermail/cmake/2016-May/063479.html
set(LIBFRESHCLAM_SOURCES
    libfreshclam.c
    libfreshclam_internal.c
    libfreshclam_internal.h
    dns.c
    dns.h
)

if(ENABLE_SHARED_LIB)
    # The libfreshclam shared library.
    add_library( freshclam SHARED )
    target_sources( freshclam
        PRIVATE
            ${LIBFRESHCLAM_SOURCES}
        PUBLIC
            libfreshclam.h )
    if(WIN32)
        target_sources( freshclam PRIVATE libfreshclam_main.c)
    endif()
    target_include_directories( freshclam
        PRIVATE
            ${CMAKE_BINARY_DIR} # For clamav-config.h
        PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )

    target_link_libraries( freshclam
        PUBLIC
            ClamAV::common
            CURL::libcurl
            OpenSSL::SSL
            OpenSSL::Crypto )
    if(APPLE)
        target_link_libraries( freshclam
            PUBLIC
                resolv
                ${APPLE_CORE_FOUNDATION}
                ${APPLE_SECURITY} )
    elseif(HAIKU)
        target_link_libraries( freshclam
            PUBLIC
                network )
    elseif(UNIX AND NOT AIX)
        if(HAVE_RESOLV_H AND NOT C_BSD) # BSD appears to have libresolv inside libc
            target_link_libraries( freshclam
                PUBLIC
                    resolv )
        endif()
    endif()

    if(WIN32)
        set_target_properties(freshclam PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    elseif(UNIX AND NOT APPLE AND NOT AIX)
        target_link_options(freshclam PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libfreshclam.map")
        if (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
            # Solaris 11.4 linker supports a subset of GNU ld version scripts, but requires a special option to enable
            target_link_options(freshclam PRIVATE "-Wl,-z,gnu-version-script-compat")
        endif()
    endif()
    set_target_properties(freshclam PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}"
        VERSION ${LIBFRESHCLAM_VERSION} SOVERSION ${LIBFRESHCLAM_SOVERSION}
        LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libfreshclam.map)
    install(TARGETS freshclam COMPONENT libraries)
    if(WIN32)
        install(FILES $<TARGET_PDB_FILE:freshclam> TYPE BIN OPTIONAL COMPONENT libraries)
        if(ENABLE_WINDOWS_INSTALL_THIRDPARTY_DEPENDENCIES)
            # Also install shared library (DLL) dependencies
            install(CODE [[
                file(GET_RUNTIME_DEPENDENCIES
                    LIBRARIES
                        $<TARGET_FILE:ClamAV::libfreshclam>
                    RESOLVED_DEPENDENCIES_VAR _r_deps
                    UNRESOLVED_DEPENDENCIES_VAR _u_deps
                    DIRECTORIES
                        $<TARGET_FILE_DIR:CURL::libcurl>
                        $<TARGET_FILE_DIR:OpenSSL::SSL>
                        $<TARGET_FILE_DIR:OpenSSL::Crypto>
                    POST_EXCLUDE_REGEXES
                        "[cC]:[\\/][wW][iI][nN][dD][oO][wW][sS]"
                )
                foreach(_file ${_r_deps})
                    string(TOLOWER ${_file} _file_lower)
                    if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                        file(INSTALL
                            DESTINATION "${CMAKE_INSTALL_PREFIX}"
                            TYPE SHARED_LIBRARY
                            FOLLOW_SYMLINK_CHAIN
                            FILES "${_file}"
                        )
                    endif()
                endforeach()
                #message("UNRESOLVED_DEPENDENCIES_VAR: ${_u_deps}")
                ]]
                COMPONENT libraries)
        endif()
    endif()

    add_library( ClamAV::libfreshclam ALIAS freshclam )
endif()

if(ENABLE_STATIC_LIB)
    # The freshclam static library.
    add_library(freshclam_static STATIC)
    target_sources(freshclam_static
        PRIVATE
            ${LIBFRESHCLAM_SOURCES}
        PUBLIC
            libfreshclam.h )
    if(WIN32)
        target_sources( freshclam_static PRIVATE libfreshclam_main.c)
    endif()
    target_include_directories( freshclam_static
        PRIVATE
            ${CMAKE_BINARY_DIR} # For clamav-config.h
        PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )

    target_link_libraries( freshclam_static
        PUBLIC
            ClamAV::common
            CURL::libcurl
            OpenSSL::SSL
            OpenSSL::Crypto )
    if(APPLE)
        target_link_libraries( freshclam_static
            PUBLIC
                resolv
                ${APPLE_CORE_FOUNDATION}
                ${APPLE_SECURITY} )
    elseif(HAIKU)
        target_link_libraries( freshclam_static
            PUBLIC
                network )
    elseif(UNIX)
        if(HAVE_RESOLV_H AND NOT C_BSD) # BSD appears to have libresolv inside libc
            target_link_libraries( freshclam_static
                PUBLIC
                    resolv )
        endif()
    endif()

    set_target_properties(freshclam_static PROPERTIES
        ARCHIVE_OUTPUT_NAME freshclam_static
        COMPILE_FLAGS       "${WARNCFLAGS}"
        VERSION ${LIBFRESHCLAM_VERSION} SOVERSION ${LIBFRESHCLAM_SOVERSION})
    target_compile_definitions(freshclam_static PUBLIC freshclam_staticLIB)
    install(TARGETS freshclam_static COMPONENT libraries)

    add_library( ClamAV::libfreshclam_static ALIAS freshclam_static )
    if(NOT ENABLE_SHARED_LIB)
        add_library( ClamAV::libfreshclam ALIAS freshclam_static )
    endif()
endif()

install(
    FILES
        libfreshclam.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT libraries)
