# Copyright 2019 Collabora, Ltd.
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)
#
# Original Author:
# 2019 Ryan Pavlik <ryan.pavlik@collabora.com>

#.rst:
# FindCheck
# ---------------
#
# Find the "Check" C unit testing framework.
#
# See https://libcheck.github.io
#
# The Debian package for this is called ``check``
#
# Targets
# ^^^^^^^
#
# If successful, the following imported targets are created.
#
# ``libcheck::check``
#
# Cache variables
# ^^^^^^^^^^^^^^^
#
# The following cache variable may also be set to assist/control the operation of this module:
#
# ``LIBCHECK_ROOT_DIR``
#  The root to search for libcheck.
#
# ``LIBCHECK_RUNTIME_LIBRARY``
#  The Check DLL used with a shared import library on Windows.

# First let's try to find libcheck in the vcpkg cache
find_package(check CONFIG QUIET)
if(check_FOUND)
    if(TARGET Check::check)
        add_library(libcheck::check ALIAS Check::check)
    else()
        add_library(libcheck::check ALIAS Check::checkShared)
    endif()
    set(LIBCHECK_FOUND TRUE)
else()
    # We didn't find the vcpkg package. Use the traditional detection logic.
    set(LIBCHECK_ROOT_DIR "${LIBCHECK_ROOT_DIR}" CACHE PATH "Root to search for libcheck")

    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        set(_old_prefix_path "${CMAKE_PREFIX_PATH}")
        # So pkg-config uses LIBCHECK_ROOT_DIR too.
        if(LIBCHECK_ROOT_DIR)
            list(APPEND CMAKE_PREFIX_PATH ${LIBCHECK_ROOT_DIR})
        endif()
        pkg_check_modules(PC_LIBCHECK QUIET check)
        # Restore
        set(CMAKE_PREFIX_PATH "${_old_prefix_path}")
    endif()
    find_path(LIBCHECK_INCLUDE_DIR
        NAMES
        check.h
        PATHS
        ${LIBCHECK_ROOT_DIR}
        HINTS
        ${PC_LIBCHECK_INCLUDE_DIRS}
        PATH_SUFFIXES
        include
    )
    find_library(LIBCHECK_LIBRARY
        NAMES
        check_pic
        check
        PATHS
        ${LIBCHECK_ROOT_DIR}
        HINTS
        ${PC_LIBCHECK_LIBRARY_DIRS}
        PATH_SUFFIXES
        lib
    )
    set(_libcheck_is_shared FALSE)
    if(WIN32 AND LIBCHECK_LIBRARY)
        get_filename_component(_libcheck_library_name "${LIBCHECK_LIBRARY}" NAME_WE)
        string(TOLOWER "${_libcheck_library_name}" _libcheck_library_name_lower)
        if(_libcheck_library_name_lower MATCHES "(dynamic|shared)" OR LIBCHECK_RUNTIME_LIBRARY)
            set(_libcheck_is_shared TRUE)
            get_filename_component(_libcheck_library_dir "${LIBCHECK_LIBRARY}" DIRECTORY)
            find_file(LIBCHECK_RUNTIME_LIBRARY
                NAMES
                checkDynamic.dll
                check.dll
                HINTS
                "${_libcheck_library_dir}/../bin"
                "${_libcheck_library_dir}"
                PATHS
                ${LIBCHECK_ROOT_DIR}
                PATH_SUFFIXES
                bin
            )
        endif()
    endif()

    find_library(LIBCHECK_SUBUNIT_LIBRARY
        NAMES
        subunit
        PATHS
        ${LIBCHECK_ROOT_DIR}
        HINTS
        ${PC_LIBCHECK_LIBRARY_DIRS}
        PATH_SUFFIXES
        lib
    )
    find_library(LIBCHECK_LIBRT rt)
    find_library(LIBCHECK_LIBM m)

    find_package(Threads QUIET)

    set(_libcheck_extra_required)
    if(PC_LIBCHECK_FOUND AND "${PC_LIBCHECK_LIBRARIES}" MATCHES "subunit")
        list(APPEND _libcheck_extra_required LIBCHECK_SUBUNIT_LIBRARY)
    endif()
    if(_libcheck_is_shared)
        list(APPEND _libcheck_extra_required LIBCHECK_RUNTIME_LIBRARY)
    endif()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Libcheck
        REQUIRED_VARS
        LIBCHECK_INCLUDE_DIR
        LIBCHECK_LIBRARY
        THREADS_FOUND
        ${_libcheck_extra_required}
    )
    if(LIBCHECK_FOUND)
        if(NOT TARGET libcheck::check)
            if(_libcheck_is_shared)
                add_library(libcheck::check SHARED IMPORTED)
                set_target_properties(libcheck::check PROPERTIES
                    IMPORTED_IMPLIB "${LIBCHECK_LIBRARY}"
                    IMPORTED_LOCATION "${LIBCHECK_RUNTIME_LIBRARY}"
                    INTERFACE_COMPILE_DEFINITIONS "CK_DLL_EXP=_declspec(dllimport)")
            else()
                add_library(libcheck::check UNKNOWN IMPORTED)
                set_target_properties(libcheck::check PROPERTIES
                    IMPORTED_LOCATION "${LIBCHECK_LIBRARY}")
            endif()

            set_target_properties(libcheck::check PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBCHECK_INCLUDE_DIR}")
            set_property(TARGET libcheck::check PROPERTY
                IMPORTED_LINK_INTERFACE_LIBRARIES Threads::Threads)

            # if we found librt or libm, link them.
            if(LIBCHECK_LIBRT)
                set_property(TARGET libcheck::check APPEND PROPERTY
                    IMPORTED_LINK_INTERFACE_LIBRARIES "${LIBCHECK_LIBRT}")
            endif()
            if(LIBCHECK_LIBM)
                set_property(TARGET libcheck::check APPEND PROPERTY
                    IMPORTED_LINK_INTERFACE_LIBRARIES "${LIBCHECK_LIBM}")
            endif()
            if(LIBCHECK_SUBUNIT_LIBRARY)
                set_property(TARGET libcheck::check APPEND PROPERTY
                    IMPORTED_LINK_INTERFACE_LIBRARIES "${LIBCHECK_SUBUNIT_LIBRARY}")
            endif()

        endif()
        mark_as_advanced(LIBCHECK_INCLUDE_DIR LIBCHECK_LIBRARY LIBCHECK_RUNTIME_LIBRARY LIBCHECK_SUBUNIT_LIBRARY)
    endif()
    mark_as_advanced(LIBCHECK_ROOT_DIR LIBCHECK_LIBRT LIBCHECK_LIBM)
endif()
