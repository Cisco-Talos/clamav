# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindSYSTEMD
-------

Finds the SYSTEMD library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``SYSTEMD::systemd``
  The SYSTEMD library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``SYSTEMD_FOUND``
  True if the system has the SYSTEMD library.
``SYSTEMD_VERSION``
  The version of the SYSTEMD library which was found.
``SYSTEMD_INCLUDE_DIRS``
  Include directories needed to use SYSTEMD.
``SYSTEMD_LIBRARIES``
  Libraries needed to link to SYSTEMD.

``SYSTEMD_PROGRAM_FOUND``
  True if library and headers were found
``SYSTEMD_UNIT_DIR``
  Include directories

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``SYSTEMD_INCLUDE_DIR``
  The directory containing ``foo.h``.
``SYSTEMD_LIBRARY``
  The path to the SYSTEMD library.

#]=======================================================================]

#
# First, We'll check for libsystemd and define a target.
#
find_package(PkgConfig QUIET)
pkg_check_modules(PC_SYSTEMD QUIET libsystemd)

if (NOT PC_SYSTEMD_FOUND)
    # libsystemd not found. What about libsystemd-DAEMON?
    pkg_check_modules(PC_SYSTEMD QUIET libsystemd-daemon)
    if (PC_SYSTEMD_FOUND)
        message(STATUS "libsystemd-daemon found")
    else()
        message(STATUS "libsystemd-daemon not found")
    endif()
endif()

find_path(SYSTEMD_INCLUDE_DIR
    NAMES systemd/sd-daemon.h
    PATHS ${PC_SYSTEMD_INCLUDE_DIRS}
    PATH_SUFFIXES systemd
)
find_library(SYSTEMD_LIBRARY
    NAMES systemd
    PATHS ${PC_SYSTEMD_LIBRARY_DIRS}
)

set(SYSTEMD_VERSION ${PC_SYSTEMD_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SYSTEMD
    FOUND_VAR SYSTEMD_FOUND
    REQUIRED_VARS
        SYSTEMD_LIBRARY
        SYSTEMD_INCLUDE_DIR
    VERSION_VAR SYSTEMD_VERSION
)

if(SYSTEMD_FOUND)
    set(SYSTEMD_LIBRARIES ${SYSTEMD_LIBRARY})
    set(SYSTEMD_INCLUDE_DIRS ${SYSTEMD_INCLUDE_DIR})
    set(SYSTEMD_DEFINITIONS ${PC_SYSTEMD_CFLAGS_OTHER})

    if(NOT TARGET SYSTEMD::systemd)
        add_library(SYSTEMD::systemd UNKNOWN IMPORTED)
        set_target_properties(SYSTEMD::systemd PROPERTIES
            IMPORTED_LOCATION "${SYSTEMD_LIBRARY}"
            INTERFACE_COMPILE_OPTIONS "${PC_SYSTEMD_CFLAGS_OTHER}"
            INTERFACE_INCLUDE_DIRECTORIES "${SYSTEMD_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(
    SYSTEMD_INCLUDE_DIR
    SYSTEMD_LIBRARY
)

#
# Next, We'll check for plain ol' systemd application, needed if we want to install the service unit files
#
pkg_check_modules(SYSTEMD_PROGRAM QUIET systemd)

if (SYSTEMD_PROGRAM_FOUND)
    if ("${SYSTEMD_UNIT_DIR}" STREQUAL "")
        # Use pkg-config to look up the systemd unit install directory
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE}
            --variable=systemdsystemunitdir systemd
            OUTPUT_VARIABLE SYSTEMD_UNIT_DIR)
        string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_DIR "${SYSTEMD_UNIT_DIR}")
    endif()

    message(STATUS "systemd services install dir: ${SYSTEMD_UNIT_DIR}")
else()
    if (SYSTEMD_UNIT_DIR)
        message (FATAL_ERROR "SYSTEMD_UNIT_DIR was defined but pkg-config was not able to find systemd!")
    endif()
endif()
