# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindMSPack
-------

Finds the MSPack library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``MSPack::mspack``
  The MSPack library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``MSPack_FOUND``
  True if the system has the MSPack library.
``MSPack_VERSION``
  The version of the MSPack library which was found.
``MSPack_INCLUDE_DIRS``
  Include directories needed to use MSPack.
``MSPack_LIBRARIES``
  Libraries needed to link to MSPack.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``MSPack_INCLUDE_DIR``
  The directory containing ``mspack.h``.
``MSPack_LIBRARY``
  The path to the MSPack library.

#]=======================================================================]

find_package(PkgConfig QUIET)
pkg_check_modules(PC_MSPack QUIET mspack)

find_path(MSPack_INCLUDE_DIR
  NAMES mspack.h
  PATHS ${PC_MSPack_INCLUDE_DIRS}
  PATH_SUFFIXES mspack
)
find_library(MSPack_LIBRARY
  NAMES mspack
  PATHS ${PC_MSPack_LIBRARY_DIRS}
)

set(MSPack_VERSION ${PC_MSPack_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MSPack
  FOUND_VAR MSPack_FOUND
  REQUIRED_VARS
    MSPack_LIBRARY
    MSPack_INCLUDE_DIR
  VERSION_VAR MSPack_VERSION
)

if(MSPack_FOUND)
  set(MSPack_LIBRARIES ${MSPack_LIBRARY})
  set(MSPack_INCLUDE_DIRS ${MSPack_INCLUDE_DIR})
  set(MSPack_DEFINITIONS ${PC_MSPack_CFLAGS_OTHER})
endif()

if(MSPack_FOUND AND NOT TARGET MSPack::mspack)
  add_library(MSPack::mspack UNKNOWN IMPORTED)
  set_target_properties(MSPack::mspack PROPERTIES
    IMPORTED_LOCATION "${MSPack_LIBRARY}"
    INTERFACE_COMPILE_OPTIONS "${PC_MSPack_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${MSPack_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(
  MSPack_INCLUDE_DIR
  MSPack_LIBRARY
)
