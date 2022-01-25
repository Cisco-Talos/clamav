# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindTomsFastMath
-------

Finds the TomsFastMath library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``TomsFastMath::TomsFastMath``
  The TomsFastMath library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``TomsFastMath_FOUND``
  True if the system has the TomsFastMath library.
``TomsFastMath_VERSION``
  The version of the TomsFastMath library which was found.
``TomsFastMath_INCLUDE_DIRS``
  Include directories needed to use TomsFastMath.
``TomsFastMath_LIBRARIES``
  Libraries needed to link to TomsFastMath.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``TomsFastMath_INCLUDE_DIR``
  The directory containing ``tfm.h``.
``TomsFastMath_LIBRARY``
  The path to the TomsFastMath library.

#]=======================================================================]

find_package(PkgConfig QUIET)
pkg_check_modules(PC_TomsFastMath QUIET toms)

find_path(TomsFastMath_INCLUDE_DIR
  NAMES tfm.h
  PATHS ${PC_TomsFastMath_INCLUDE_DIRS}
)
find_library(TomsFastMath_LIBRARY
  NAMES tfm
  PATHS ${PC_TomsFastMath_LIBRARY_DIRS}
)

set(TomsFastMath_VERSION ${PC_TomsFastMath_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TomsFastMath
  FOUND_VAR TomsFastMath_FOUND
  REQUIRED_VARS
    TomsFastMath_LIBRARY
    TomsFastMath_INCLUDE_DIR
  VERSION_VAR TomsFastMath_VERSION
)

if(TomsFastMath_FOUND)
  set(TomsFastMath_LIBRARIES ${TomsFastMath_LIBRARY})
  set(TomsFastMath_INCLUDE_DIRS ${TomsFastMath_INCLUDE_DIR})
  set(TomsFastMath_DEFINITIONS ${PC_TomsFastMath_CFLAGS_OTHER})
endif()

if(TomsFastMath_FOUND AND NOT TARGET TomsFastMath::TomsFastMath)
  add_library(TomsFastMath::TomsFastMath UNKNOWN IMPORTED)
  set_target_properties(TomsFastMath::TomsFastMath PROPERTIES
    IMPORTED_LOCATION "${TomsFastMath_LIBRARY}"
    INTERFACE_COMPILE_OPTIONS "${PC_TomsFastMath_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${TomsFastMath_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(
  TomsFastMath_INCLUDE_DIR
  TomsFastMath_LIBRARY
)
