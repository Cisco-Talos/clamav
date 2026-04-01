# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindZSTD
-------

Finds the Zstandard (zstd) library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``ZSTD::zstd``
  The Zstandard library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``ZSTD_FOUND``
  True if the system has the zstd library.
``ZSTD_VERSION``
  The version of the zstd library which was found.
``ZSTD_INCLUDE_DIRS``
  Include directories needed to use zstd.
``ZSTD_LIBRARIES``
  Libraries needed to link to zstd.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``ZSTD_INCLUDE_DIR``
  The directory containing ``zstd.h``.
``ZSTD_LIBRARY``
  The path to the zstd library.

#]=======================================================================]

find_package(PkgConfig QUIET)
pkg_check_modules(PC_ZSTD QUIET libzstd)

find_path(ZSTD_INCLUDE_DIR
  NAMES zstd.h
  PATHS ${PC_ZSTD_INCLUDE_DIRS}
  PATH_SUFFIXES zstd include/zstd
)

if(ZSTD_LIBRARY)
  set(ZSTD_LIBRARIES "${ZSTD_LIBRARY}")
endif()

if(NOT ZSTD_LIBRARIES)
  find_library(ZSTD_LIBRARY_RELEASE
    NAMES zstd NAMES_PER_DIR HINTS ${PC_ZSTD_LIBRARY_DIRS} PATH_SUFFIXES lib)
  find_library(ZSTD_LIBRARY_DEBUG
    NAMES zstdd NAMES_PER_DIR HINTS ${PC_ZSTD_LIBRARY_DIRS} PATH_SUFFIXES lib)

  include(SelectLibraryConfigurations)
  SELECT_LIBRARY_CONFIGURATIONS(ZSTD)
else()
  file(TO_CMAKE_PATH "${ZSTD_LIBRARIES}" ZSTD_LIBRARIES)
endif()

set(ZSTD_VERSION ${PC_ZSTD_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZSTD
  FOUND_VAR ZSTD_FOUND
  REQUIRED_VARS
    ZSTD_LIBRARIES
    ZSTD_INCLUDE_DIR
  VERSION_VAR ZSTD_VERSION
)

if(ZSTD_FOUND)
  set(ZSTD_INCLUDE_DIRS ${ZSTD_INCLUDE_DIR})
  set(ZSTD_DEFINITIONS ${PC_ZSTD_CFLAGS_OTHER})

  if(NOT TARGET ZSTD::zstd)
    add_library(ZSTD::zstd UNKNOWN IMPORTED)
    set_target_properties(ZSTD::zstd PROPERTIES
      INTERFACE_COMPILE_OPTIONS "${PC_ZSTD_CFLAGS_OTHER}"
      INTERFACE_INCLUDE_DIRECTORIES "${ZSTD_INCLUDE_DIRS}")

    if(ZSTD_LIBRARY_RELEASE)
      set_property(TARGET ZSTD::zstd APPEND PROPERTY
        IMPORTED_CONFIGURATIONS RELEASE)
      set_target_properties(ZSTD::zstd PROPERTIES
        IMPORTED_LOCATION_RELEASE "${ZSTD_LIBRARY_RELEASE}"
      )
    endif()

    if(ZSTD_LIBRARY_DEBUG)
      set_property(TARGET ZSTD::zstd APPEND PROPERTY
        IMPORTED_CONFIGURATIONS DEBUG)
      set_target_properties(ZSTD::zstd PROPERTIES
        IMPORTED_LOCATION_DEBUG "${ZSTD_LIBRARY_DEBUG}"
      )
    endif()

    if(NOT ZSTD_LIBRARY_RELEASE AND NOT ZSTD_LIBRARY_DEBUG)
      set_property(TARGET ZSTD::zstd APPEND PROPERTY
        IMPORTED_LOCATION "${ZSTD_LIBRARY}")
    endif()
  endif()
endif()

mark_as_advanced(
  ZSTD_INCLUDE_DIR
  ZSTD_LIBRARY
)
