# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindPCRE2
-------

Finds the PCRE2 library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``PCRE2::pcre2``
  The PCRE2 library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``PCRE2_FOUND``
  True if the system has the PCRE2 library.
``PCRE2_VERSION``
  The version of the PCRE2 library which was found.
``PCRE2_INCLUDE_DIRS``
  Include directories needed to use PCRE2.
``PCRE2_LIBRARIES``
  Libraries needed to link to PCRE2.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``PCRE2_INCLUDE_DIR``
  The directory containing ``foo.h``.
``PCRE2_LIBRARY``
  The path to the PCRE2 library.

#]=======================================================================]

find_package(PkgConfig QUIET)
pkg_check_modules(PC_PCRE2 QUIET pcre2)

find_path(PCRE2_INCLUDE_DIR
  NAMES pcre2.h
  PATHS ${PC_PCRE2_INCLUDE_DIRS}
  PATH_SUFFIXES pcre2 include/pcre2
)

if(PCRE2_LIBRARY)
  set(PCRE2_LIBRARIES "${PCRE2_LIBRARY}")
endif()

if(NOT PCRE2_LIBRARIES)
  find_library(PCRE2_LIBRARY_RELEASE
    NAMES pcre2-8 NAMES_PER_DIR ${PC_PCRE2_LIBRARY_DIRS} PATH_SUFFIXES lib)
  find_library(PCRE2_LIBRARY_DEBUG
    NAMES pcre2-8d NAMES_PER_DIR ${PC_PCRE2_LIBRARY_DIRS} PATH_SUFFIXES lib)

  include(SelectLibraryConfigurations)
  SELECT_LIBRARY_CONFIGURATIONS(PCRE2)
else()
  file(TO_CMAKE_PATH "${PCRE2_LIBRARIES}" PCRE2_LIBRARIES)
endif()

set(PCRE2_VERSION ${PC_PCRE2_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2
  FOUND_VAR PCRE2_FOUND
  REQUIRED_VARS
    PCRE2_LIBRARIES
    PCRE2_INCLUDE_DIR
  VERSION_VAR PCRE2_VERSION
)

if(PCRE2_FOUND)
  set(PCRE2_INCLUDE_DIRS ${PCRE2_INCLUDE_DIR})
  set(PCRE2_DEFINITIONS ${PC_PCRE2_CFLAGS_OTHER})

  if(NOT TARGET PCRE2::pcre2)
    add_library(PCRE2::pcre2 UNKNOWN IMPORTED)
    set_target_properties(PCRE2::pcre2 PROPERTIES
      INTERFACE_COMPILE_OPTIONS "${PC_PCRE2_CFLAGS_OTHER}"
      INTERFACE_INCLUDE_DIRECTORIES "${PCRE2_INCLUDE_DIRS}")

    if(PCRE2_LIBRARY_RELEASE)
      set_property(TARGET PCRE2::pcre2 APPEND PROPERTY
        IMPORTED_CONFIGURATIONS RELEASE)
      set_target_properties(PCRE2::pcre2 PROPERTIES
        IMPORTED_LOCATION_RELEASE "${PCRE2_LIBRARY_RELEASE}"
      )
    endif()

    if(PCRE2_LIBRARY_DEBUG)
      set_property(TARGET PCRE2::pcre2 APPEND PROPERTY
        IMPORTED_CONFIGURATIONS DEBUG)
      set_target_properties(PCRE2::pcre2 PROPERTIES
        IMPORTED_LOCATION_DEBUG "${PCRE2_LIBRARY_DEBUG}"
      )
    endif()

    if(NOT PCRE2_LIBRARY_RELEASE AND NOT PCRE2_LIBRARY_DEBUG)
      set_property(TARGET PCRE2::pcre2 APPEND PROPERTY
        IMPORTED_LOCATION "${PCRE2_LIBRARY}")
    endif()
  endif()
endif()

mark_as_advanced(
  PCRE2_INCLUDE_DIR
  PCRE2_LIBRARY
)
