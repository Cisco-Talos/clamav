# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindPThreadW32
-------

Finds the PThreadW32 library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``PThreadW32::pthreadw32``
  The PThreadW32 library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``PThreadW32_FOUND``
  True if the system has the PThreadW32 library.
``PThreadW32_VERSION``
  The version of the PThreadW32 library which was found.
``PThreadW32_INCLUDE_DIRS``
  Include directories needed to use PThreadW32.
``PThreadW32_LIBRARIES``
  Libraries needed to link to PThreadW32.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``PThreadW32_INCLUDE_DIR``
  The directory containing ``foo.h``.
``PThreadW32_LIBRARY``
  The path to the PThreadW32 library.

#]=======================================================================]

if(NOT WIN32)
  message(FATAL_ERROR "This find module intended for use on Windows")
endif()

find_package(PkgConfig QUIET)
pkg_check_modules(PC_PThreadW32 QUIET pthreadw32)

find_path(PThreadW32_INCLUDE_DIR
  NAMES pthread.h
  PATHS ${PC_PThreadW32_INCLUDE_DIRS}
  PATH_SUFFIXES pthreadw32
)

if(PThreadW32_LIBRARY)
  set(PThreadW32_LIBRARIES "${PThreadW32_LIBRARY}")
endif()

if(NOT PThreadW32_LIBRARIES)
  find_library(PThreadW32_LIBRARY_RELEASE
    NAMES pthreadVC2 pthreadVC3 PATHS ${PC_PThreadW32_LIBRARY_DIRS})
  find_library(PThreadW32_LIBRARY_DEBUG
    NAMES pthreadVC2d pthreadVC3d PATHS ${PC_PThreadW32_LIBRARY_DIRS})

  include(SelectLibraryConfigurations)
  SELECT_LIBRARY_CONFIGURATIONS(PThreadW32)
else()
  file(TO_CMAKE_PATH "${PThreadW32_LIBRARIES}" PThreadW32_LIBRARIES)
endif()

set(PThreadW32_VERSION ${PC_PThreadW32_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PThreadW32
  FOUND_VAR PThreadW32_FOUND
  REQUIRED_VARS
    PThreadW32_LIBRARIES
    PThreadW32_INCLUDE_DIR
  VERSION_VAR PThreadW32_VERSION
)

if(PThreadW32_FOUND)
  set(PThreadW32_INCLUDE_DIRS ${PThreadW32_INCLUDE_DIR})
  set(PThreadW32_DEFINITIONS ${PC_PThreadW32_CFLAGS_OTHER})

  if(NOT TARGET PThreadW32::pthreadw32)
    add_library(PThreadW32::pthreadw32 UNKNOWN IMPORTED)
    set_target_properties(PThreadW32::pthreadw32 PROPERTIES
      INTERFACE_COMPILE_OPTIONS "${PC_PThreadW32_CFLAGS_OTHER}"
      INTERFACE_INCLUDE_DIRECTORIES "${PThreadW32_INCLUDE_DIR}"
    )

    if(PThreadW32_LIBRARY_RELEASE)
      set_property(TARGET PThreadW32::pthreadw32 APPEND PROPERTY
        IMPORTED_CONFIGURATIONS RELEASE)
      set_target_properties(PThreadW32::pthreadw32 PROPERTIES
        IMPORTED_LOCATION_RELEASE "${PThreadW32_LIBRARY_RELEASE}"
      )
    endif()

    if(PThreadW32_LIBRARY_DEBUG)
      set_property(TARGET PThreadW32::pthreadw32 APPEND PROPERTY
        IMPORTED_CONFIGURATIONS DEBUG)
      set_target_properties(PThreadW32::pthreadw32 PROPERTIES
        IMPORTED_LOCATION_DEBUG "${PThreadW32_LIBRARY_DEBUG}"
      )
    endif()

    if(NOT PThreadW32_LIBRARY_RELEASE AND NOT PThreadW32_LIBRARY_DEBUG)
      set_property(TARGET PThreadW32::pthreadw32 APPEND PROPERTY
        IMPORTED_LOCATION "${PThreadW32_LIBRARY}")
    endif()
  endif()
endif()

mark_as_advanced(
  PThreadW32_INCLUDE_DIR
  PThreadW32_LIBRARY
)
