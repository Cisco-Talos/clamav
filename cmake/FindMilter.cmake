# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindMilter
-------

Finds the Milter library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``Sendmail::milter``
  The Sendmail milter library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``Milter_FOUND``
  True if the system has the Milter library.
``Milter_VERSION``
  The version of the Milter library which was found.
``Milter_INCLUDE_DIRS``
  Include directories needed to use Milter.
``Milter_LIBRARIES``
  Libraries needed to link to Milter.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``Milter_INCLUDE_DIR``
  The directory containing ``foo.h``.
``Milter_LIBRARY``
  The path to the Milter library.

#]=======================================================================]

find_package(PkgConfig QUIET)
pkg_check_modules(PC_Milter QUIET milter)

find_path(Milter_INCLUDE_DIR
  NAMES libmilter/mfapi.h
  PATHS ${PC_Milter_INCLUDE_DIRS}
  PATH_SUFFIXES milter
)
find_library(Milter_LIBRARY
  NAMES milter
  PATHS ${PC_Milter_LIBRARY_DIRS}
)

set(Milter_VERSION ${PC_Milter_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Milter
  FOUND_VAR Milter_FOUND
  REQUIRED_VARS
    Milter_LIBRARY
    Milter_INCLUDE_DIR
  VERSION_VAR Milter_VERSION
)

if(Milter_FOUND)
  set(Milter_LIBRARIES ${Milter_LIBRARY})
  set(Milter_INCLUDE_DIRS ${Milter_INCLUDE_DIR})
  set(Milter_DEFINITIONS ${PC_Milter_CFLAGS_OTHER})
endif()

if(Milter_FOUND AND NOT TARGET Sendmail::milter)
  add_library(Sendmail::milter UNKNOWN IMPORTED)
  set_target_properties(Sendmail::milter PROPERTIES
    IMPORTED_LOCATION "${Milter_LIBRARY}"
    INTERFACE_COMPILE_OPTIONS "${PC_Milter_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${Milter_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(
  Milter_INCLUDE_DIR
  Milter_LIBRARY
)
