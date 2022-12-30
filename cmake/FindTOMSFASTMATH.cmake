# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindTOMSFASTMATH
-------

Finds the TOMSFASTMATH library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``TOMSFASTMATH::tfm``
The TOMSFASTMATH library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``TOMSFASTMATH_FOUND``
True if the system has the TOMSFASTMATH library.
``TOMSFASTMATH_VERSION``
The version of the TOMSFASTMATH library which was found.
``TOMSFASTMATH_INCLUDE_DIRS``
Include directories needed to use TOMSFASTMATH.
``TOMSFASTMATH_LIBRARIES``
Libraries needed to link to TOMSFASTMATH.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``TOMSFASTMATH_INCLUDE_DIR``
  The directory containing ``tfm.h``.
  ``TOMSFASTMATH_LIBRARY``
  The path to the TOMSFASTMATH library.

#]=======================================================================]

if(NOT ENABLE_EXTERNAL_TOMSFASTMATH)
     set(TOMSFASTMATH_LIB_NAME "tomsfastmath")
     set(TOMSFASTMATH_BUILTIN 1)
else()
     set(TOMSFASTMATH_LIB_NAME "tfm")
     add_definitions(-DHAVE_SYSTEM_TOMSFASTMATH)

find_package(PkgConfig QUIET)
pkg_check_modules(PC_TOMSFASTMATH QUIET tomsfastmath)

find_path(TOMSFASTMATH_INCLUDE_DIR
  NAMES tfm.h
  PATHS ${PC_TOMSFASTMATH_INCLUDE_DIRS}
  PATH_SUFFIXES tfm
)
find_library(TOMSFASTMATH_LIBRARY
  NAMES tfm
  PATHS ${PC_TOMSFASTMATH_LIBRARY_DIRS}
)

set(TOMSFASTMATH_VERSION ${PC_TOMSFASTMATH_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TOMSFASTMATH
	FOUND_VAR TOMSFASTMATH_FOUND
  REQUIRED_VARS
  TOMSFASTMATH_LIBRARY
  TOMSFASTMATH_INCLUDE_DIR
  VERSION_VAR TOMSFASTMATH_VERSION
)

if(TOMSFASTMATH_FOUND)
	set(TOMSFASTMATH_LIBRARIES ${TOMSFASTMATH_LIBRARY})
	set(TOMSFASTMATH_INCLUDE_DIRS ${TOMSFASTMATH_INCLUDE_DIR})
	set(TOMSFASTMATH_DEFINITIONS ${PC_TOMSFASTMATH_CFLAGS_OTHER})
endif()

mark_as_advanced(
	TOMSFASTMATH_INCLUDE_DIR
	TOMSFASTMATH_LIBRARY
)
endif()
