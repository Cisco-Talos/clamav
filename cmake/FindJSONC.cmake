# From https://github.com/fastogt/cmake/blob/master/FindJSON-C.cmake
# Copyright (c) 2018, FastoGT
# License: BSD 3-Clause
# Modified by: Micah Snyder

# JSONC_FOUND - true if library and headers were found
# JSONC_INCLUDE_DIRS - include directories
# JSONC_LIBRARIES - library directories

if(JSONC_USE_STATIC)
  add_library(jsonc STATIC IMPORTED GLOBAL)
else()
  add_library(jsonc SHARED IMPORTED GLOBAL)
endif(JSONC_USE_STATIC)

find_package(PkgConfig QUIET)
PKG_CHECK_MODULES(PC_JSONC QUIET json-c)

find_path(JSONC_INCLUDE_DIR json.h
  HINTS ${PC_JSONC_INCLUDEDIR} ${PC_JSONC_INCLUDE_DIRS} PATH_SUFFIXES json-c json)

if(JSONC_USE_STATIC)
  find_library(JSONC_LIBRARY NAMES libjson-c.a libjson-c-static.a
    HINTS ${PC_JSONC_LIBDIR} ${PC_JSONC_LIBRARY_DIRS})
else()
  find_library(JSONC_LIBRARY NAMES json-c libjson-c
    HINTS ${PC_JSONC_LIBDIR} ${PC_JSONC_LIBRARY_DIRS})
endif(JSONC_USE_STATIC)

set(JSONC_LIBRARIES ${JSONC_LIBRARY})
set(JSONC_INCLUDE_DIRS ${JSONC_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSONC DEFAULT_MSG JSONC_LIBRARIES JSONC_INCLUDE_DIRS)

if(JSONC_FOUND AND NOT TARGET JSONC::jsonc)
  add_library(JSONC::jsonc UNKNOWN IMPORTED)
  set_target_properties(JSONC::jsonc PROPERTIES
    IMPORTED_LOCATION "${JSONC_LIBRARY}"
    INTERFACE_COMPILE_OPTIONS "${PC_JSONC_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${JSONC_INCLUDE_DIRS}"
  )
endif()

mark_as_advanced(
  JSONC_INCLUDE_DIR
  JSONC_LIBRARY
)
