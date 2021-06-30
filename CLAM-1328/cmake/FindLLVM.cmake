# Find the native LLVM includes and libraries
#
# Defines the following variables
#  LLVM_INCLUDE_DIRS   - where to find llvm include files
#  LLVM_LIBRARY_DIRS   - where to find llvm libs
#  LLVM_CFLAGS         - llvm compiler flags
#  LLVM_LFLAGS         - llvm linker flags
#  LLVM_MODULE_LIBS    - list of llvm libs for working with modules.
#  LLVM_INSTALL_PREFIX - LLVM installation prefix
#  LLVM_FOUND          - True if llvm found.
#  LLVM_VERSION        - Version string ("llvm-config --version")
#
# This module reads hints about search locations from variables
#  LLVM_ROOT           - Preferred LLVM installation prefix (containing bin/, lib/, ...)
#
#  Note: One may specify these as environment variables if they are not specified as
#   CMake variables or cache entries.

#=============================================================================
# Copyright 2014 Kevin Funk <kfunk@kde.org>
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================

if (NOT LLVM_ROOT AND DEFINED ENV{LLVM_ROOT})
    file(TO_CMAKE_PATH "$ENV{LLVM_ROOT}" LLVM_ROOT)
endif()

# if the user specified LLVM_ROOT, use that and fail otherwise
if (LLVM_ROOT)
  find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config HINTS ${LLVM_ROOT}/bin DOC "llvm-config executable" NO_DEFAULT_PATH)
elseif (NOT LLVM_CONFIG_EXECUTABLE)
  # find llvm-config, prefer the one with a version suffix, e.g. llvm-config-3.5
  # note: FreeBSD installs llvm-config as llvm-config35 and so on
  # note: on some distributions, only 'llvm-config' is shipped, so let's always try to fallback on that
  string(REPLACE "." "" LLVM_FIND_VERSION_CONCAT ${LLVM_FIND_VERSION})
  find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config-${LLVM_FIND_VERSION} llvm-config${LLVM_FIND_VERSION_CONCAT} llvm-config DOC "llvm-config executable")

  # other distributions don't ship llvm-config, but only some llvm-config-VERSION binary
  # try to deduce installed LLVM version by looking up llvm-nm in PATH and *then* find llvm-config-VERSION via that
  if (NOT LLVM_CONFIG_EXECUTABLE)
    find_program(_llvmNmExecutable llvm-nm)
    if (_llvmNmExecutable)
      execute_process(COMMAND ${_llvmNmExecutable} --version OUTPUT_VARIABLE _out)
      string(REGEX REPLACE ".*LLVM version ([^ \n]+).*" "\\1" _versionString "${_out}")
      find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config-${_versionString} DOC "llvm-config executable")
    endif()
  endif()
endif()

set(LLVM_FOUND FALSE)

if (LLVM_CONFIG_EXECUTABLE)
  # verify that we've found the correct version of llvm-config
  execute_process(COMMAND ${LLVM_CONFIG_EXECUTABLE} --version
    OUTPUT_VARIABLE LLVM_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  if (NOT LLVM_VERSION)
    set(_LLVM_ERROR_MESSAGE "Failed to parse version from ${LLVM_CONFIG_EXECUTABLE}")
    unset(LLVM_CONFIG_EXECUTABLE CACHE)
  elseif (LLVM_FIND_VERSION VERSION_GREATER LLVM_VERSION)
    set(_LLVM_ERROR_MESSAGE "${LLVM_CONFIG_EXECUTABLE} (version ${LLVM_VERSION}) unsuitable: too old for requested version ${LLVM_FIND_VERSION}")
    unset(LLVM_CONFIG_EXECUTABLE CACHE)
  else()
    set(LLVM_FOUND TRUE)
  endif()
else()
  set(_LLVM_ERROR_MESSAGE "Could NOT find 'llvm-config' executable")
endif()

if (LLVM_FOUND)
  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --includedir
    OUTPUT_VARIABLE LLVM_INCLUDE_DIRS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --libdir
    OUTPUT_VARIABLE LLVM_LIBRARY_DIRS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --cppflags
    OUTPUT_VARIABLE LLVM_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --ldflags
    OUTPUT_VARIABLE LLVM_LFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --libs core bitreader asmparser analysis
    OUTPUT_VARIABLE LLVM_MODULE_LIBS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --libfiles
    OUTPUT_VARIABLE LLVM_LIBS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --prefix
    OUTPUT_VARIABLE LLVM_INSTALL_PREFIX
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  if (NOT ${LLVM_VERSION} VERSION_LESS "3.8.0")
    execute_process(
        COMMAND ${LLVM_CONFIG_EXECUTABLE} --shared-mode
        OUTPUT_VARIABLE _LLVM_SHARED_MODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (_LLVM_SHARED_MODE STREQUAL "shared")
        set(LLVM_SHARED_MODE ON)
    else()
        set(LLVM_SHARED_MODE OFF)
    endif()
  else()
    set(LLVM_SHARED_MODE OFF)
  endif()

  # potentially add include dir from binary dir for non-installed LLVM
  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --src-root
    OUTPUT_VARIABLE _llvmSourceRoot
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  string(FIND "${LLVM_INCLUDE_DIRS}" "${_llvmSourceRoot}" _llvmIsInstalled)
  if (NOT _llvmIsInstalled)
    list(APPEND LLVM_INCLUDE_DIRS "${LLVM_INSTALL_PREFIX}/include")
  endif()
endif()

if (LLVM_FIND_REQUIRED AND NOT LLVM_FOUND)
  message(FATAL_ERROR "Could not find LLVM: ${_LLVM_ERROR_MESSAGE}")
elseif(_LLVM_ERROR_MESSAGE)
  message(STATUS "Could not find LLVM: ${_LLVM_ERROR_MESSAGE}")
endif()

if (LLVM_FOUND)
  message(STATUS "Found LLVM (version: ${LLVM_VERSION}): (using ${LLVM_CONFIG_EXECUTABLE})")
  message(STATUS "  Include dirs:   ${LLVM_INCLUDE_DIRS}")
  message(STATUS "  LLVM libraries: ${LLVM_LIBS}")
endif()
