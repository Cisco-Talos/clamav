# Detect Clang libraries
#
# Defines the following variables:
#  CLANG_FOUND                 - True if Clang was found
#  CLANG_INCLUDE_DIRS          - Where to find Clang includes
#  CLANG_LIBRARY_DIRS          - Where to find Clang libraries
#  CLANG_BUILTIN_DIR           - Where to find Clang builtin includes
#
#  CLANG_CLANG_LIB             - Libclang C library
#
#  CLANG_CLANGFRONTEND_LIB     - Clang Frontend (C++) Library
#  CLANG_CLANGDRIVER_LIB       - Clang Driver (C++) Library
#  ...
#
#  CLANG_LIBS                  - All the Clang C++ libraries
#
# Uses the same include and library paths detected by FindLLVM.cmake
#
# See https://clang.llvm.org/docs/InternalsManual.html for full list of libraries

#=============================================================================
# Copyright 2014-2015 Kevin Funk <kfunk@kde.org>
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.

#=============================================================================

set(KNOWN_VERSIONS 11 10 9 8 7 6.0 5.0 4.0 3.9 3.8)

foreach(version ${KNOWN_VERSIONS})
    if(DEFINED Clang_FIND_VERSION AND Clang_FIND_VERSION VERSION_EQUAL version)
        find_package(LLVM ${version} PATHS ${LLVM_ROOT})
    else()
        find_package(LLVM PATHS ${LLVM_ROOT})
    endif()
endforeach()

if (${Clang_FIND_REQUIRED})
    if(NOT DEFINED LLVM_FOUND)
        message(SEND_ERROR "Could not find LLVM (or Clang for that matter)")
    else()
        message("Found LLVM version ${LLVM_VERSION}")
    endif()
endif()

set(CLANG_FOUND FALSE)

if(LLVM_FOUND AND LLVM_LIBRARY_DIRS)
  message("Searching for clang libraries...")
  macro(FIND_AND_ADD_CLANG_LIB _libname_)
    # message("Searching for ${LLVM_LIBRARY_DIRS}/lib${_libname_}-${Clang_FIND_VERSION}.so.1")
    string(TOUPPER ${_libname_} _prettylibname_)
    find_library(CLANG_${_prettylibname_}_LIB
      NAMES
        ${_libname_}-${Clang_FIND_VERSION}.so.1 lib${_libname_}-${Clang_FIND_VERSION}.so.1
        ${_libname_}-${Clang_FIND_VERSION} lib${_libname_}-${Clang_FIND_VERSION}
        ${_libname_}.so.1 lib${_libname_}.so.1
        ${_libname_} lib${_libname_}
      HINTS
        ${LLVM_LIBRARY_DIRS} ${ARGN})
    if(CLANG_${_prettylibname_}_LIB)
      message("Found ${CLANG_${_prettylibname_}_LIB}")
      set(CLANG_LIBS ${CLANG_LIBS} ${CLANG_${_prettylibname_}_LIB})
    endif()
  endmacro(FIND_AND_ADD_CLANG_LIB)

  FIND_AND_ADD_CLANG_LIB(clangFrontend)

  # note: On Windows there's 'libclang.dll' instead of 'clang.dll' -> search for 'libclang', too
  FIND_AND_ADD_CLANG_LIB(clang NAMES clang libclang clang-${Clang_FIND_VERSION} libclang-${Clang_FIND_VERSION}) # LibClang: high-level C interface

  FIND_AND_ADD_CLANG_LIB(clangDriver)
  FIND_AND_ADD_CLANG_LIB(clangCodeGen)
  FIND_AND_ADD_CLANG_LIB(clangSema)
  FIND_AND_ADD_CLANG_LIB(clangChecker)
  FIND_AND_ADD_CLANG_LIB(clangAnalysis)
  FIND_AND_ADD_CLANG_LIB(clangRewriteFrontend)
  FIND_AND_ADD_CLANG_LIB(clangRewrite)
  FIND_AND_ADD_CLANG_LIB(clangAST)
  FIND_AND_ADD_CLANG_LIB(clangParse)
  FIND_AND_ADD_CLANG_LIB(clangLex)
  FIND_AND_ADD_CLANG_LIB(clangBasic)
  FIND_AND_ADD_CLANG_LIB(clangARCMigrate)
  FIND_AND_ADD_CLANG_LIB(clangEdit)
  FIND_AND_ADD_CLANG_LIB(clangFrontendTool)
  FIND_AND_ADD_CLANG_LIB(clangSerialization)
  FIND_AND_ADD_CLANG_LIB(clangTooling)
  FIND_AND_ADD_CLANG_LIB(clangStaticAnalyzerCheckers)
  FIND_AND_ADD_CLANG_LIB(clangStaticAnalyzerCore)
  FIND_AND_ADD_CLANG_LIB(clangStaticAnalyzerFrontend)
  FIND_AND_ADD_CLANG_LIB(clangRewriteCore)
endif()

if(CLANG_LIBS OR CLANG_CLANG_LIB)
  set(CLANG_FOUND TRUE)
else()
  message(STATUS "Could not find any Clang libraries in ${LLVM_LIBRARY_DIRS}")
endif()

if(CLANG_FOUND)
  set(CLANG_LIBRARY_DIRS ${LLVM_LIBRARY_DIRS})
  set(CLANG_INCLUDE_DIRS ${LLVM_INCLUDE_DIRS})
  set(CLANG_VERSION ${LLVM_VERSION})

  # svn version of clang has a svn suffix "8.0.0svn" but installs the header in "8.0.0", without the suffix
  string(REPLACE "svn" "" CLANG_VERSION_CLEAN "${CLANG_VERSION}")
  # dito for git
  string(REPLACE "git" "" CLANG_VERSION_CLEAN "${CLANG_VERSION}")

  find_path(CLANG_BUILTIN_DIR
            # cpuid.h because it is defined in ClangSupport constructor as valid clang builtin dir indicator
            NAMES "cpuid.h"
            PATHS "${CLANG_LIBRARY_DIRS}"
                  "${CLANG_INCLUDE_DIRS}"
            PATH_SUFFIXES "clang/${CLANG_VERSION}/include"
                          "../../../clang/${CLANG_VERSION}/include"
                          "clang/${CLANG_VERSION_CLEAN}/include"
                          "../../../clang/${CLANG_VERSION_CLEAN}/include"
            NO_DEFAULT_PATH
  )

  if (NOT CLANG_BUILTIN_DIR)
      message(FATAL_ERROR "Could not find Clang builtin directory")
  endif()
  get_filename_component(CLANG_BUILTIN_DIR ${CLANG_BUILTIN_DIR} ABSOLUTE)

  # check whether llvm-config comes from an install prefix
  execute_process(
    COMMAND ${LLVM_CONFIG_EXECUTABLE} --src-root
    OUTPUT_VARIABLE _llvmSourceRoot
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  string(FIND "${LLVM_INCLUDE_DIRS}" "${_llvmSourceRoot}" _llvmIsInstalled)
  if (NOT _llvmIsInstalled)
    message(STATUS "Detected that llvm-config comes from a build-tree, adding more include directories for Clang")
    list(APPEND CLANG_INCLUDE_DIRS
         "${LLVM_INSTALL_PREFIX}/tools/clang/include" # build dir
    )

    # check whether the source is from llvm-project.git (currently recommended way to clone the LLVM projects)
    # contains all LLVM projects in the top-level directory
    get_filename_component(_llvmProjectClangIncludeDir ${_llvmSourceRoot}/../clang/include REALPATH)
    if (EXISTS ${_llvmProjectClangIncludeDir})
        message(STATUS "  Note: llvm-project.git structure detected, using different include path pointing into source dir")
        list(APPEND CLANG_INCLUDE_DIRS "${_llvmProjectClangIncludeDir}") # source dir
    else()
        list(APPEND CLANG_INCLUDE_DIRS "${_llvmSourceRoot}/tools/clang/include") # source dir
    endif()
  endif()

  # if the user specified LLVM_ROOT, use that and fail otherwise
  if (LLVM_ROOT)
    find_program(CLANG_EXECUTABLE NAMES clang HINTS ${LLVM_ROOT}/bin DOC "clang executable" NO_DEFAULT_PATH)
  elseif (NOT CLANG_EXECUTABLE)
    # find clang, prefer the one with a version suffix, e.g. clang-3.5
    # note: FreeBSD installs clang as clang35 and so on
    # note: on some distributions, only 'clang' is shipped, so let's always try to fallback on that
    string(REPLACE "." "" Clang_FIND_VERSION_CONCAT ${Clang_FIND_VERSION})
    find_program(CLANG_EXECUTABLE NAMES clang-${Clang_FIND_VERSION} clang${Clang_FIND_VERSION_CONCAT} clang DOC "clang executable")
  endif()

  message(STATUS "Found Clang (LLVM version: ${CLANG_VERSION})")
  message(STATUS "  Include dirs:        ${CLANG_INCLUDE_DIRS}")
  message(STATUS "  Clang libraries:     ${CLANG_LIBS}")
  message(STATUS "  Libclang C library:  ${CLANG_CLANG_LIB}")
  message(STATUS "  Builtin include dir: ${CLANG_BUILTIN_DIR}")
  message(STATUS "  Clang executable:    ${CLANG_EXECUTABLE}")
else()
  if(Clang_FIND_REQUIRED)
    message(FATAL_ERROR "Could NOT find Clang")
  endif()
endif()
