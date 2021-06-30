# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    cmake_minimum_required( VERSION 3.16 ) # For file(GET_RUNTIME_DEPENDENCIES)
else()
    cmake_minimum_required( VERSION 3.14 )
endif()

cmake_policy(SET CMP0087 NEW) # support generator expressions in install(CODE) and install(SCRIPT)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Change this on a release:
#  During active development: set(VERSION_SUFFIX "-devel-${TODAY}")
#  For beta:                  set(VERSION_SUFFIX "-beta")
#  For release candidate:     set(VERSION_SUFFIX "-rc")
#  For release:               set(VERSION_SUFFIX "")
string(TIMESTAMP TODAY "%Y%m%d")
set(VERSION_SUFFIX "-devel-${TODAY}")

project( ClamBCC
         VERSION "0.103.1"
         DESCRIPTION "ClamAV Bytecode Compiler." )

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
#include(Version)

set(PACKAGE_NAME      "${PROJECT_NAME}")
set(PACKAGE_VERSION   "${PROJECT_VERSION}")
set(PACKAGE_STRING    "${PROJECT_NAME} ${PROJECT_VERSION}${VERSION_SUFFIX}")
set(PACKAGE_BUGREPORT "https://github.com/Cisco-Talos/clamav-bytecode-compiler/issues")
set(PACKAGE_URL       "https://www.clamav.net/")
#HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

# libtool library versioning rules: http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
set(LIBCLAMBC_CURRENT  1)
set(LIBCLAMBC_REVISION 0)
set(LIBCLAMBC_AGE      0)

math(EXPR LIBCLAMBC_SOVERSION "${LIBCLAMBC_CURRENT} - ${LIBCLAMBC_AGE}")
set(LIBCLAMBC_VERSION "${LIBCLAMBC_SOVERSION}.${LIBCLAMBC_AGE}.${LIBCLAMBC_REVISION}")
#HexVersion(LIBCLAMBC_VERSION_NUM ${LIBCLAMBC_CURRENT} ${LIBCLAMBC_REVISION} ${LIBCLAMBC_AGE})

# Git optionally used to add commit info into build to differentiate in bug reports.
find_package(Git)
if(Git_FOUND)
    # Store git description into variable
    execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags --always
        OUTPUT_VARIABLE REPO_VERSION ERROR_QUIET)
    if("${REPO_VERSION}" MATCHES "")
        unset(REPO_VERSION)
    else()
        string(STRIP ${REPO_VERSION} REPO_VERSION)
    endif()
endif()

# Enable use of pkg-config to find depenencies.
find_package(PkgConfig QUIET)

#
# Load Build Options
#
set(ENABLE_TESTS_DEFAULT            ON)
set(ENABLE_EXAMPLES_DEFAULT         ON)

#TODO: Add manpages
if(WIN32)
    set(ENABLE_MAN_PAGES_DEFAULT    OFF)
else()
    set(ENABLE_MAN_PAGES_DEFAULT    OFF)
endif()

# See CMakeOptions.cmake for additional options.
include(CMakeOptions.cmake)

#
# Set RPATH for custom install prefixes
#
if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

# Used for the application interface and for facilitating testing
find_package(Python3 REQUIRED)

#
# Find Test dependencies
#
if(ENABLE_TESTS)
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -m pip show pytest
        RESULT_VARIABLE EXIT_CODE
        ERROR_QUIET OUTPUT_QUIET
    )

    if (NOT ${EXIT_CODE} EQUAL 0)
        message("Python3 package 'pytest' is not installed.")
        message("Failed unit tests will be easier to read if you install pytest.")
        message("Eg:  python3 -m pip install --user pytest")
        set(Python3_TEST_PACKAGE "unittest;--verbose")
    else()
        set(Python3_TEST_PACKAGE "pytest;-v")
    endif()

#    find_package(ClamAV REQUIRED)
endif()

find_package(Clang 8 REQUIRED)
find_package(LLVM 8 REQUIRED)

# Do not disable assertions based on CMAKE_BUILD_TYPE.
foreach(_build_type "Release" "MinSizeRel" "RelWithDebInfo")
    foreach(_lang C CXX)
        string(TOUPPER "CMAKE_${_lang}_FLAGS_${_build_type}" _var)
        string(REGEX REPLACE "(^|)[/-]D *NDEBUG($|)" " " ${_var} "${${_var}}")
    endforeach()
endforeach()

# Disable optimizations if OPTIMIZE=OFF
if(NOT OPTIMIZE)
    # Get rid of any previous optimization flag settings...
    string(REGEX REPLACE "(\-O[011123456789])" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REGEX REPLACE "(\-O[011123456789])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

    # ...And substitute our own.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
endif()

# Support the latest c++ standard available.
include(ExtractValidFlags)
foreach(_cxx1x_flag -std=c++14 -std=c++11)
    extract_valid_cxx_flags(_cxx1x_flag_supported ${_cxx1x_flag})
    if(_cxx1x_flag_supported)
        set(CXX1XCXXFLAGS ${_cxx1x_flag})
        break()
    endif()
endforeach()

#Temporarily disable building with optimizations, because there is a
#bug in one of the passes that is revealed by optimizations that has
#not been tracked down yet.
foreach(optSetting "-O1" "-O2" "-O3" "-Os")
    string(REPLACE ${optSetting}   ""   CMAKE_C_FLAGS_RELWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})
    string(REPLACE ${optSetting}   ""   CMAKE_C_FLAGS_MINSIZEREL ${CMAKE_C_FLAGS_MINSIZEREL})
    string(REPLACE ${optSetting}   ""   CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

    string(REPLACE ${optSetting}   ""   CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
    string(REPLACE ${optSetting}   ""   CMAKE_CXX_FLAGS_MINSIZEREL ${CMAKE_CXX_FLAGS_MINSIZEREL})
    string(REPLACE ${optSetting}   ""   CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
endforeach()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the build type" FORCE)

    # Include "None" as option to disable any additional (optimization) flags,
    # relying on just CMAKE_C_FLAGS and CMAKE_CXX_FLAGS (which are empty by
    # default). These strings are presented in cmake-gui.
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "None" "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Always use '-fPIC'/'-fPIE' option.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable lots of warnings
set(WARNCXXFLAGS "-Wall -Wextra")
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    if(ENABLE_WERROR)
        set(WARNCXXFLAGS  /WX)
    endif()
else()
    if(ENABLE_WERROR)
        extract_valid_cxx_flags(WARNCXXFLAGS -Werror)
    endif()

    extract_valid_cxx_flags(WARNCXXFLAGS
        -Wall
        -Wformat-security
        -Wno-unused-parameter
    )
endif()

#configure_file(clambc-version.h.in clambc-version.h)

#
# Build targets!
#

## The bytecode compiler optimization passes
## This is the core of the bytecode compiler
#add_subdirectory(libclambcc)

# The bytecode compiler application
# This is really just a python script
add_subdirectory(TestJIT)
add_subdirectory(JITMain)

# A tool to generate the runtime interface from the headers
#TODO: Finish updating ifacegen to work with modern LLVM
# add_subdirectory(clambc-ifacegen)

## The bytecode API headers used to compile bytecode signatures.
##
## Some of these are copied from ClamAV, some are generated,
## and some provide similar interfaces to familiar POSIX API's.
#add_subdirectory(headers)

# Documentation (doxygen, manpages)
#TODO:
# - Implement CMakeLists.txt for doxygen, manpages, and write manpages.
# - Translate TeX to markdown for easier editing.
#   `pandoc -s file.tex -o file.md` mostly-works, but w/ the doxygen integration is insufficient.
# add_subdirectory(docs)

#if(ENABLE_EXAMPLES)
#    # Example optimization passes; boilerplate to help compiler devs write new passes.
#    add_subdirectory( examples )
#endif()

#include(CTest)
#add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
#if(ENABLE_TESTS)
#    # Tests to verify compiler works as intended and that signatures behave as intended.
#    add_subdirectory( test )
#endif()

if(WIN32)
    # Include the license(s) in the installation
    install(FILES ${CMAKE_SOURCE_DIR}/COPYING.txt DESTINATION .)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/COPYING DESTINATION .)
endif()

#
# The Summary Info.
#
include(ColourMessage)
string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "${Y}Configuration Options Summary${e} --
${c}    Package Version:        ${e}${PACKAGE_STRING}
${c}    libclambcc version:     ${e}${LIBCLAMBC_CURRENT}:${LIBCLAMBC_REVISION}:${LIBCLAMBC_AGE}
${c}    Install prefix:         ${e}${CMAKE_INSTALL_PREFIX}
${c}    Host system:            ${e}${CMAKE_HOST_SYSTEM}
${c}    Target system:          ${e}${CMAKE_SYSTEM}
${c}    Compiler:               ${e}
${b}        Build type:         ${e}${CMAKE_BUILD_TYPE}
${b}        C++ compiler:       ${e}${CMAKE_CXX_COMPILER}
${b}        CXXFLAGS:           ${e}${CMAKE_CXX_FLAGS_${_build_type}} ${CMAKE_CXX_FLAGS}
${b}        WARNCXXFLAGS:       ${e}${WARNCXXFLAGS}
${c}    Build Options:          ${e}
${b}        Tests:              ${e}${ENABLE_TESTS}
${b}        Examples:           ${e}${ENABLE_EXAMPLES}
${b}        Build man pages:    ${e}${ENABLE_MAN_PAGES}
${b}        Build doxygen HTML: ${e}${ENABLE_DOXYGEN}")

message(STATUS "${C}Compiler Dependencies${e} --
${b}        LLVM Library:       ${e}
${_}                            ${e}${LLVM_LIBS} ${LLVM_LDFLAGS}
${_}                            ${e}${LLVM_INCLUDE_DIRS}
${b}        Clang Library:      ${e}
${_}                            ${e}${CLANG_LIBS} ${CLANG_LDFLAGS}
${_}                            ${e}${CLANG_INCLUDE_DIRS}
${b}        Clang Executable:   ${e}${CLANG_EXECUTABLE}")

if(ENABLE_TESTS)
message(STATUS "${C}Test Dependencies${e} --
${b}        Feature Test Framework:${e}
${_}            python3         ${e}${Python3_EXECUTABLE}
${_}                            ${e}${Python3_TEST_PACKAGE}
${_}            clamav          ${e}${ClamAV_VERSION}
${_}                clamscan:   ${e}${clamscan_EXECUTABLE}
${_}                bc-headers: ${e}${clambc_headers_DIRECTORY}")
endif()
