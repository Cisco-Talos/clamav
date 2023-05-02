# Copyright (C) 2019-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Change this on a release:
#  During active development: set(VERSION_SUFFIX "-devel-${TODAY}")
#  For beta:                  set(VERSION_SUFFIX "-beta")
#  For release candidate:     set(VERSION_SUFFIX "-rc")
#  For release:               set(VERSION_SUFFIX "")
string(TIMESTAMP TODAY "%Y%m%d")
set(VERSION_SUFFIX "")

project( ClamAV
         VERSION "0.103.9"
         DESCRIPTION "ClamAV open source email, web, and end-point anti-virus toolkit." )

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
include(Version)

set(PACKAGE_NAME      "${PROJECT_NAME}")
set(PACKAGE_VERSION   "${PROJECT_VERSION}")
set(PACKAGE_STRING    "${PROJECT_NAME} ${PROJECT_VERSION}${VERSION_SUFFIX}")
set(PACKAGE_BUGREPORT "https://github.com/Cisco-Talos/clamav/issues")
set(PACKAGE_URL       "https://www.clamav.net/")
HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

# libtool library versioning rules: http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
set(LIBCLAMAV_CURRENT  9)
set(LIBCLAMAV_REVISION 5)
set(LIBCLAMAV_AGE      0)

math(EXPR LIBCLAMAV_SOVERSION "${LIBCLAMAV_CURRENT} - ${LIBCLAMAV_AGE}")
set(LIBCLAMAV_VERSION "${LIBCLAMAV_SOVERSION}.${LIBCLAMAV_AGE}.${LIBCLAMAV_REVISION}")
HexVersion(LIBCLAMAV_VERSION_NUM ${LIBCLAMAV_CURRENT} ${LIBCLAMAV_REVISION} ${LIBCLAMAV_AGE})

set(LIBFRESHCLAM_CURRENT  2)
set(LIBFRESHCLAM_REVISION 1)
set(LIBFRESHCLAM_AGE      0)

math(EXPR LIBFRESHCLAM_SOVERSION "${LIBFRESHCLAM_CURRENT} - ${LIBFRESHCLAM_AGE}")
set(LIBFRESHCLAM_VERSION "${LIBFRESHCLAM_SOVERSION}.${LIBFRESHCLAM_AGE}.${LIBFRESHCLAM_REVISION}")
HexVersion(LIBFRESHCLAM_VERSION_NUM ${LIBFRESHCLAM_CURRENT} ${LIBFRESHCLAM_REVISION} ${LIBFRESHCLAM_AGE})

# Git optionally used to add commit info into build to differentiate in bug reports.
find_package(Git)
if(Git_FOUND)
    # Store git description into variable
    execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags --always
        OUTPUT_VARIABLE REPO_VERSION)
    if("${REPO_VERSION}" MATCHES "")
        unset(REPO_VERSION)
    else()
        string(STRIP ${REPO_VERSION} REPO_VERSION)
    endif()
endif()

# Enable use of pkg-config to find depenencies.
find_package(PkgConfig QUIET)

#
# Find Build Tools
#

if(MAINTAINER_MODE)
    # Bison, Flex required to build Yara module for libclamav.
    find_package(BISON REQUIRED)
    find_package(FLEX  REQUIRED)
    # TODO: Gperf required to generate JS-normalization code.
    # find_package(GPERF REQUIRED)
endif()

#
# Load Build Options
#

# CMake Option default values:
set(ENABLE_APP_DEFAULT          ON)
set(ENABLE_MILTER_DEFAULT       OFF)
set(ENABLE_CLAMONACC_DEFAULT    ON)
set(ENABLE_EXAMPLES_DEFAULT     OFF)
if(WIN32)
    set(ENABLE_DOCS_DEFAULT     OFF)
else()
    set(ENABLE_DOCS_DEFAULT     ON)
endif()
set(ENABLE_DOXYGEN_DEFAULT      OFF)
set(ENABLE_UNRAR_DEFAULT        ON)
set(ENABLE_SYSTEMD_DEFAULT      ON)

# See CMakeOptions.cmake for additional options.
include(CMakeOptions.cmake)

if(ENABLE_LIBCLAMAV_ONLY AND (ENABLE_APP OR ENABLE_EXAMPLES))
    # Remember when disabled options are disabled for later diagnostics.
    set(ENABLE_LIB_ONLY_DISABLED_OTHERS 1)
else()
    set(ENABLE_LIB_ONLY_DISABLED_OTHERS 0)
endif()
if(ENABLE_LIBCLAMAV_ONLY)
    set(ENABLE_APP              OFF)
    set(ENABLE_EXAMPLES         OFF)
endif()

#
# Set RPATH for custom install prefixes
#
if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

#
# Define LINUX because CMake only defines UNIX
#
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(LINUX 1)

    if(CMAKE_COMPILER_IS_GNUCXX)
        # For O_LARGEFILE, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, etc flags on older systems
        # (pre POSIX.1-2008: glibc 2.11 and earlier). #4042
        set(_GNU_SOURCE 1)
    endif()
endif()

#
# Set FreeBSD include path to include /usr/local/include
#
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    include_directories(/usr/local/include)
endif()

#
# Use the `lib` prefix on Windows, to match previous ClamAV build
#
if(WIN32)
   set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
   set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
endif()

#
# Find Library Dependencies
#
if (WIN32)
    find_package(PThreadW32)
    set(HAVE_PTHREAD_H 1)
    set(_REENTRANT 1)
    set(CL_THREAD_SAFE 1)
else()
    set(CMAKE_THREAD_PREFER_PTHREAD 1)
    find_package(Threads)
    if(Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
        set(HAVE_PTHREAD_H 1)
        set(_REENTRANT 1)
        set(CL_THREAD_SAFE 1)
    endif()
endif()

# libclamav efficacy dependencies
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(HAVE_LIBSSL 1)
endif()

find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    set(HAVE_ZLIB_H 1)
    set(HAVE_LIBZ 1)
endif()

find_package(BZip2 REQUIRED)
if(BZIP2_FOUND)
    set(HAVE_BZLIB_H 1)
endif()

find_package(LibXml2 REQUIRED)
if(LibXml2_FOUND)
    set(HAVE_LIBXML2 1)
endif()

find_package(PCRE2 REQUIRED)
if(PCRE2_FOUND)
    set(HAVE_PCRE 1)
    set(USING_PCRE2 1)
endif()

# libclamav feature dependencies
if(NOT WIN32)
    find_package(Iconv REQUIRED)
    # Set variable required by libclamav to use iconv
    set(HAVE_ICONV 1)
endif()

if(ENABLE_JSON_SHARED)
    set(JSONC_USE_STATIC OFF)
else()
    set(JSONC_USE_STATIC ON)
endif()
find_package(JSONC REQUIRED)
# Set variable required by libclamav to use libjson-c
set(HAVE_JSON 1)

if(BYTECODE_RUNTIME STREQUAL "llvm")
    find_package(LLVM REQUIRED)
    if(LLVM_FOUND)
        # Set variable required by libclamav to use llvm instead of interpreter
        set(LLVM_VERSION ${LLVM_VERSION_MAJOR}${LLVM_VERSION_MINOR})
    endif()
endif()

# libfreshclam & app dependencies
if(NOT ENABLE_LIBCLAMAV_ONLY)
    find_package(CURL REQUIRED)

    if(APPLE)
        find_library(APPLE_CORE_FOUNDATION CoreFoundation)
        if (NOT APPLE_CORE_FOUNDATION)
            message(FATAL_ERROR "Apple CoreFoundation framework not found")
        endif()
        find_library(APPLE_SECURITY Security)
        if (NOT APPLE_SECURITY)
            message(FATAL_ERROR "Apple Security framework not found")
        endif()
    endif()

    if(ENABLE_APP)
        find_package(CURSES REQUIRED)

        if(NOT WIN32 AND ENABLE_MILTER)
            find_package(Milter REQUIRED)
        endif()

        if(LINUX AND ENABLE_SYSTEMD)
            find_package(SYSTEMD)
            if(SYSTEMD_FOUND)
                set(HAVE_SYSTEMD 1)
            endif()
        endif()
    endif()
endif()


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

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the build type" FORCE)

    # Include "None" as option to disable any additional (optimization) flags,
    # relying on just CMAKE_C_FLAGS and CMAKE_CXX_FLAGS (which are empty by
    # default). These strings are presented in cmake-gui.
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "None" "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

include(GNUInstallDirs)

# For test scripts and documentation
find_package(Python3)

# Always use '-fPIC'/'-fPIE' option.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Checks for header files.
include(CheckIncludeFile)
check_include_file("arpa/inet.h"        HAVE_ARPA_INET_H)
check_include_file("fcntl.h"            HAVE_FCNTL_H)
check_include_file("grp.h"              HAVE_GRP_H)
check_include_file("limits.h"           HAVE_LIMITS_H)
check_include_file("malloc.h"           HAVE_MALLOC_H)
check_include_file("netdb.h"            HAVE_NETDB_H)
check_include_file("netinet/in.h"       HAVE_NETINET_IN_H)
check_include_file("poll.h"             HAVE_POLL_H)
check_include_file("pwd.h"              HAVE_PWD_H)
check_include_file("stdbool.h"          HAVE_STDBOOL_H)
check_include_file("stdlib.h"           HAVE_STDLIB_H)
check_include_file("string.h"           HAVE_STRING_H)
check_include_file("strings.h"          HAVE_STRINGS_H)
check_include_file("sys/cdefs.h"        HAVE_SYS_CDEFS_H)
check_include_file("sys/dl.h"           HAVE_SYS_DL_H)
check_include_file("sys/fileio.h"       HAVE_SYS_FILIO_H)
check_include_file("sys/mman.h"         HAVE_SYS_MMAN_H)
check_include_file("sys/param.h"        HAVE_SYS_PARAM_H)
check_include_file("sys/queue.h"        HAVE_SYS_QUEUE_H)
check_include_file("sys/select.h"       HAVE_SYS_SELECT_H)
check_include_file("sys/socket.h"       HAVE_SYS_SOCKET_H)
check_include_file("sys/stat.h"         HAVE_SYS_STAT_H)
check_include_file("sys/time.h"         HAVE_SYS_TIME_H)
check_include_file("sys/times.h"        HAVE_SYS_TIMES_H)
check_include_file("sys/uio.h"          HAVE_SYS_UIO_H)
check_include_file("syslog.h"           USE_SYSLOG)
check_include_file("termios.h"          HAVE_TERMIOS_H)
check_include_file("time.h"             HAVE_TIME_H)
check_include_file("unistd.h"           HAVE_UNISTD_H)
check_include_file("sys/fanotify.h"     HAVE_SYS_FANOTIFY_H)

if(WIN32)
    set(HAVE_RESOLV_H 1)
    set(HAVE_DIRENT_H 1)
    set(HAVE_DLFCN_H 1)
else()
    if(APPLE)
        set(BIND_8_COMPAT 1)
    endif()
    check_include_file("resolv.h"       HAVE_RESOLV_H) # Disabled, beacuse libfreshclam/dns.c is broken.
    check_include_file("dirent.h"       HAVE_DIRENT_H)
    check_include_file("dlfcn.h"        HAVE_DLFCN_H)
endif()

# int-types variants
check_include_file("inttypes.h"         HAVE_INTTYPES_H)
check_include_file("sys/inttypes.h"     HAVE_SYS_INTTYPES_H)
check_include_file("sys/int_types.h"    HAVE_SYS_INT_TYPES_H)
check_include_file("stdint.h"           HAVE_STDINT_H)

include(CheckTypeSize)
# Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T
check_type_size("ssize_t" SIZEOF_SSIZE_T)
if(SIZEOF_SSIZE_T STREQUAL "")
    # ssize_t is a signed type in POSIX storing at least -1.
    # Set it to "int" to match the behavior of AC_TYPE_SSIZE_T (autotools).
    set(ssize_t int)
endif()
check_type_size("off_t" SIZEOF_OFF_T)
if(SIZEOF_OFF_T STREQUAL "")
    # off_t is a signed type in POSIX no narrower than int.
    # Set it to "long int" to match the behavior of AC_TYPE_OFF_T (autotools).
    set(off_t long int)
endif()

check_type_size("int" SIZEOF_INT)
check_type_size("short" SIZEOF_SHORT)
check_type_size("long" SIZEOF_LONG)
check_type_size("long long" SIZEOF_LONG_LONG)

#
# Variables for clamav-types.h.in
#
if(HAVE_SYS_INT_TYPES_H)
    set(INT_TYPES_HEADER "#include <sys/int_types.h>")
elseif(HAVE_INTTYPES_H)
    set(INT_TYPES_HEADER "#include <inttypes.h>")
elseif(HAVE_STDINT_H)
    set(INT_TYPES_HEADER "#include <stdint.h>")
elseif(WIN32 AND MSVC)
    # Windows / Visual C++ (not Cygwin), stdint.h should exist.
    set(INT_TYPES_HEADER "#include <stdint.h>")
else()
    # No int types header available. We'll define the types manually.
    set(INT8_DEF "typedef signed char int8_t;")
    set(UINT8_DEF "typedef unsigned char uint8_t;")

    if(SIZEOF_INT EQUAL 2)
        set(INT16_DEF "typedef signed int int16_t;")
        set(UINT16_DEF "typedef unsigned int uint16_t;")
    elif(SIZEOF_SHORT EQUAL 2)
        set(INT16_DEF "typedef signed short int16_t;")
        set(UINT16_DEF "typedef unsigned short uint16_t;")
    endif()

    if(SIZEOF_INT EQUAL 4)
        set(INT32_DEF "typedef signed int int32_t;")
        set(UINT32_DEF "typedef unsigned int uint32_t;")
    elif(SIZEOF_LONG EQUAL 4)
        set(INT32_DEF "typedef signed long int32_t;")
        set(UINT32_DEF "typedef unsigned long uint32_t;")
    endif()

    if(SIZEOF_LONG EQUAL 8)
        set(INT64_DEF "typedef signed long int64_t;")
        set(UINT64_DEF "typedef unsigned long uint64_t;")
    elif(SIZEOF_LONG_LONG EQUAL 8)
        set(INT64_DEF "typedef signed long long int64_t;")
        set(UINT64_DEF "typedef unsigned long long uint64_t;")
    endif()
endif()

# Check for restrict keyword
#TODO: Move this to a .cmake file
foreach( ac_kw __restrict __restrict__ _Restrict restrict )
    check_c_source_compiles(
        "
        typedef int * int_ptr;
        int foo (int_ptr ${ac_kw} ip) {
            return ip[0];
        }
        int main() {
            int s[1];
            int * ${ac_kw} t = s;
            t[0] = 0;
            return foo(t);
        }
        "
        HAVE_RESTRICT )

    if( HAVE_RESTRICT )
        set( ac_cv_c_restrict ${ac_kw} )
        break()
    endif()
endforeach()
if( HAVE_RESTRICT )
    set( restrict ${ac_cv_c_restrict} )
endif()

# Define inline macro as needed.
include(TestInline)
# Determine if _FILE_OFFSET_BITS 64 needs to be set to handle large files.
include(CheckFileOffsetBits)
# Determine how to pack structs on this platform.
include(CheckStructPacking)
# Check for signed right shift implementation.
include(CheckSignedRightShift)
# Check if systtem fts implementation available
include(CheckFTS)
# Check if uname(2) follows POSIX standard.
include(CheckUnamePosix)
# Check support for file descriptor passing
include(CheckFDPassing)

# Check if big-endian
include(TestBigEndian)
TEST_BIG_ENDIAN(WORDS_BIGENDIAN)

include(CheckStructHasMember)
check_struct_has_member("struct tm" tm_gmtoff time.h HAVE_STRUCT_TM_TM_GMTOFF)

# Check size of pointer to decide we need 8 bytes alignment adjustment.
check_type_size("int *"   SIZEOF_INT_P)
check_type_size("time_t"  SIZEOF_TIME_T)

# Checks for library functions.
include(CheckSymbolExists)
check_symbol_exists(_Exit           "stdlib.h"      HAVE__EXIT)
check_symbol_exists(accept4         "sys/types.h"   HAVE_ACCEPT4)
check_symbol_exists(snprintf        "stdio.h"       HAVE_SNPRINTF)
check_symbol_exists(stat64          "sys/stat.h"    HAVE_STAT64)
check_symbol_exists(strcasestr      "string.h"      HAVE_STRCASESTR)
check_symbol_exists(strerror_r      "string.h"      HAVE_STRERROR_R)
check_symbol_exists(strlcat         "string.h"      HAVE_STRLCAT)
check_symbol_exists(strlcpy         "string.h"      HAVE_STRLCPY)
check_symbol_exists(strndup         "string.h"      HAVE_STRNDUP)
check_symbol_exists(strnlen         "string.h"      HAVE_STRNLEN)
check_symbol_exists(strnstr         "string.h"      HAVE_STRNSTR)
check_symbol_exists(sysctlbyname    "sysctl.h"      HAVE_SYSCTLBYNAME)
check_symbol_exists(timegm          "time.h"        HAVE_TIMEGM)
check_symbol_exists(vsnprintf       "stdio.h"       HAVE_VSNPRINTF)

if(WIN32)
    #set(HAVE_FSEEKO 1)
    set(HAVE_GETADDRINFO 1)
    set(HAVE_GETPAGESIZE 1)
    set(HAVE_MKSTEMP 1)
    set(HAVE_POLL 1)
else()
    check_symbol_exists(fseeko          "stdio.h"       HAVE_FSEEKO)
    check_symbol_exists(getaddrinfo     "netdb.h"       HAVE_GETADDRINFO)
    check_symbol_exists(getpagesize     "unistd.h"      HAVE_GETPAGESIZE)
    check_symbol_exists(mkstemp         "unistd.h"      HAVE_MKSTEMP)
    check_symbol_exists(poll            "poll.h"        HAVE_POLL)
    check_symbol_exists(setgroups       "unistd.h"      HAVE_SETGROUPS)
    check_symbol_exists(setsid          "unistd.h"      HAVE_SETSID)
endif()

include(CheckSymbolExists)
# XXX does this correctly detect initgroups (un)availability on cygwin?
check_symbol_exists(initgroups grp.h HAVE_INITGROUPS)
if(NOT HAVE_INITGROUPS AND HAVE_UNISTD_H)
    # FreeBSD declares initgroups() in unistd.h
    check_symbol_exists(initgroups unistd.h HAVE_INITGROUPS2)
    if(HAVE_INITGROUPS2)
        set(HAVE_INITGROUPS 1)
    endif()
endif()

set(WARNCFLAGS)
set(WARNCXXFLAGS)
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    if(ENABLE_WERROR)
        set(WARNCFLAGS    /WX)
        set(WARNCXXFLAGS  /WX)
    endif()
else()
    if(ENABLE_WERROR)
        extract_valid_c_flags(WARNCFLAGS    -Werror)
        extract_valid_c_flags(WARNCXXFLAGS  -Werror)
    endif()

    # For C compiler
    extract_valid_c_flags(WARNCFLAGS
        -Wall -Wextra
        -Wformat-security
    )
    if(ENABLE_ALL_THE_WARNINGS)
        extract_valid_c_flags(WARNCFLAGS
            -Waddress
            -Wattributes
            -Wclobbered
            -Wconversion
            -Wdeclaration-after-statement
            -Wdiv-by-zero
            -Wempty-body
            -Wendif-labels
            -Wfloat-equal
            -Wformat-nonliteral
            -Winline
            -Wmissing-declarations
            -Wmissing-field-initializers
            -Wmissing-noreturn
            -Wmissing-prototypes
            -Wnested-externs
            #-Wno-format-nonliteral            # May be required to pass format string as "const char*.
            -Wpointer-arith
            -Wpragmas
            -Wredundant-decls
            -Wshadow
            -Wunreachable-code
            -Wunused-parameter
            -Wvla
            -Wwrite-strings
            -Wstrict-prototypes
            -Wundef
            -Wcast-align
            -Wextended-offsetof               # May be missing from GCC
            -Wheader-guard                    # Only work with Clang for the moment
            -Wlanguage-extension-token        # May be missing from GCC
            -Wmissing-variable-declarations   # May be missing from GCC
            #-Wpadded                          # Not used because we cannot change public structs
            -Wshorten-64-to-32                # May be missing from GCC
            -Wsign-conversion
            #-Wswitch-enum                     # Not used because this basically disallows default case
            -Wunreachable-code-break          # May be missing from GCC
            -Wunused-macros
        )
    endif()

    # For C++ compiler
    extract_valid_cxx_flags(WARNCXXFLAGS
        -Wall
        -Wformat-security
    )
endif()

# autotools-compatible names
# Sphinx expects relative paths in the .rst files. Use the fact that the files
# below are all one directory level deep.
file(RELATIVE_PATH top_srcdir   "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_SOURCE_DIR}")
file(RELATIVE_PATH top_builddir "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_BINARY_DIR}")
set(abs_top_srcdir   "${CMAKE_CURRENT_SOURCE_DIR}")
set(abs_top_builddir "${CMAKE_CURRENT_BINARY_DIR}")
# libclamav.pc (pkg-config file)
set(prefix      "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix "${CMAKE_INSTALL_PREFIX}")
set(bindir      "${CMAKE_INSTALL_FULL_BINDIR}")
set(sbindir     "${CMAKE_INSTALL_FULL_SBINDIR}")
set(libdir      "${CMAKE_INSTALL_FULL_LIBDIR}")
set(includedir  "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set(VERSION     "${PACKAGE_VERSION}")

# DBDIR for systemd service.in files
set(DBDIR       "${DATABASE_DIRECTORY}")

if(ENABLE_DEBUG)
    set(CL_DEBUG 1)
endif()
if(ENABLE_EXPERIMENTAL)
    set(CL_EXPERIMENTAL 1)
endif()
if(ENABLE_STRN_INTERNAL)
    set(HAVE_STRNI 1)
endif()
if(ENABLE_FRESHCLAM_DNS_FIX)
    set(FRESHCLAM_DNS_FIX 1)
endif()
if(ENABLE_FRESHCLAM_NO_CACHE)
    set(FRESHCLAM_NO_CACHE 1)
endif()

set(SCANBUFF 131072) # scan buffer size
set(FILEBUFF 8192)   # file i/o buffer size

if(APPLE)
    set(C_DARWIN 1)
endif()

include(CheckFmapFeatures)
if(WIN32)
    set(USE_MPOOL 1)
endif()

add_definitions(-DHAVE_CONFIG_H)
configure_file(clamav-config.h.cmake.in clamav-config.h)
configure_file(target.h.cmake.in target.h)
configure_file(platform.h.in platform.h)
configure_file(clamav-version.h.in clamav-version.h)
configure_file(clamav-types.h.in clamav-types.h)

if(WIN32)
    #
    # Windows-specific config stuff
    #

    # Windows resource file
    set(CLAMAV_RES "")
    configure_file(
        win32/res/common.rc.in
        ${CMAKE_BINARY_DIR}/version.rc
        @ONLY)
else()
    #
    # POSIX-specific config stuff
    #

    # Don't confuse clamav-config.in with clamav-config.h.in or clamav-config.h.cmake.in
    configure_file(clamav-config.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-config
        @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/clamav-config"
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ             GROUP_EXECUTE
            WORLD_READ             WORLD_EXECUTE)

    # pkg-config
    configure_file(
        libclamav.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/libclamav.pc
        @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libclamav.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
endif()

#
# ClamAV Build targets!
#

# Build targets for libraries.
if(ENABLE_UNRAR)
    # Only build libclamunrar if enabled.
    # We still define the libclamunrar_iface's interface regardless,
    # so that libclamav will have unrar_iface.h in the include path.
    add_subdirectory( libclamunrar )
endif()
add_subdirectory( libclamunrar_iface )

if(NOT ENABLE_EXTERNAL_MSPACK)
    add_subdirectory(libclammspack)
else()
    find_package(MSPack)
endif()

if(WIN32)
    add_subdirectory( win32/compat )
endif()

add_subdirectory( libclamav )

if(NOT LIBCLAMAV_ONLY)
    add_subdirectory( shared )

    add_subdirectory( libfreshclam )

    if(ENABLE_APP)
        # Build targets for primary applications.
        add_subdirectory( clamconf )

        add_subdirectory( clamd )

        add_subdirectory( clamdscan )

        if(LINUX AND ENABLE_CLAMONACC)
            add_subdirectory( clamonacc )
        endif()

        if(NOT WIN32 AND ENABLE_MILTER)
            add_subdirectory( clamav-milter )
        endif()

        add_subdirectory( clamscan )

        add_subdirectory( sigtool )

        add_subdirectory( clambc )

        add_subdirectory( clamsubmit )

        add_subdirectory( freshclam )

        add_subdirectory( clamdtop )

        if(WIN32)
            add_subdirectory( win32/conf_examples )
        else()
            add_subdirectory( etc )
        endif()
    endif()
endif()

if(ENABLE_EXAMPLES)
    add_subdirectory( examples )
endif()

if(ENABLE_DOCS)
    add_subdirectory( docs )
endif()

if(ENABLE_FUZZ)
    add_subdirectory( fuzz )
endif()

#
# The Summary Info.
#
include(ColourMessage)
string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "${Y}Configuration Options Summary${e} --
${c}    Package Version:        ${e}${PACKAGE_STRING}
${c}    libclamav version:      ${e}${LIBCLAMAV_CURRENT}:${LIBCLAMAV_REVISION}:${LIBCLAMAV_AGE}
${c}    libfreshclam version:   ${e}${LIBFRESHCLAM_CURRENT}:${LIBFRESHCLAM_REVISION}:${LIBFRESHCLAM_AGE}
${c}    Install prefix:         ${e}${CMAKE_INSTALL_PREFIX}
${c}    Target system:          ${e}${CMAKE_SYSTEM}
${c}    Compiler:               ${e}
${b}        Build type:         ${e}${CMAKE_BUILD_TYPE}
${b}        C compiler:         ${e}${CMAKE_C_COMPILER}
${b}        CFLAGS:             ${e}${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
${b}        WARNCFLAGS:         ${e}${WARNCFLAGS}
${c}    Build Options:          ${e}
${b}        Build apps:         ${e}${ENABLE_APP}
${b}        Shared library:     ${e}${ENABLE_SHARED_LIB}
${b}        Static library:     ${e}${ENABLE_STATIC_LIB}
${b}        Enable UnRAR:       ${e}${ENABLE_UNRAR}
${b}        Examples:           ${e}${ENABLE_EXAMPLES}
${b}        Build man pages:    ${e}${ENABLE_DOCS}
${b}        Build doxygen HTML: ${e}${ENABLE_DOXYGEN}")
if(NOT WIN32)
message("\
${c}    Build Extras:           ${e}")
message("\
${b}        Build milter:       ${e}${ENABLE_MILTER}  (toggle with -DENABLE_MILTER=ON/OFF)")
if(LINUX)
message("\
${b}        Build clamonacc:    ${e}${ENABLE_CLAMONACC}  (toggle with -DENABLE_CLAMONACC=ON/OFF)")
endif()
endif()

if(LLVM_FOUND)
message(STATUS "${C}Engine Options${e} --
${b}        Bytecode Runtime:   ${e}
${_}            ${BYTECODE_RUNTIME}            ${e}${LLVM_INCLUDE_DIRS}
${_}                            ${e}${LLVM_LDFLAGS} ${LLVM_LIBRARIES}
${_}                            ${e}${LLVM_LIBRARY_DIRS}")
else()
message(STATUS "${C}Engine Options${e} --
${b}        Bytecode Runtime:   ${e}
${_}            ${BYTECODE_RUNTIME}            ${e}")
endif()

message(STATUS "${C}libclamav Dependencies${e} --
${b}        Compression support:${e}
${_}            bzip2           ${e}${BZIP2_INCLUDE_DIRS}
${_}                            ${e}${BZIP2_LIBRARIES}
${_}            zlib            ${e}${ZLIB_INCLUDE_DIRS}
${_}                            ${e}${ZLIB_LIBRARIES}
${b}        XML support:        ${e}
${_}            libxml2         ${e}${LIBXML2_INCLUDE_DIRS}
${_}                            ${e}${LIBXML2_LIBRARIES}
${b}        RegEx support:      ${e}
${_}            libpcre2        ${e}${PCRE2_INCLUDE_DIRS}
${_}                            ${e}${PCRE2_LIBRARIES}
${b}        Crypto support:     ${e}
${_}            openssl         ${e}${OPENSSL_INCLUDE_DIR}
${_}                            ${e}${OPENSSL_LIBRARIES}
${b}        JSON support:       ${e}
${_}            json-c          ${e}${JSONC_INCLUDE_DIRS}
${_}                            ${e}${JSONC_LIBRARIES}
${b}        Threading support:  ${e}")
if (WIN32)
message("\
${_}            pthread-win32   ${e}${PThreadW32_INCLUDE_DIRS}
${_}                            ${e}${PThreadW32_LIBRARIES}")
elseif(Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
message("\
${_}            pthread         ${e}")
else()
message("\
${o}            no              ${e}")
endif()

message(STATUS "${C}libfreshclam Extra Dependencies${e} --
${b}        HTTP support:       ${e}
${_}            curl            ${e}${CURL_INCLUDE_DIRS}
${_}                            ${e}${CURL_LIBRARIES}")

if(HAVE_LIBNCURSES)
message(STATUS "${C}Application Extra Dependencies${e} --
${b}        GUI support:        ${e}
${_}            ncurses         ${e}${CURSES_INCLUDE_DIRS}
${_}                            ${e}${CURSES_LIBRARIES}")
elseif(HAVE_LIBPDCURSES)
message(STATUS "${C}Application Extra Dependencies${e} --
${b}        GUI support:        ${e}
${_}            pdcurses        ${e}${CURSES_INCLUDE_DIRS}
${_}                            ${e}${CURSES_LIBRARIES}")
endif()

if(LINUX)
if(SYSTEMD_PROGRAM_FOUND)
message("\
${b}        systemd:            ${e}
${_}            unit directory  ${e}${SYSTEMD_UNIT_DIR}
${b}        systemd ctl support: ${e}")
if(SYSTEMD_FOUND)
message("\
${_}            libsystemd      ${e}${SYSTEMD_INCLUDE_DIRS}
${_}                            ${e}${SYSTEMD_LIBRARIES}")
else()
message("\
${_}            libsystemd      ${e}not found")
endif()
else()
message("\
${b}        systemd:            ${e}not found")
endif()
endif()

if(ENABLE_MILTER)
message("\
${b}        Milter Support:     ${e}
${_}            libmilter       ${e}${Milter_INCLUDE_DIRS}
${_}                            ${e}${Milter_LIBRARIES}")
endif()
message("")

if(NOT JSONC_USE_STATIC)
    message(STATUS "${g}Warning:${e} libjson-c is known to share symbol names with other JSON libraries which may result in crashes for applications that use libclamav. Consider providing a static json-c library that was compiled with: CFLAGS=\"-fPIC\". Default build settings for json-c 0.15+ should also work. Use the `-DENABLE_JSON_SHARED=OFF` option to prefer detection of the static library, or use -DJSONC_INCLUDE_DIR and -DJSONC_LIBRARY to specify the static JSON library.")
endif()
