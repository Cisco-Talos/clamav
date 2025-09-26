#
# libclamav features written in Rust
#
# Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#

# The Rust openssl-sys crate needs to know how to find the OpenSSL headers and libraries.
get_filename_component(OPENSSL_DIR "${OPENSSL_INCLUDE_DIR}" DIRECTORY)

set(OPENSSL_LIBS "")

# Get the libcrypto library.
# Remove path and extension.
get_filename_component(LIBNAME "${OPENSSL_CRYPTO_LIBRARY}" NAME_WLE)
# Remove "lib" prefix, if present.
string(REGEX REPLACE "^lib" "" LIBNAME "${LIBNAME}")
# Add libcrypto.
set(OPENSSL_LIBS "${LIBNAME}")

# Get the libssl library.
# Remove path and extension.
get_filename_component(LIBNAME "${OPENSSL_SSL_LIBRARY}" NAME_WLE)
# Remove "lib" prefix, if present.
string(REGEX REPLACE "^lib" "" LIBNAME "${LIBNAME}")
# Add libssl.
set(OPENSSL_LIBS "${OPENSSL_LIBS}:${LIBNAME}")

# Get the libcrypto library.
# Depending on the FindOpenSSL script, this can be either a path or a list of
# configurations and paths, e.g., "optimized;C:/vcpkg/installed/x64-windows/lib/libcrypto.lib;debug;C:/vcpkg/installed/x64-windows/debug/lib/libcrypto.lib"
foreach(OPENSSL_CRYPTO_LIB IN LISTS OPENSSL_CRYPTO_LIBRARY)
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        # Get the libcrypto library.
        # Remove path and extension.
        get_filename_component(LIBNAME "${OPENSSL_CRYPTO_LIBRARY}" NAME_WLE)
        # Remove "lib" prefix, if present.
        string(REGEX REPLACE "^lib" "" LIBNAME "${LIBNAME}")
        # Add libcrypto.
        set(OPENSSL_LIBS "${LIBNAME}")

        get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIB}" DIRECTORY)
        set(OPENSSL_CRYPTO_LIB_FOUND TRUE)
        break()
    endif()
endforeach()

foreach(OPENSSL_SSL_LIB IN LISTS OPENSSL_SSL_LIBRARY)
    if(EXISTS "${OPENSSL_SSL_LIB}")
        # Remove path and extension.
        get_filename_component(LIBNAME "${OPENSSL_SSL_LIB}" NAME_WLE)
        # Remove "lib" prefix, if present.
        string(REGEX REPLACE "^lib" "" LIBNAME "${LIBNAME}")
        # Add libssl.
        set(OPENSSL_LIBS "${OPENSSL_LIBS}:${LIBNAME}")
        set(OPENSSL_SSL_LIB_FOUND TRUE)
        break()
    endif()
endforeach()

if(NOT OPENSSL_CRYPTO_LIB_FOUND OR NOT OPENSSL_SSL_LIB_FOUND)
    message(FATAL_ERROR "Could not deduce OpenSSL library directory from OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY} and OPENSSL_SSL_LIBRARY: ${OPENSSL_SSL_LIBRARY}.")
endif()

set(ENVIRONMENT "")
list(APPEND ENVIRONMENT "OPENSSL_DIR=${OPENSSL_DIR}")
list(APPEND ENVIRONMENT "OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")
if(NOT MSVC)
    # Setting OPENSSL_LIBS caused failures in testing for Windows.
    # It's possible they require a different format or the .lib or .dll extensions.
    # For now, we'll only set this for non-Windows builds.
    list(APPEND ENVIRONMENT "OPENSSL_LIBS=${OPENSSL_LIBS}")
endif()
list(APPEND ENVIRONMENT "OPENSSL_LIB_DIR=${OPENSSL_LIB_DIR}")

# libclamav rust static library
add_rust_library(TARGET clamav_rust
    SOURCE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
    ENVIRONMENT "${ENVIRONMENT}"
    INCLUDE_DIRECTORIES "$<TARGET_PROPERTY:ClamAV::libclamav,INCLUDE_DIRECTORIES>"
    # Tests cannot be pre-compiled here, because there are circular dependencies
    # between libclamav_rust and libclamav to include calls like `cli_getdsig()`
    # as well as the logging functions.
    PRECOMPILE_TESTS FALSE
)
if (WIN32)
    target_link_libraries(clamav_rust PUBLIC INTERFACE Userenv)
endif()

install(FILES $<TARGET_FILE:clamav_rust> TYPE LIB COMPONENT libraries)

add_library(ClamAV::libclamav_rust ALIAS clamav_rust)
