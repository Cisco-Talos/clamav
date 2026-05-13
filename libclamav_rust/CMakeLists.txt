#
# libclamav features written in Rust
#
# Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#

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

if(ENABLE_PDFIUM AND PDFIUM_LIBRARY)
    get_filename_component(_PDFIUM_LIBRARY_DIR "${PDFIUM_LIBRARY}" DIRECTORY)

    if(PDFIUM_LIBRARY MATCHES "\\.(dll|dylib|so)(\\.[0-9]+)*$")
        list(APPEND ENVIRONMENT "PDFIUM_DYNAMIC_LIB_PATH=${_PDFIUM_LIBRARY_DIR}")
    else()
        list(APPEND ENVIRONMENT "PDFIUM_STATIC_LIB_PATH=${_PDFIUM_LIBRARY_DIR}")
    endif()

    foreach(_PDFIUM_EXTRA_LIBRARY IN LISTS PDFIUM_EXTRA_LIBRARIES)
        if(_PDFIUM_EXTRA_LIBRARY MATCHES "^-framework[ ]+(.+)$")
            string(APPEND RUSTFLAGS " -C link-arg=-framework -C link-arg=${CMAKE_MATCH_1}")
        elseif(IS_ABSOLUTE "${_PDFIUM_EXTRA_LIBRARY}" OR EXISTS "${_PDFIUM_EXTRA_LIBRARY}" OR _PDFIUM_EXTRA_LIBRARY MATCHES "\\.(a|lib|dylib|so)(\\.[0-9]+)*$")
            string(APPEND RUSTFLAGS " -C link-arg=${_PDFIUM_EXTRA_LIBRARY}")
        elseif(_PDFIUM_EXTRA_LIBRARY MATCHES "^-")
            string(APPEND RUSTFLAGS " -C link-arg=${_PDFIUM_EXTRA_LIBRARY}")
        else()
            string(APPEND RUSTFLAGS " -l ${_PDFIUM_EXTRA_LIBRARY}")
        endif()
    endforeach()
endif()

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
