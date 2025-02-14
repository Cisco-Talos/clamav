#
# libclamav features written in Rust
#
# Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#

# libclamav rust static library
add_rust_library(TARGET clamav_rust
    SOURCE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
    INCLUDE_DIRECTORIES "$<TARGET_PROPERTY:ClamAV::libclamav,INCLUDE_DIRECTORIES>"
    # Tests cannot be pre-compiled here, because there are circular dependencies
    # between libclamav_rust and libclamav to include calls like `cli_getdsig()`
    # as well as the logging functions.
    PRECOMPILE_TESTS FALSE
)
if (WIN32)
    target_link_libraries(clamav_rust PUBLIC INTERFACE Userenv)
endif()

if(WIN32)
    install(FILES $<TARGET_FILE:clamav_rust> DESTINATION . COMPONENT libraries)
else()
    install(FILES $<TARGET_FILE:clamav_rust> DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries)
endif()

add_library(ClamAV::libclamav_rust ALIAS clamav_rust)
