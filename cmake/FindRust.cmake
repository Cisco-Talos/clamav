# Find the Rust toolchain and add the `add_rust_library()` API to build Rust
# libraries.
#
# Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# Author: Micah Snyder
# To see this in a sample project, visit: https://github.com/micahsnyder/cmake-rust-demo
#
# Code to set the Cargo arguments was lifted from:
# https://github.com/Devolutions/CMakeRust
#
# This Module defines the following variables:
# - <program>_FOUND      - True if the program was found
# - <program>_EXECUTABLE - path of the program
# - <program>_VERSION    - version number of the program
#
# ... for the following Rust toolchain programs:
# - cargo
# - rustc
# - rustup
# - rust-gdb
# - rust-lldb
# - rustdoc
# - rustfmt
# - bindgen
#
# Callers can make any program mandatory by setting `<program>_REQUIRED` before
# the call to `find_package(Rust)`
#
# Eg:
# find_package(Rust REQUIRED)
#
# This module provides the following functions:
# =============================================
#
# `add_rust_library()`
# --------------------
#
# This allows a caller to create a Rust static library
# target which you can link to with `target_link_libraries()`.
#
# Your Rust static library target will itself depend on the native static libs
# you get from `rustc --crate-type staticlib --print=native-static-libs /dev/null`
#
# The CARGO_CMD environment variable will be set to "BUILD" so you can tell
# it's not building the unit tests inside your (optional) `build.rs` file.
#
# Example `add_rust_library()` usage:
#
#   ```cmake
#   add_rust_library(TARGET yourlib
#       SOURCE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
#       BINARY_DIRECTORY "${CMAKE_BINARY_DIR}")
#   add_library(YourProject::yourlib ALIAS yourlib)
#
#   add_executable(yourexe)
#   target_link_libraries(yourexe YourProject::yourlib)
#   ```
#
# If your library has unit tests AND your library does NOT depend on your C
# librar(ies), you can use `add_rust_library()` to build your library and unit
# tests at the same time. Just pass `PRECOMPILE_TESTS TRUE` to add_rust_library.
# This should make it so when you run the tests, they don't have to compile
# during the test run.
#
# If your library does have C dependencies, you can still precompile the tests
# by passing `PRECOMPILE_TESTS TRUE`, with `add_rust_test()` instead.
# It will be slower because it will have to compile the C stuff first,
# then compile the Rust stuff from scratch. See below.
#
# `add_rust_test()`
# -----------------
#
# This allows a caller to run `cargo test` for a specific Rust target as a CTest
# test.
#
# The CARGO_CMD environment variable will be set to "TEST" so you can tell
# it's not building the unit tests inside your (optional) `build.rs` file.
#
# Example `add_rust_test()` usage:
#
#   ```cmake
#   add_rust_test(NAME yourlib
#       SOURCE_DIRECTORY "${CMAKE_SOURCE_DIR}/path/to/yourlib"
#       BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
#   )
#   set_property(TEST yourlib PROPERTY ENVIRONMENT ${ENVIRONMENT})
#   ```
#
# Experimental: Precompile the Tests Executable
# ~~~~~~~~~~~~
# This feature will cause install failures if you `sudo make install` because
# it will recompile the test executable with sudo and Cargo is likely to fail to
# run with sudo.
# This cannot be fixed unless we can predetermine the test exeecutable OUTPUT
# filepath. See: https://github.com/rust-lang/cargo/issues/1924
#
# If your library has unit tests AND your library DOES depend on your C
# libraries, you can precompile the unit tests application with some extra
# parameters to `add_rust_test()`:
# - `PRECOMPILE_TESTS TRUE`
# - `PRECOMPILE_DEPENDS <the CMake target name for your C library dependency>`
# - `PRECOMPILE_ENVIRONMENT <a linked list of environment vars to build the Rust lib>`
#
# The `PRECOMPILE_DEPENDS` option is required so CMake will build the C library first.
# The `PRECOMPILE_ENVIRONMENT` option is required for use in your `build.rs` file so you
# can tell rustc how to link to your C library.
#
# For example:
#
#   ```cmake
#   add_rust_test(NAME yourlib
#       SOURCE_DIRECTORY "${CMAKE_SOURCE_DIR}/yourlib"
#       BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
#       PRECOMPILE_TESTS TRUE
#       PRECOMPILE_DEPENDS ClamAV::libclamav
#       PRECOMPILE_ENVIRONMENT "${ENVIRONMENT}"
#   )
#   set_property(TEST yourlib PROPERTY ENVIRONMENT ${ENVIRONMENT})
#   ```
#
# `add_rust_executable()`
# -----------------------
#
# This allows a caller to create a Rust executable target.
#
# Example `add_rust_executable()` usage:
#
#   ```cmake
#   add_rust_executable(TARGET yourexe
#       SOURCE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
#       BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
#   )
#   add_executable(YourProject::yourexe ALIAS yourexe)
#   ```

if(NOT DEFINED CARGO_HOME)
    if(WIN32)
        set(CARGO_HOME "$ENV{USERPROFILE}/.cargo")
    else()
        set(CARGO_HOME "$ENV{HOME}/.cargo")
    endif()
endif()

include(FindPackageHandleStandardArgs)

function(find_rust_program RUST_PROGRAM)
    find_program(${RUST_PROGRAM}_EXECUTABLE ${RUST_PROGRAM}
        HINTS "${CARGO_HOME}"
        PATH_SUFFIXES "bin"
    )

    if(${RUST_PROGRAM}_EXECUTABLE)
        execute_process(COMMAND "${${RUST_PROGRAM}_EXECUTABLE}" --version
            OUTPUT_VARIABLE ${RUST_PROGRAM}_VERSION_OUTPUT
            ERROR_VARIABLE ${RUST_PROGRAM}_VERSION_ERROR
            RESULT_VARIABLE ${RUST_PROGRAM}_VERSION_RESULT
        )

        if(NOT ${${RUST_PROGRAM}_VERSION_RESULT} EQUAL 0)
            message(STATUS "Rust tool `${RUST_PROGRAM}` not found: Failed to determine version.")
            unset(${RUST_PROGRAM}_EXECUTABLE)
        else()
            string(REGEX
                MATCH "[0-9]+\\.[0-9]+(\\.[0-9]+)?(-nightly)?"
                ${RUST_PROGRAM}_VERSION "${${RUST_PROGRAM}_VERSION_OUTPUT}"
            )
            set(${RUST_PROGRAM}_VERSION "${${RUST_PROGRAM}_VERSION}" PARENT_SCOPE)
            message(STATUS "Rust tool `${RUST_PROGRAM}` found: ${${RUST_PROGRAM}_EXECUTABLE}, ${${RUST_PROGRAM}_VERSION}")
        endif()

        mark_as_advanced(${RUST_PROGRAM}_EXECUTABLE ${RUST_PROGRAM}_VERSION)
    else()
        if(${${RUST_PROGRAM}_REQUIRED})
            message(FATAL_ERROR "Rust tool `${RUST_PROGRAM}` not found.")
        else()
            message(STATUS "Rust tool `${RUST_PROGRAM}` not found.")
        endif()
    endif()
endfunction()

function(cargo_vendor)
    set(options)
    set(oneValueArgs TARGET SOURCE_DIRECTORY BINARY_DIRECTORY)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # Vendor the dependencies and create .cargo/config.toml
    # Vendored dependencies will be used during the build.
    # This will allow us to package vendored dependencies in source tarballs
    # for online builds when we run `cpack --config CPackSourceConfig.cmake`
    message(STATUS "Running `cargo vendor` to collect dependencies for ${ARGS_TARGET}. This may take a while if the local crates.io index needs to be updated ...")
    make_directory(${CMAKE_SOURCE_DIR}/.cargo)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}" ${cargo_EXECUTABLE} vendor "${CMAKE_SOURCE_DIR}/.cargo/vendor"
        WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
        OUTPUT_VARIABLE CARGO_VENDOR_OUTPUT
        ERROR_VARIABLE CARGO_VENDOR_ERROR
        RESULT_VARIABLE CARGO_VENDOR_RESULT
    )

    if(NOT ${CARGO_VENDOR_RESULT} EQUAL 0)
        message(FATAL_ERROR "Failed!\n${CARGO_VENDOR_ERROR}")
    else()
        message("Success!")
    endif()

    if(NOT EXISTS ${CMAKE_SOURCE_DIR}/.cargo/config.toml)
        write_file(${CMAKE_SOURCE_DIR}/.cargo/config.toml "
[source.crates-io]
replace-with = \"vendored-sources\"

[source.\"git+https://github.com/Cisco-Talos/onenote.rs.git?branch=CLAM-2329-new-from-slice\"]
git = \"https://github.com/Cisco-Talos/onenote.rs.git\"
branch = \"CLAM-2329-new-from-slice\"
replace-with = \"vendored-sources\"

[source.\"git+https://github.com/Cisco-Talos/clamav-signature-util.git?tag=1.2.4\"]
git = \"https://github.com/Cisco-Talos/clamav-signature-util.git\"
tag = \"1.2.4\"
replace-with = \"vendored-sources\"

[source.vendored-sources]
directory = \".cargo/vendor\"
"
        )
    endif()
endfunction()

function(add_rust_executable)
    set(options)
    set(oneValueArgs TARGET SOURCE_DIRECTORY BINARY_DIRECTORY)
    set(multiValueArgs ENVIRONMENT)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(WIN32)
        set(OUTPUT "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}/${CARGO_BUILD_TYPE}/${ARGS_TARGET}.exe")
    else()
        set(OUTPUT "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}/${CARGO_BUILD_TYPE}/${ARGS_TARGET}")
    endif()

    file(GLOB_RECURSE EXE_SOURCES "${ARGS_SOURCE_DIRECTORY}/*.rs")

    set(MY_CARGO_ARGS ${CARGO_ARGS})
    list(APPEND MY_CARGO_ARGS "--target-dir" ${ARGS_BINARY_DIRECTORY})
    list(JOIN MY_CARGO_ARGS " " MY_CARGO_ARGS_STRING)

    list(APPEND ARGS_ENVIRONMENT "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}" "CARGO_INCLUDE_DIRECTORIES=\"${ARGS_INCLUDE_DIRECTORIES}\"")

    # Build the executable.
    add_custom_command(
        OUTPUT "${OUTPUT}"
        COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS}
        WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
        DEPENDS ${EXE_SOURCES}
        COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY} with:\n\t ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}\n  Environment:  ${ARGS_ENVIRONMENT}")

    # Create a target from the build output
    add_custom_target(${ARGS_TARGET}_target
        DEPENDS ${OUTPUT})

    # Create an executable target from custom target
    add_custom_target(${ARGS_TARGET} ALL DEPENDS ${ARGS_TARGET}_target)

    # Specify where the executable is
    set_target_properties(${ARGS_TARGET}
        PROPERTIES
        IMPORTED_LOCATION "${OUTPUT}"
    )

    # Vendor the dependencies, if desired
    if(VENDOR_DEPENDENCIES)
        cargo_vendor(TARGET "${ARGS_TARGET}"
            SOURCE_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
            BINARY_DIRECTORY "${ARGS_BINARY_DIRECTORY}"
        )
    endif()
endfunction()

function(add_rust_library)
    set(options)
    set(oneValueArgs TARGET SOURCE_DIRECTORY BINARY_DIRECTORY PRECOMPILE_TESTS INCLUDE_DIRECTORIES)
    set(multiValueArgs ENVIRONMENT)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(WIN32)
        set(OUTPUT "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}/${CARGO_BUILD_TYPE}/${ARGS_TARGET}.lib")
    else()
        set(OUTPUT "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}/${CARGO_BUILD_TYPE}/lib${ARGS_TARGET}.a")
    endif()

    file(GLOB_RECURSE LIB_SOURCES "${ARGS_SOURCE_DIRECTORY}/*.rs")

    set(MY_CARGO_ARGS ${CARGO_ARGS})
    if(ARGS_PRECOMPILE_TESTS)
        list(APPEND MY_CARGO_ARGS "--tests")
    endif()
    list(APPEND MY_CARGO_ARGS "--target-dir" ${ARGS_BINARY_DIRECTORY})
    list(JOIN MY_CARGO_ARGS " " MY_CARGO_ARGS_STRING)

    list(APPEND ARGS_ENVIRONMENT "CARGO_CMD=build" "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}" "MAINTAINER_MODE=${MAINTAINER_MODE}" "CARGO_INCLUDE_DIRECTORIES=\"${ARGS_INCLUDE_DIRECTORIES}\"" "RUSTFLAGS=${RUSTFLAGS}")

    # Build the library and generate the c-binding
    if("${CMAKE_OSX_ARCHITECTURES}" MATCHES "^(arm64;x86_64|x86_64;arm64)$")
        add_custom_command(
            OUTPUT "${OUTPUT}"
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --target=x86_64-apple-darwin
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --target=aarch64-apple-darwin
            COMMAND ${CMAKE_COMMAND} -E make_directory "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}/${CARGO_BUILD_TYPE}"
            COMMAND lipo -create ${ARGS_BINARY_DIRECTORY}/x86_64-apple-darwin/${CARGO_BUILD_TYPE}/lib${ARGS_TARGET}.a ${ARGS_BINARY_DIRECTORY}/aarch64-apple-darwin/${CARGO_BUILD_TYPE}/lib${ARGS_TARGET}.a -output "${OUTPUT}"
            WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
            DEPENDS ${LIB_SOURCES}
            COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY} with:  ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}\n  Environment:  ${ARGS_ENVIRONMENT}")
    elseif("${CMAKE_OSX_ARCHITECTURES}" MATCHES "^(arm64)$")
        add_custom_command(
            OUTPUT "${OUTPUT}"
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --target=aarch64-apple-darwin
            WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
            DEPENDS ${LIB_SOURCES}
            COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY} with:  ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}\n  Environment:  ${ARGS_ENVIRONMENT}")
            elseif("${CMAKE_OSX_ARCHITECTURES}" MATCHES "^(x86_64)$")
        add_custom_command(
            OUTPUT "${OUTPUT}"
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --target=x86_64-apple-darwin
            COMMAND ${CMAKE_COMMAND} -E make_directory "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}/${CARGO_BUILD_TYPE}"
            WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
            DEPENDS ${LIB_SOURCES}
            COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY} with:  ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}\n  Environment:  ${ARGS_ENVIRONMENT}")
    else()
        add_custom_command(
            OUTPUT "${OUTPUT}"
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS}
            WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
            DEPENDS ${LIB_SOURCES}
            COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY} with:  ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}\n  Environment:  ${ARGS_ENVIRONMENT}")
    endif()

    # Create a target from the build output
    add_custom_target(${ARGS_TARGET}_target
        DEPENDS ${OUTPUT})

    # Create a static imported library target from custom target
    add_library(${ARGS_TARGET} STATIC IMPORTED GLOBAL)
    add_dependencies(${ARGS_TARGET} ${ARGS_TARGET}_target)
    target_link_libraries(${ARGS_TARGET} INTERFACE ${RUST_NATIVE_STATIC_LIBS})

    # Specify where the library is and where to find the headers
    set_target_properties(${ARGS_TARGET}
        PROPERTIES
        IMPORTED_LOCATION "${OUTPUT}"
        INTERFACE_INCLUDE_DIRECTORIES "${ARGS_SOURCE_DIRECTORY};${ARGS_BINARY_DIRECTORY}"
    )

    # Vendor the dependencies, if desired
    if(VENDOR_DEPENDENCIES)
        cargo_vendor(TARGET "${ARGS_TARGET}"
            SOURCE_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
            BINARY_DIRECTORY "${ARGS_BINARY_DIRECTORY}")
    endif()
endfunction()

function(add_rust_test)
    set(options)
    set(oneValueArgs NAME SOURCE_DIRECTORY BINARY_DIRECTORY PRECOMPILE_TESTS PRECOMPILE_DEPENDS)
    set(multiValueArgs PRECOMPILE_ENVIRONMENT)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    set(MY_CARGO_ARGS "test")

    if(NOT "${CMAKE_OSX_ARCHITECTURES}" MATCHES "^(arm64;x86_64|x86_64;arm64)$") # Don't specify the target for universal, we'll do that manually for each build.
        list(APPEND MY_CARGO_ARGS "--target" ${RUST_COMPILER_TARGET})
    endif()

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
        list(APPEND MY_CARGO_ARGS "--release")
    endif()

    list(APPEND MY_CARGO_ARGS "--target-dir" ${ARGS_BINARY_DIRECTORY})
    list(JOIN MY_CARGO_ARGS " " MY_CARGO_ARGS_STRING)

    if(ARGS_PRECOMPILE_TESTS)
        list(APPEND ARGS_PRECOMPILE_ENVIRONMENT "CARGO_CMD=test" "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}")
        add_custom_target(${ARGS_NAME}_tests ALL
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_PRECOMPILE_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --color always --no-run
            DEPENDS ${ARGS_PRECOMPILE_DEPENDS}
            WORKING_DIRECTORY ${ARGS_SOURCE_DIRECTORY}
        )
    endif()

    message(STATUS "Environment: ${ARGS_ENVIRONMENT}")

    add_test(
        NAME ${ARGS_NAME}
        COMMAND ${CMAKE_COMMAND} -E env "CARGO_CMD=test" "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}" "RUSTFLAGS=${RUSTFLAGS}" ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --color always
        WORKING_DIRECTORY ${ARGS_SOURCE_DIRECTORY}
    )
endfunction()

#
# Cargo is the primary tool for using the Rust Toolchain to build static
# libs that can include other crate dependencies.
#
find_rust_program(cargo)

# These other programs may also be useful...
find_rust_program(rustc)
find_rust_program(rustup)
find_rust_program(rust-gdb)
find_rust_program(rust-lldb)
find_rust_program(rustdoc)
find_rust_program(rustfmt)
find_rust_program(bindgen)

if(RUSTC_MINIMUM_REQUIRED AND rustc_VERSION VERSION_LESS RUSTC_MINIMUM_REQUIRED)
    message(FATAL_ERROR "Your Rust toolchain is to old to build this project:
    ${rustc_VERSION} < ${RUSTC_MINIMUM_REQUIRED}")
endif()

if(WIN32)
    file(TOUCH ${CMAKE_BINARY_DIR}/empty-file)
    set(EMPTY_FILE "${CMAKE_BINARY_DIR}/empty-file")
else()
    set(EMPTY_FILE "/dev/null")
endif()

# Determine the native libs required to link w/ rust static libs
# message(STATUS "Detecting native static libs for rust: ${rustc_EXECUTABLE} --crate-type staticlib --print=native-static-libs ${EMPTY_FILE}")
execute_process(
    COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_BINARY_DIR}" ${rustc_EXECUTABLE} --crate-type staticlib --print=native-static-libs ${EMPTY_FILE}
    OUTPUT_VARIABLE RUST_NATIVE_STATIC_LIBS_OUTPUT
    ERROR_VARIABLE RUST_NATIVE_STATIC_LIBS_ERROR
    RESULT_VARIABLE RUST_NATIVE_STATIC_LIBS_RESULT
)
string(REGEX REPLACE "\r?\n" ";" LINE_LIST "${RUST_NATIVE_STATIC_LIBS_ERROR}")

foreach(LINE ${LINE_LIST})
    # do the match on each line
    string(REGEX MATCH "native-static-libs: .*" LINE "${LINE}")

    if(NOT LINE)
        continue()
    endif()

    string(REPLACE "native-static-libs: " "" LINE "${LINE}")
    string(REGEX REPLACE "  " "" LINE "${LINE}")
    string(REGEX REPLACE " " ";" LINE "${LINE}")
    # remove linker flags
    list(FILTER LINE EXCLUDE REGEX "/.*")

    if(LINE)
        message(STATUS "Rust's native static libs: ${LINE}")
        set(RUST_NATIVE_STATIC_LIBS "${LINE}")
        break()
    endif()
endforeach()

if(NOT RUST_COMPILER_TARGET)
    # Automatically determine the Rust Target Triple.
    # Note: Users may override automatic target detection by specifying their own. Most likely needed for cross-compiling.
    # For reference determining target platform: https://doc.rust-lang.org/nightly/rustc/platform-support.html
    if(WIN32)
        # For windows x86/x64, it's easy enough to guess the target.
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(RUST_COMPILER_TARGET "x86_64-pc-windows-msvc")
        else()
            set(RUST_COMPILER_TARGET "i686-pc-windows-msvc")
        endif()
    elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin AND "${CMAKE_OSX_ARCHITECTURES}" MATCHES "^(arm64;x86_64|x86_64;arm64)$")
        # Special case for Darwin because we may want to build universal binaries.
        set(RUST_COMPILER_TARGET "universal-apple-darwin")
    else()
        # Determine default LLVM target triple.
        execute_process(COMMAND ${rustc_EXECUTABLE} -vV
            OUTPUT_VARIABLE RUSTC_VV_OUT ERROR_QUIET)
        string(REGEX REPLACE "^.*host: ([a-zA-Z0-9_\\-]+).*" "\\1" DEFAULT_RUST_COMPILER_TARGET1 "${RUSTC_VV_OUT}")
        string(STRIP ${DEFAULT_RUST_COMPILER_TARGET1} DEFAULT_RUST_COMPILER_TARGET)

        set(RUST_COMPILER_TARGET "${DEFAULT_RUST_COMPILER_TARGET}")
    endif()
endif()

set(CARGO_ARGS "build")

if(EXISTS "${CMAKE_SOURCE_DIR}/.cargo/vendor")
    list(APPEND CARGO_ARGS "--offline")
endif()

if(NOT "${RUST_COMPILER_TARGET}" MATCHES "^universal-apple-darwin$")
    # Don't specify the target for macOS universal builds, we'll do that manually for each build.
    list(APPEND CARGO_ARGS "--target" ${RUST_COMPILER_TARGET})
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CARGO_BUILD_TYPE "debug")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release" OR ${CMAKE_BUILD_TYPE} STREQUAL "MinSizeRel")
    set(CARGO_BUILD_TYPE "release")
    list(APPEND CARGO_ARGS "--release")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "RelWithDebInfo")
    set(CARGO_BUILD_TYPE "release")
    list(APPEND CARGO_ARGS "--release")
    string(APPEND RUSTFLAGS " -g")
else()
    set(CARGO_BUILD_TYPE "debug")
endif()
string(STRIP "${RUSTFLAGS} $ENV{RUSTFLAGS}" RUSTFLAGS)

find_package_handle_standard_args(Rust
    REQUIRED_VARS cargo_EXECUTABLE
    VERSION_VAR cargo_VERSION
)
