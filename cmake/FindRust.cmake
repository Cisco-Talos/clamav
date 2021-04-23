# Find the Rust toolchain and add the `add_rust_library()` API to build Rust
# libraries.
#
# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# Author: Micah Snyder
# To see this in a sample project, visit: https://github.com/micahsnyder/cmake-rust-demo
#
# Code to set the Cargo arguments was lifted from:
#   https://github.com/Devolutions/CMakeRust
#
# This Module defines the following variables:
#  - <program>_FOUND      - True if the program was found
#  - <program>_EXECUTABLE - path of the program
#  - <program>_VERSION    - version number of the program
#
# ... for the following Rust toolchain programs:
#  - cargo
#  - rustc
#  - rustup
#  - rust-gdb
#  - rust-lldb
#  - rustdoc
#  - rustfmt
#  - bindgen
#  - cbindgen
#
# Note that `cbindgen` is presently 3rd-party, and is not included with the
# standard Rust installation. `bindgen` is a part of the rust toolchain, but
# might need to be installed separately.
#
# Callers can make any program mandatory by setting `<program>_REQUIRED` before
# the call to `find_package(Rust)`
#
# Eg:
#
#    if(MAINTAINER_MODE)
#        set(cbindgen_REQUIRED 1)
#        set(bindgen_REQUIRED 1)
#    endif()
#    find_package(Rust REQUIRED)
#
# This module also provides an `add_rust_library()` function which allows a
# caller to create a Rust static library target which you can link to with
# `target_link_libraries()`.
#
# Your Rust static library target will itself depend on the native static libs
# you get from `rustc --crate-type staticlib --print=native-static-libs /dev/null`
#
# Example `add_rust_library()` usage:
#
#    add_rust_library(TARGET yourlib WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
#    add_library(YourProject::yourlib ALIAS yourlib)
#
#    add_executable(yourexe)
#    target_link_libraries(yourexe YourProject::yourlib)
#

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
            ERROR_VARIABLE  ${RUST_PROGRAM}_VERSION_ERROR
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
    set(oneValueArgs TARGET WORKING_DIRECTORY)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT EXISTS ${ARGS_WORKING_DIRECTORY}}/.cargo/config.toml)
        # Vendor the dependencies and create .cargo/config.toml
        # Vendored dependencies will be used during the build.
        # This will allow us to package vendored dependencies in source tarballs
        # for online builds when we run `cpack --config CPackSourceConfig.cmake`
        message(STATUS "Running `cargo vendor` to collect dependencies for ${ARGS_TARGET}. This may take a while if the local crates.io index needs to be updated ...")
        make_directory(${ARGS_WORKING_DIRECTORY}/.cargo)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}" ${cargo_EXECUTABLE} vendor ".cargo/vendor"
            WORKING_DIRECTORY "${ARGS_WORKING_DIRECTORY}"
            OUTPUT_VARIABLE CARGO_VENDOR_OUTPUT
            ERROR_VARIABLE  CARGO_VENDOR_ERROR
            RESULT_VARIABLE CARGO_VENDOR_RESULT
        )
        if(NOT ${CARGO_VENDOR_RESULT} EQUAL 0)
            message(FATAL_ERROR "Failed!\n${CARGO_VENDOR_ERROR}")
        else()
            message("Success!")
        endif()
        write_file(${ARGS_WORKING_DIRECTORY}/.cargo/config.toml "
[source.crates-io]
replace-with = \"vendored-sources\"

[source.vendored-sources]
directory = \".cargo/vendor\"
"
        )
    endif()
endfunction()

function(add_rust_library)
    set(options)
    set(oneValueArgs TARGET WORKING_DIRECTORY)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(WIN32)
        set(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${LIB_TARGET}/${LIB_BUILD_TYPE}/${ARGS_TARGET}.lib")
    else()
        set(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${LIB_TARGET}/${LIB_BUILD_TYPE}/lib${ARGS_TARGET}.a")
    endif()

    file(GLOB_RECURSE LIB_SOURCES "${ARGS_WORKING_DIRECTORY}/*.rs")

    set(MY_CARGO_ARGS ${CARGO_ARGS})
    list(APPEND MY_CARGO_ARGS "--target-dir" ${CMAKE_CURRENT_BINARY_DIR})
    list(JOIN MY_CARGO_ARGS " " MY_CARGO_ARGS_STRING)

    # Build the library and generate the c-binding, if `cbindgen` is required.
    if(${cbindgen_REQUIRED})
        add_custom_command(
            OUTPUT "${OUTPUT}"
            COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}" ${cargo_EXECUTABLE} ARGS ${MY_CARGO_ARGS}
            COMMAND ${cbindgen_EXECUTABLE} --lang c -o ${ARGS_WORKING_DIRECTORY}/${ARGS_TARGET}.h ${ARGS_WORKING_DIRECTORY}
            WORKING_DIRECTORY "${ARGS_WORKING_DIRECTORY}"
            DEPENDS ${LIB_SOURCES}
            COMMENT "Building ${ARGS_TARGET} in ${ARGS_WORKING_DIRECTORY} with:\n\t ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}")
    else()
        add_custom_command(
            OUTPUT "${OUTPUT}"
            COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}" ${cargo_EXECUTABLE} ARGS ${MY_CARGO_ARGS}
            WORKING_DIRECTORY "${ARGS_WORKING_DIRECTORY}"
            DEPENDS ${LIB_SOURCES}
            COMMENT "Building ${ARGS_TARGET} in ${ARGS_WORKING_DIRECTORY} with:\n\t ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}")
    endif()

    # Create a target from the build output
    add_custom_target(${ARGS_TARGET}_target
        DEPENDS ${OUTPUT})

    # Create a static imported library target from library target
    add_library(${ARGS_TARGET} STATIC IMPORTED GLOBAL)
    add_dependencies(${ARGS_TARGET} ${ARGS_TARGET}_target)
    target_link_libraries(${ARGS_TARGET} INTERFACE ${RUST_NATIVE_STATIC_LIBS})

    # Specify where the library is and where to find the headers
    set_target_properties(${ARGS_TARGET}
        PROPERTIES
            IMPORTED_LOCATION "${OUTPUT}"
            INTERFACE_INCLUDE_DIRECTORIES "${ARGS_WORKING_DIRECTORY}"
    )

    # Vendor the dependencies, if desired
    if(VENDOR_DEPENDENCIES)
        cargo_vendor(TARGET "${ARGS_TARGET}" WORKING_DIRECTORY "${ARGS_WORKING_DIRECTORY}")
    endif()
endfunction()

function(add_rust_test)
    set(options)
    set(oneValueArgs NAME WORKING_DIRECTORY)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_test(
        NAME test-${ARGS_NAME}
        COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}" ${cargo_EXECUTABLE} test -vv --color always
        WORKING_DIRECTORY ${ARGS_WORKING_DIRECTORY}
    )
endfunction()

#
# Cargo is the primary tool for using the Rust Toolchain to to build static
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
find_rust_program(cbindgen)

# Determine the native libs required to link w/ rust static libs
# message(STATUS "Detecting native static libs for rust: ${rustc_EXECUTABLE} --crate-type staticlib --print=native-static-libs /dev/null")
execute_process(
    COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}" ${rustc_EXECUTABLE} --crate-type staticlib --print=native-static-libs /dev/null
    OUTPUT_VARIABLE RUST_NATIVE_STATIC_LIBS_OUTPUT
    ERROR_VARIABLE  RUST_NATIVE_STATIC_LIBS_ERROR
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
    if(LINE)
        message(STATUS "Rust's native static libs: ${LINE}")
        set(RUST_NATIVE_STATIC_LIBS "${LINE}")
        break()
    endif()
endforeach()

if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(LIB_TARGET "x86_64-pc-windows-msvc")
    else()
        set(LIB_TARGET "i686-pc-windows-msvc")
    endif()
elseif(ANDROID)
    if(ANDROID_SYSROOT_ABI STREQUAL "x86")
        set(LIB_TARGET "i686-linux-android")
    elseif(ANDROID_SYSROOT_ABI STREQUAL "x86_64")
        set(LIB_TARGET "x86_64-linux-android")
    elseif(ANDROID_SYSROOT_ABI STREQUAL "arm")
        set(LIB_TARGET "arm-linux-androideabi")
    elseif(ANDROID_SYSROOT_ABI STREQUAL "arm64")
        set(LIB_TARGET "aarch64-linux-android")
    endif()
elseif(IOS)
    set(LIB_TARGET "universal")
elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(LIB_TARGET "x86_64-apple-darwin")
else()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(LIB_TARGET "x86_64-unknown-linux-gnu")
    else()
        set(LIB_TARGET "i686-unknown-linux-gnu")
    endif()
endif()

if(IOS)
    set(CARGO_ARGS "lipo")
else()
    set(CARGO_ARGS "build")
    list(APPEND CARGO_ARGS "--target" ${LIB_TARGET})
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(LIB_BUILD_TYPE "debug")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(LIB_BUILD_TYPE "release")
    list(APPEND CARGO_ARGS "--release")
else()
    set(LIB_BUILD_TYPE "debug")
endif()

find_package_handle_standard_args( Rust
    REQUIRED_VARS cargo_EXECUTABLE
    VERSION_VAR cargo_VERSION
)
