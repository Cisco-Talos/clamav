# Find the Rust toolchain and add the `add_rust_library()` API to build Rust
# libraries.
#
# Copyright (C) 2021-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
# The buildable custom target uses TARGET as its name, and the Cargo artifact is
# also exposed as an imported executable target named <TARGET>_executable so
# CMake consumers can use $<TARGET_FILE:<TARGET>_executable>.
# OUTPUT_VARIABLE may be supplied to return the artifact path to the caller.
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
    set(oneValueArgs TARGET SOURCE_DIRECTORY BINARY_DIRECTORY OUTPUT_VARIABLE)
    set(multiValueArgs ENVIRONMENT DEPENDS)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARGS_TARGET OR NOT ARGS_SOURCE_DIRECTORY OR NOT ARGS_BINARY_DIRECTORY)
        message(FATAL_ERROR "add_rust_executable requires TARGET, SOURCE_DIRECTORY, and BINARY_DIRECTORY")
    endif()

    # CMake may request a single macOS architecture different from the host
    # Rust target. Build the Cargo executable for that requested architecture
    # so the output path and binary architecture agree.
    if("${RUST_COMPILER_TARGET}" MATCHES "^universal-apple-darwin$")
        set(RUST_EXECUTABLE_TARGET "${RUST_COMPILER_TARGET}")
    elseif(APPLE AND "${CMAKE_OSX_ARCHITECTURES}" STREQUAL "arm64")
        set(RUST_EXECUTABLE_TARGET "aarch64-apple-darwin")
    elseif(APPLE AND "${CMAKE_OSX_ARCHITECTURES}" STREQUAL "x86_64")
        set(RUST_EXECUTABLE_TARGET "x86_64-apple-darwin")
    else()
        set(RUST_EXECUTABLE_TARGET "${RUST_COMPILER_TARGET}")
    endif()

    if(WIN32)
        set(RUST_EXECUTABLE_SUFFIX ".exe")
    else()
        set(RUST_EXECUTABLE_SUFFIX "")
    endif()
    if("${RUST_EXECUTABLE_TARGET}" MATCHES "^universal-apple-darwin$")
        set(RUST_EXECUTABLE_DIRECTORY "${ARGS_BINARY_DIRECTORY}/${RUST_COMPILER_TARGET}")
    else()
        set(RUST_EXECUTABLE_DIRECTORY "${ARGS_BINARY_DIRECTORY}/${RUST_EXECUTABLE_TARGET}")
    endif()
    set(OUTPUT "${RUST_EXECUTABLE_DIRECTORY}/${CARGO_BUILD_TYPE}/${ARGS_TARGET}${RUST_EXECUTABLE_SUFFIX}")
    set(DEBUG_OUTPUT "${RUST_EXECUTABLE_DIRECTORY}/debug/${ARGS_TARGET}${RUST_EXECUTABLE_SUFFIX}")
    set(RELEASE_OUTPUT "${RUST_EXECUTABLE_DIRECTORY}/release/${ARGS_TARGET}${RUST_EXECUTABLE_SUFFIX}")

    file(GLOB_RECURSE EXE_SOURCES CONFIGURE_DEPENDS "${ARGS_SOURCE_DIRECTORY}/*.rs")
    set(CARGO_INPUTS
        ${EXE_SOURCES}
        "${ARGS_SOURCE_DIRECTORY}/Cargo.toml"
        "${CMAKE_SOURCE_DIR}/Cargo.toml"
        "${CMAKE_SOURCE_DIR}/Cargo.lock"
        ${ARGS_DEPENDS}
    )
    if(EXISTS "${ARGS_SOURCE_DIRECTORY}/build.rs")
        list(APPEND CARGO_INPUTS "${ARGS_SOURCE_DIRECTORY}/build.rs")
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/.cargo/config.toml")
        list(APPEND CARGO_INPUTS "${CMAKE_SOURCE_DIR}/.cargo/config.toml")
    endif()

    set(MY_CARGO_ARGS ${CARGO_ARGS})
    list(FIND MY_CARGO_ARGS "--target" CARGO_TARGET_INDEX)
    if(NOT CARGO_TARGET_INDEX EQUAL -1)
        list(REMOVE_AT MY_CARGO_ARGS ${CARGO_TARGET_INDEX})
        list(REMOVE_AT MY_CARGO_ARGS ${CARGO_TARGET_INDEX})
    endif()
    if(NOT "${RUST_EXECUTABLE_TARGET}" MATCHES "^universal-apple-darwin$")
        list(APPEND MY_CARGO_ARGS "--target" ${RUST_EXECUTABLE_TARGET})
    endif()
    list(APPEND MY_CARGO_ARGS "--target-dir" ${ARGS_BINARY_DIRECTORY})
    list(JOIN MY_CARGO_ARGS " " MY_CARGO_ARGS_STRING)

    list(APPEND ARGS_ENVIRONMENT "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}" "RUSTFLAGS=${RUSTFLAGS}")

    if(CMAKE_CONFIGURATION_TYPES)
        # Cargo has debug and release profiles while multi-config generators
        # select Debug, Release, RelWithDebInfo, or MinSizeRel at build time.
        # Make the utility target choose the matching Cargo profile and expose
        # configuration-specific imported locations below. A custom target is
        # intentionally used here because CMake 3.17 cannot express a
        # configuration-dependent custom-command output.
        set(RUST_RELEASE_CONFIGURATION "$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>")
        set(RUST_CARGO_PROFILE "$<IF:${RUST_RELEASE_CONFIGURATION},release,dev>")
        set(RUST_ARTIFACT_PROFILE "$<IF:${RUST_RELEASE_CONFIGURATION},release,debug>")
        set(RUST_PROFILE_ARGUMENT "--profile=${RUST_CARGO_PROFILE}")
        if("${RUST_COMPILER_TARGET}" MATCHES "^universal-apple-darwin$")
            add_custom_target(${ARGS_TARGET}_target
                COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} ${RUST_PROFILE_ARGUMENT} --target=x86_64-apple-darwin
                COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} ${RUST_PROFILE_ARGUMENT} --target=aarch64-apple-darwin
                COMMAND ${CMAKE_COMMAND} -E make_directory "${RUST_EXECUTABLE_DIRECTORY}/${RUST_ARTIFACT_PROFILE}"
                COMMAND lipo -create "${ARGS_BINARY_DIRECTORY}/x86_64-apple-darwin/${RUST_ARTIFACT_PROFILE}/${ARGS_TARGET}" "${ARGS_BINARY_DIRECTORY}/aarch64-apple-darwin/${RUST_ARTIFACT_PROFILE}/${ARGS_TARGET}" -output "${RUST_EXECUTABLE_DIRECTORY}/${RUST_ARTIFACT_PROFILE}/${ARGS_TARGET}"
                WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
                DEPENDS ${CARGO_INPUTS}
                COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY}")
        else()
            add_custom_target(${ARGS_TARGET}_target
                COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} ${RUST_PROFILE_ARGUMENT}
                WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
                DEPENDS ${CARGO_INPUTS}
                COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY}")
        endif()
        set(OUTPUT "$<IF:${RUST_RELEASE_CONFIGURATION},${RELEASE_OUTPUT},${DEBUG_OUTPUT}>")
    else()
        # Build the executable. A universal macOS binary needs one Cargo build
        # per architecture followed by lipo, matching add_rust_library().
        if("${RUST_COMPILER_TARGET}" MATCHES "^universal-apple-darwin$")
            set(X86_64_OUTPUT "${ARGS_BINARY_DIRECTORY}/x86_64-apple-darwin/${CARGO_BUILD_TYPE}/${ARGS_TARGET}")
            set(ARM64_OUTPUT "${ARGS_BINARY_DIRECTORY}/aarch64-apple-darwin/${CARGO_BUILD_TYPE}/${ARGS_TARGET}")
            add_custom_command(
                OUTPUT "${OUTPUT}"
                COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --target=x86_64-apple-darwin
                COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} --target=aarch64-apple-darwin
                COMMAND ${CMAKE_COMMAND} -E make_directory "${RUST_EXECUTABLE_DIRECTORY}/${CARGO_BUILD_TYPE}"
                COMMAND lipo -create "${X86_64_OUTPUT}" "${ARM64_OUTPUT}" -output "${OUTPUT}"
                WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
                DEPENDS ${CARGO_INPUTS}
                COMMENT "Building universal ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY}")
        else()
            add_custom_command(
                OUTPUT "${OUTPUT}"
                COMMAND ${CMAKE_COMMAND} -E env ${ARGS_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS}
                WORKING_DIRECTORY "${ARGS_SOURCE_DIRECTORY}"
                DEPENDS ${CARGO_INPUTS}
                COMMENT "Building ${ARGS_TARGET} in ${ARGS_BINARY_DIRECTORY} with:\n\t ${cargo_EXECUTABLE} ${MY_CARGO_ARGS_STRING}\n  Environment:  ${ARGS_ENVIRONMENT}")
        endif()
        add_custom_target(${ARGS_TARGET}_target DEPENDS ${OUTPUT})
    endif()

    # Keep a buildable custom target and expose the Cargo artifact as an
    # imported executable target for CMake consumers that use TARGET_FILE.
    add_custom_target(${ARGS_TARGET} ALL DEPENDS ${ARGS_TARGET}_target)
    add_executable(${ARGS_TARGET}_executable IMPORTED GLOBAL)
    add_dependencies(${ARGS_TARGET}_executable ${ARGS_TARGET}_target)

    # Specify where the executable artifact is.
    if(CMAKE_CONFIGURATION_TYPES)
        set_target_properties(${ARGS_TARGET}_executable
            PROPERTIES
            IMPORTED_LOCATION "${DEBUG_OUTPUT}"
            IMPORTED_CONFIGURATIONS "DEBUG;RELEASE;RELWITHDEBINFO;MINSIZEREL"
            IMPORTED_LOCATION_DEBUG "${DEBUG_OUTPUT}"
            IMPORTED_LOCATION_RELEASE "${RELEASE_OUTPUT}"
            IMPORTED_LOCATION_RELWITHDEBINFO "${RELEASE_OUTPUT}"
            IMPORTED_LOCATION_MINSIZEREL "${RELEASE_OUTPUT}"
        )
    else()
        set_target_properties(${ARGS_TARGET}_executable
            PROPERTIES
            IMPORTED_LOCATION "${OUTPUT}"
        )
    endif()

    if(ARGS_OUTPUT_VARIABLE)
        set(${ARGS_OUTPUT_VARIABLE} "${OUTPUT}" PARENT_SCOPE)
    endif()

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
    set(multiValueArgs ENVIRONMENT PRECOMPILE_ENVIRONMENT)
    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    set(MY_CARGO_ARGS "test")

    if(NOT "${CMAKE_OSX_ARCHITECTURES}" MATCHES "^(arm64;x86_64|x86_64;arm64)$") # Don't specify the target for universal, we'll do that manually for each build.
        list(APPEND MY_CARGO_ARGS "--target" ${RUST_COMPILER_TARGET})
    endif()

    if(CMAKE_CONFIGURATION_TYPES)
        set(RUST_TEST_PROFILE "$<IF:$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>,release,dev>")
        set(RUST_TEST_PROFILE_ARGUMENT "--profile=${RUST_TEST_PROFILE}")
    elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo" OR "${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel")
        list(APPEND MY_CARGO_ARGS "--release")
    endif()

    list(APPEND MY_CARGO_ARGS "--target-dir" ${ARGS_BINARY_DIRECTORY})
    list(JOIN MY_CARGO_ARGS " " MY_CARGO_ARGS_STRING)

    set(RUST_TEST_ENVIRONMENT ${ARGS_ENVIRONMENT})
    list(APPEND RUST_TEST_ENVIRONMENT
        "CARGO_CMD=test"
        "CARGO_TARGET_DIR=${ARGS_BINARY_DIRECTORY}"
        "RUSTFLAGS=${RUSTFLAGS}")

    if(ARGS_PRECOMPILE_TESTS)
        list(APPEND ARGS_PRECOMPILE_ENVIRONMENT ${RUST_TEST_ENVIRONMENT})
        add_custom_target(${ARGS_NAME}_tests ALL
            COMMAND ${CMAKE_COMMAND} -E env ${ARGS_PRECOMPILE_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} ${RUST_TEST_PROFILE_ARGUMENT} --color always --no-run
            DEPENDS ${ARGS_PRECOMPILE_DEPENDS}
            WORKING_DIRECTORY ${ARGS_SOURCE_DIRECTORY}
        )
    endif()

    message(STATUS "Environment: ${RUST_TEST_ENVIRONMENT}")

    add_test(
        NAME ${ARGS_NAME}
        COMMAND ${CMAKE_COMMAND} -E env ${RUST_TEST_ENVIRONMENT} ${cargo_EXECUTABLE} ${MY_CARGO_ARGS} ${RUST_TEST_PROFILE_ARGUMENT} --color always
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
        # For Visual Studio ARM64 configurations, CMAKE_SIZEOF_VOID_P is also
        # eight. Check the target platform before falling back to x86_64.
        if(CMAKE_GENERATOR_PLATFORM MATCHES "^[Aa][Rr][Mm]64$"
                OR CMAKE_VS_PLATFORM_NAME MATCHES "^[Aa][Rr][Mm]64$"
                OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
            set(RUST_COMPILER_TARGET "aarch64-pc-windows-msvc")
        elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
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

string(STRIP "${RUSTFLAGS} $ENV{RUSTFLAGS}" RUSTFLAGS)

if(RUSTFLAGS MATCHES "(^| )-Zsanitizer=[^ ]+($| )")
    if(NOT rustc_VERSION MATCHES "-nightly")
        message(FATAL_ERROR
            "Rust sanitizer support requires a nightly Rust toolchain because "
            "`-Zsanitizer` is unstable."
        )
    endif()
endif()

if(RUSTFLAGS MATCHES "(^| )-Zsanitizer=memory($| )")
    if(NOT "${RUST_COMPILER_TARGET}" MATCHES "^(aarch64|x86_64)-unknown-linux-gnu$")
        message(FATAL_ERROR
            "Rust MemorySanitizer requires a target whose standard library can be "
            "rebuilt with `-Zbuild-std`, and `${RUST_COMPILER_TARGET}` is not a "
            "supported Rust MSan target. Use a supported Linux target or remove "
            "`-Zsanitizer=memory` from RUSTFLAGS."
        )
    endif()

    list(APPEND CARGO_ARGS
        "-Zbuild-std=core,alloc,std,proc_macro,panic_abort"
        "-Zbuild-std-features=panic_immediate_abort"
    )
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
string(STRIP "${RUSTFLAGS}" RUSTFLAGS)

find_package_handle_standard_args(Rust
    REQUIRED_VARS cargo_EXECUTABLE
    VERSION_VAR cargo_VERSION
)
