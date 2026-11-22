# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

# Build clamdtop as a standalone Rust application. The executable speaks the
# clamd protocol directly and does not link against libclamav or curses.
set(CLAMAV_VERSION "${PROJECT_VERSION}${VERSION_SUFFIX}")
set(CLAMAV_DEFAULT_CLAMD_CONFIG "${CONFDIR}/clamd.conf")
set(CLAMD_TOP_RESOURCE_DEPENDS
    "${CMAKE_SOURCE_DIR}/win32/res/clamdtop.rc"
    "${CMAKE_SOURCE_DIR}/win32/res/clam.manifest"
    "${CMAKE_SOURCE_DIR}/win32/res/clam.ico"
    "${CMAKE_SOURCE_DIR}/win32/res/common.rc.in"
)
if(WIN32)
    list(APPEND CLAMD_TOP_RESOURCE_DEPENDS "${CMAKE_SOURCE_DIR}/win32/res/common.rc")
endif()

add_rust_executable(TARGET clamdtop
    SOURCE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
    OUTPUT_VARIABLE CLAMD_TOP_EXECUTABLE
    DEPENDS ${CLAMD_TOP_RESOURCE_DEPENDS}
    ENVIRONMENT
        "CLAMAV_VERSION=${CLAMAV_VERSION}"
        "CLAMAV_DEFAULT_CLAMD_CONFIG=${CLAMAV_DEFAULT_CLAMD_CONFIG}"
        "CLAMAV_CMAKE_BUILD_DIR=${CMAKE_BINARY_DIR}"
)

if(ENABLE_TESTS)
    add_rust_test(NAME clamdtop
        SOURCE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
        ENVIRONMENT "CLAMAV_CMAKE_BUILD_DIR=${CMAKE_BINARY_DIR}"
    )
endif()

install(PROGRAMS "${CLAMD_TOP_EXECUTABLE}" TYPE BIN COMPONENT programs)

if(APPLE AND CLAMAV_SIGN_FILE)
    # add_rust_executable() exposes a utility target, for which CMake does not
    # support POST_BUILD commands. Depend on its generated Cargo artifact and
    # make the normal clamdtop target run signing after it has been built.
    add_custom_target(clamdtop_sign
        COMMAND /usr/bin/codesign --force --sign "${CODE_SIGN_IDENTITY}"
            --identifier com.cisco.clamav.clamdtop "${CLAMD_TOP_EXECUTABLE}"
        DEPENDS clamdtop_target
        COMMENT "Signing clamdtop")
    add_dependencies(clamdtop clamdtop_sign)
endif()

if(WIN32)
    install(FILES "${CLAMD_TOP_EXECUTABLE}.pdb" TYPE BIN OPTIONAL COMPONENT programs)
endif()
