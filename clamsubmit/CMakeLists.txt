# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamsubmit executable.
add_executable( clamsubmit )
target_sources( clamsubmit
    PRIVATE
        clamsubmit.c )
if(WIN32)
    target_sources( clamsubmit PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/clamsubmit.rc )
endif()
target_include_directories( clamsubmit
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamsubmit PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( clamsubmit
    PRIVATE
        ClamAV::libclamav
        ClamAV::shared
        JSONC::jsonc )
if(APPLE)
    target_link_libraries( clamsubmit
        PUBLIC
            ${APPLE_CORE_FOUNDATION}
            ${APPLE_SECURITY} )
endif()
if(WIN32)
    install(TARGETS clamsubmit DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS clamsubmit DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
