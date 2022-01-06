# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamconf executable.
add_executable( clamconf )
target_sources( clamconf
    PRIVATE
        clamconf.c )
if(WIN32)
    target_sources( clamconf PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/clamconf.rc )
endif()
target_include_directories( clamconf
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamconf PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( clamconf
    PRIVATE
        ClamAV::libclamav
        ClamAV::shared )
if(WIN32)
    install(TARGETS clamconf DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS clamconf DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
