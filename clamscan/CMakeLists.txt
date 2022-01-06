# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamscan executable.
add_executable( clamscan )
target_sources( clamscan
    PRIVATE
        clamscan.c
        manager.c
        manager.h
        global.h )
if(WIN32)
    target_sources( clamscan PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/clamscan.rc )
endif()
target_include_directories( clamscan
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamscan PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( clamscan
    PRIVATE
        ClamAV::libclamav
        ClamAV::shared )
if(WIN32)
    install(TARGETS clamscan DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS clamscan DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
