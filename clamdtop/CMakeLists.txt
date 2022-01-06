# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamdtop executable.
add_executable( clamdtop )
target_sources( clamdtop
    PRIVATE
        clamdtop.c )
if(WIN32)
    target_sources( clamdtop PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/clamdtop.rc )
endif()
target_include_directories( clamdtop
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamdtop PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( clamdtop
    PRIVATE
        ClamAV::libclamav
        ClamAV::shared
        Curses::curses )
if(WIN32)
    install(TARGETS clamdtop DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS clamdtop DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
