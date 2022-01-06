# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamd executable.
add_executable( clamd )
target_sources( clamd
    PRIVATE
        clamd.c
        clamd_others.c
        clamd_others.h
        localserver.c
        localserver.h
        scanner.c
        scanner.h
        server-th.c
        server.h
        session.c
        session.h
        shared.h
        tcpserver.c
        tcpserver.h
        thrmgr.c
        thrmgr.h )
if(WIN32)
    target_sources( clamd PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/clamd.rc )
endif()
target_include_directories( clamd
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamd PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( clamd
    PRIVATE
        ClamAV::libclamav
        ClamAV::shared )
if(WIN32)
    install(TARGETS clamd DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS clamd DESTINATION ${CMAKE_INSTALL_SBINDIR})
endif()

if(SYSTEMD_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-daemon.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-daemon.service @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-daemon.service
        DESTINATION ${SYSTEMD_UNIT_DIR})
endif()
