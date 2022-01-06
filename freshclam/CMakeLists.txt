# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The freshclam executable.
add_executable( freshclam-bin )
target_sources( freshclam-bin
    PRIVATE
        freshclam.c
        execute.c
        execute.h
        notify.c
        notify.h )
if(WIN32)
    target_sources( freshclam-bin PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/freshclam.rc )
endif()
set_target_properties( freshclam-bin PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries(freshclam-bin
    PRIVATE
        ClamAV::libfreshclam
        ClamAV::libclamav
        ClamAV::shared )
if(WIN32)
    install(TARGETS freshclam-bin DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS freshclam-bin DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# Install an empty database directory
if(WIN32)
    INSTALL(CODE "FILE(MAKE_DIRECTORY \${ENV}\${CMAKE_INSTALL_PREFIX}/database)")
else()
    INSTALL(CODE "FILE(MAKE_DIRECTORY \${ENV}\${CMAKE_INSTALL_PREFIX}/share/clamav)")
endif()

# now we rename resman-bin executable to resman using target properties
set_target_properties( freshclam-bin
        PROPERTIES OUTPUT_NAME freshclam )

if(SYSTEMD_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-freshclam.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam.service @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam.service
        DESTINATION ${SYSTEMD_UNIT_DIR})
endif()
