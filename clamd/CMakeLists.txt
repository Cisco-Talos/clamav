# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

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
    target_sources( clamd
    PRIVATE
        ${CMAKE_SOURCE_DIR}/win32/res/clamd.rc
        ${CMAKE_SOURCE_DIR}/win32/res/clam.manifest )
endif()
target_include_directories( clamd
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamd PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( clamd PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries( clamd
    PRIVATE
        ClamAV::libclamav
        ClamAV::common )
install(TARGETS clamd DESTINATION ${CMAKE_INSTALL_SBINDIR} COMPONENT programs)
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:clamd> TYPE SBIN OPTIONAL COMPONENT programs)
endif()

if(SYSTEMD_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-daemon.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-daemon.service @ONLY)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-daemon.socket.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-daemon.socket @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-daemon.service
        DESTINATION ${SYSTEMD_UNIT_DIR} COMPONENT programs)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-daemon.socket
        DESTINATION ${SYSTEMD_UNIT_DIR} COMPONENT programs)
endif()
