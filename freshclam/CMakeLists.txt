# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

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
    target_sources( freshclam-bin
        PRIVATE
            ${CMAKE_SOURCE_DIR}/win32/res/freshclam.rc
            ${CMAKE_SOURCE_DIR}/win32/res/clam.manifest )
endif()
set_target_properties( freshclam-bin PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( freshclam-bin PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries(freshclam-bin
    PRIVATE
        ClamAV::libfreshclam
        ClamAV::libclamav
        ClamAV::common )
install(TARGETS freshclam-bin COMPONENT programs)
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:freshclam-bin> TYPE BIN OPTIONAL COMPONENT programs)
endif()

# Now we rename freshclam-bin executable to freshclam using target properties
set_target_properties( freshclam-bin
        PROPERTIES OUTPUT_NAME freshclam )

if(SYSTEMD_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-freshclam.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam.service @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam.service
        DESTINATION ${SYSTEMD_UNIT_DIR}
        COMPONENT programs)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-freshclam-once.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam-once.service @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam-once.service
        DESTINATION ${SYSTEMD_UNIT_DIR}
        COMPONENT programs)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-freshclam-once.timer.in
        ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam-once.timer @ONLY)
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/clamav-freshclam-once.timer
        DESTINATION ${SYSTEMD_UNIT_DIR}
        COMPONENT programs)
endif()
