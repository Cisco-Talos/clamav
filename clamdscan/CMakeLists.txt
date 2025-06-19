# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamdscan executable.
add_executable( clamdscan )
target_sources( clamdscan
    PRIVATE
        clamdscan.c
        client.c
        client.h
        proto.c
        proto.h )
if(WIN32)
    target_sources( clamdscan
    PRIVATE
        ${CMAKE_SOURCE_DIR}/win32/res/clamdscan.rc
        ${CMAKE_SOURCE_DIR}/win32/res/clam.manifest )
endif()
target_include_directories( clamdscan
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamdscan PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( clamdscan PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries( clamdscan
    PRIVATE
        ClamAV::libclamav
        ClamAV::common )
install(TARGETS clamdscan COMPONENT programs)
if(WIN32)
	install(FILES $<TARGET_PDB_FILE:clamdscan> TYPE BIN OPTIONAL COMPONENT programs)
endif()
