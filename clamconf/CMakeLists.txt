# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamconf executable.
add_executable( clamconf )
target_sources( clamconf
    PRIVATE
        clamconf.c )
if(WIN32)
    target_sources( clamconf PRIVATE 
    ${CMAKE_SOURCE_DIR}/win32/res/clamconf.rc
    ${CMAKE_SOURCE_DIR}/win32/res/clam.manifest )
endif()
target_include_directories( clamconf
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamconf PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( clamconf PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries( clamconf
    PRIVATE
        ClamAV::libclamav
        ClamAV::common )

install(TARGETS clamconf COMPONENT programs)
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:clamconf> TYPE BIN OPTIONAL COMPONENT programs)
endif()
