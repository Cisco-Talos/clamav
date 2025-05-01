# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clambc executable.
add_executable( clambc )
target_sources( clambc
    PRIVATE
        bcrun.c )
if(WIN32)
    target_sources( clambc PRIVATE ${CMAKE_SOURCE_DIR}/win32/res/clambc.rc )
endif()
target_include_directories( clambc
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clambc PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if(CLANG_TIDY)
    set_target_properties( clambc PROPERTIES
        C_CLANG_TIDY "${CLANG_TIDY_PROPERTY}"
        C_CLANG_TIDY_EXPORT_FIXES_DIR "${CMAKE_BINARY_DIR}/clang-tidy-fixes" )
endif()

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( clambc PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries( clambc
    PRIVATE
        ClamAV::libclamav
        ClamAV::common )
if(WIN32)
    install(TARGETS clambc DESTINATION . COMPONENT programs)
    install(FILES $<TARGET_PDB_FILE:clambc> DESTINATION . OPTIONAL COMPONENT programs)
else()
    install(TARGETS clambc DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)
endif()
