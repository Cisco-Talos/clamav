# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

# The clamav-milter executable.
add_executable( clamav-milter )
target_sources( clamav-milter
    PRIVATE
        clamav-milter.c
        clamfi.c
        clamfi.h
        connpool.c
        connpool.h
        netcode.c
        netcode.h
        allow_list.c
        allow_list.h )
target_include_directories( clamav-milter
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamav-milter PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( clamav-milter PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries( clamav-milter
    PRIVATE
        ClamAV::libclamav
        ClamAV::common
        Sendmail::milter )
install(TARGETS clamav-milter DESTINATION ${CMAKE_INSTALL_SBINDIR} COMPONENT programs)
