# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

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
        whitelist.c
        whitelist.h )
target_include_directories( clamav-milter
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamav-milter PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( clamav-milter
    PRIVATE
        ClamAV::libclamav
        ClamAV::shared
        Sendmail::milter )
install(TARGETS clamav-milter DESTINATION ${CMAKE_INSTALL_SBINDIR})
