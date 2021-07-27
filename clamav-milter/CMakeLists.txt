# Copyright (C) 2020-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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
target_link_libraries( clamav-milter
    PRIVATE
        ClamAV::libclamav
        ClamAV::common
        Sendmail::milter )
install(TARGETS clamav-milter DESTINATION ${CMAKE_INSTALL_SBINDIR} COMPONENT programs)
