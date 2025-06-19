
cmake_minimum_required( VERSION 3.13 )

if(WIN32)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# This is a hack!  We need a config.h
# TODO: either un-vendor mspack, or use new mspack CMake tooling when it merges into the upstream.
configure_file(config.h.in.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# not using an object library for the sake of Xcode compatibility
# See: https://cmake.org/pipermail/cmake/2016-May/063479.html
set(MSPACK_SOURCES
    mspack/cab.h
    mspack/cabc.c
    mspack/cabd.c
    mspack/chm.h
    mspack/chmc.c
    mspack/chmd.c
    mspack/crc32.c
    mspack/crc32.h
    mspack/des.h
    mspack/hlp.h
    mspack/hlpc.c
    mspack/hlpd.c
    mspack/kwaj.h
    mspack/kwajc.c
    mspack/kwajd.c
    mspack/lit.h
    mspack/litc.c
    mspack/litd.c
    mspack/lzss.h
    mspack/lzssd.c
    mspack/lzx.h
    mspack/lzxc.c
    mspack/lzxd.c
    mspack/mszip.h
    mspack/mszipc.c
    mspack/mszipd.c
    mspack/oab.h
    mspack/oabc.c
    mspack/oabd.c
    mspack/qtm.h
    mspack/qtmd.c
    mspack/readbits.h
    mspack/readhuff.h
    mspack/sha.h
    mspack/system.c
    mspack/system.h
    mspack/szdd.h
    mspack/szddc.c
    mspack/szddd.c
)

if(ENABLE_SHARED_LIB)
    # The mspack shared library.
    add_library( clammspack SHARED )
    set_target_properties(clammspack PROPERTIES
        VERSION "0.8.0" SOVERSION 0)
    if(WIN32)
        set_target_properties(clammspack PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
    target_sources( clammspack
        PRIVATE
            ${MSPACK_SOURCES}
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/mspack/mspack.h )
    target_include_directories( clammspack
        PRIVATE
            ${CMAKE_BINARY_DIR}
            ${CMAKE_CURRENT_BINARY_DIR}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mspack )

    if (APPLE AND CLAMAV_SIGN_FILE)
        set_target_properties( clammspack PROPERTIES
            XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
            XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
        )
    endif()

    install(TARGETS clammspack COMPONENT libraries)
    if(WIN32)
        install(FILES $<TARGET_PDB_FILE:clammspack> TYPE BIN OPTIONAL COMPONENT libraries)
    endif()

    add_library( ClamAV::libmspack ALIAS clammspack )
endif()

if(ENABLE_STATIC_LIB)
    # The clamav static library.
    add_library( clammspack_static STATIC)
    target_sources( clammspack_static
        PRIVATE
            ${MSPACK_SOURCES}
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/mspack/mspack.h )
    target_include_directories( clammspack_static
        PRIVATE
            ${CMAKE_BINARY_DIR}
            ${CMAKE_CURRENT_BINARY_DIR}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mspack )

    install(TARGETS clammspack_static COMPONENT libraries)

    add_library( ClamAV::libmspack_static ALIAS clammspack_static )
    if(NOT ENABLE_SHARED_LIB)
        add_library( ClamAV::libmspack ALIAS clammspack_static )
    endif()
endif()
