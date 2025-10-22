# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# The clamdtop executable.
add_executable( clamdtop )
target_sources( clamdtop
    PRIVATE
        clamdtop.c )
if(WIN32)
    target_sources( clamdtop PRIVATE 
    ${CMAKE_SOURCE_DIR}/win32/res/clamdtop.rc
    ${CMAKE_SOURCE_DIR}/win32/res/clam.manifest )
endif()
target_include_directories( clamdtop
    PRIVATE ${CMAKE_BINARY_DIR} # For clamav-config.h
)
set_target_properties( clamdtop PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )

if (APPLE AND CLAMAV_SIGN_FILE)
    set_target_properties( clamdtop PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
    )
endif()

target_link_libraries( clamdtop
    PRIVATE
        ClamAV::libclamav
        ClamAV::common
        Curses::curses )
install(TARGETS clamdtop COMPONENT programs)
if(WIN32)
    install(FILES $<TARGET_PDB_FILE:clamdtop> TYPE BIN OPTIONAL COMPONENT programs)
    if(ENABLE_WINDOWS_INSTALL_THIRDPARTY_DEPENDENCIES)
        # Also install shared library (DLL) dependencies
        install(CODE [[
            file(GET_RUNTIME_DEPENDENCIES
                EXECUTABLES
                    $<TARGET_FILE:clamdtop>
                RESOLVED_DEPENDENCIES_VAR _r_deps
                UNRESOLVED_DEPENDENCIES_VAR _u_deps
                DIRECTORIES
                    $<TARGET_FILE_DIR:Curses::curses>
                POST_EXCLUDE_REGEXES
                    "[cC]:[\\/][wW][iI][nN][dD][oO][wW][sS]"
            )
            foreach(_file ${_r_deps})
                string(TOLOWER ${_file} _file_lower)
                if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                    file(INSTALL
                        DESTINATION "${CMAKE_INSTALL_PREFIX}"
                        TYPE SHARED_LIBRARY
                        FOLLOW_SYMLINK_CHAIN
                        FILES "${_file}"
                    )
                endif()
            endforeach()
            #message("UNRESOLVED_DEPENDENCIES_VAR: ${_u_deps}")
            ]]
            COMPONENT programs)
    endif()
endif()
