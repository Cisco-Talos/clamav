
cmake_minimum_required( VERSION 3.13 )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# Move public headers to a dedicated INTERFACE library
#
# An interface is required because libclamav objects will depend on the
# interface to put unrar_iface.h in the include path, but we don't want to link
# with it.
# libclamunrar_iface will be dynamically loaded at run time, if enabled.
add_library(clamunrar_iface_iface INTERFACE)
target_sources(clamunrar_iface_iface
    INTERFACE
        unrar_iface.h )
target_include_directories( clamunrar_iface_iface
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> )

add_library( ClamAV::libclamunrar_iface_iface ALIAS clamunrar_iface_iface )

if(ENABLE_UNRAR)
    # The clamunrar_iface SHARED library.
    add_library( clamunrar_iface SHARED )
    set_target_properties(clamunrar_iface PROPERTIES
        VERSION ${LIBCLAMAV_VERSION}
        SOVERSION ${LIBCLAMAV_SOVERSION})
    target_sources( clamunrar_iface
        PRIVATE
            unrar_iface.cpp )

    target_include_directories( clamunrar_iface
        PRIVATE
            "${CMAKE_BINARY_DIR}" # For clamav-config.h
            $<TARGET_PROPERTY:ClamAV::libclamunrar,INTERFACE_INCLUDE_DIRECTORIES>
            $<TARGET_PROPERTY:ClamAV::libclamav,INTERFACE_INCLUDE_DIRECTORIES> )

    set_target_properties( clamunrar_iface PROPERTIES
        COMPILE_FLAGS "${WARNCXXFLAGS} ${CXX1XCXXFLAGS}" )

    if(WIN32)
        set_target_properties(clamunrar_iface PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()

    # Private (internal-only) dependencies.
    target_link_libraries( clamunrar_iface
        PRIVATE
            ClamAV::libclamunrar
        PUBLIC
            ClamAV::libclamunrar_iface_iface)

    if(WIN32)
        install(TARGETS clamunrar_iface DESTINATION ${CMAKE_INSTALL_PREFIX})
    else()
        install(TARGETS clamunrar_iface DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()

    add_library( ClamAV::libclamunrar_iface ALIAS clamunrar_iface )
endif()