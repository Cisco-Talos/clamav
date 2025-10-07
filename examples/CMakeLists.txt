# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Example executables
#
add_executable(ex_basic_scandesc)
target_sources(ex_basic_scandesc
    PRIVATE   ex_basic_scandesc.c)
set_target_properties( ex_basic_scandesc PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries(ex_basic_scandesc
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex_basic_scandesc PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex_basic_scandesc PUBLIC ${LLVM_LIBRARIES} )
endif()
install(TARGETS ex_basic_scandesc)

if(ENABLE_STATIC_LIB)
    add_executable(ex_basic_scandesc_static)
    set_target_properties( ex_basic_scandesc_static PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
    target_sources(ex_basic_scandesc_static
        PRIVATE   ex_basic_scandesc.c)
    target_link_libraries(ex_basic_scandesc_static
        PRIVATE
            ClamAV::libclamav_static)
    if(LLVM_FOUND)
        target_link_directories( ex_basic_scandesc_static PUBLIC ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( ex_basic_scandesc_static PUBLIC ${LLVM_LIBRARIES} )
    endif()
    install(TARGETS ex_basic_scandesc_static)
endif()

add_executable(ex_prescan_callback)
target_sources(ex_prescan_callback
    PRIVATE   ex_prescan_callback.c)
set_target_properties(ex_prescan_callback PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries(ex_prescan_callback
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex_prescan_callback PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex_prescan_callback PUBLIC ${LLVM_LIBRARIES} )
endif()
install(TARGETS ex_prescan_callback)

add_executable(ex_file_inspection_callback)
target_sources(ex_file_inspection_callback
    PRIVATE   ex_file_inspection_callback.c)
set_target_properties(ex_file_inspection_callback PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries(ex_file_inspection_callback
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex_file_inspection_callback PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex_file_inspection_callback PUBLIC ${LLVM_LIBRARIES} )
endif()
install(TARGETS ex_file_inspection_callback)

add_executable(ex_scan_callbacks)
target_sources(ex_scan_callbacks
    PRIVATE   ex_scan_callbacks.c)
set_target_properties(ex_scan_callbacks PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries(ex_scan_callbacks
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex_scan_callbacks PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex_scan_callbacks PUBLIC ${LLVM_LIBRARIES} )
endif()
if(WIN32)
    install(TARGETS ex_scan_callbacks DESTINATION .)
else()
    install(TARGETS ex_scan_callbacks DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

add_executable(ex_cl_cvdunpack)
target_sources(ex_cl_cvdunpack
    PRIVATE   ex_cl_cvdunpack.c)
set_target_properties( ex_cl_cvdunpack PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries(ex_cl_cvdunpack
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex_cl_cvdunpack PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex_cl_cvdunpack PUBLIC ${LLVM_LIBRARIES} )
endif()

if(ENABLE_STATIC_LIB)
    add_executable(ex_cl_cvdunpack_static)
    set_target_properties( ex_cl_cvdunpack_static PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
    target_sources(ex_cl_cvdunpack_static
        PRIVATE   ex_cl_cvdunpack.c)
    target_link_libraries(ex_cl_cvdunpack_static
        PRIVATE
            ClamAV::libclamav_static)
    if(LLVM_FOUND)
        target_link_directories( ex_cl_cvdunpack_static PUBLIC ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( ex_cl_cvdunpack_static PUBLIC ${LLVM_LIBRARIES} )
    endif()
endif()
