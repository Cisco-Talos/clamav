# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Example executables
#
add_executable(ex1)
target_sources(ex1
    PRIVATE   ex1.c)
set_target_properties( ex1 PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries(ex1
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex1 PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex1 PUBLIC ${LLVM_LIBRARIES} )
endif()
if(WIN32)
    install(TARGETS ex1 DESTINATION .)
else()
    install(TARGETS ex1 DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(ENABLE_STATIC_LIB)
    add_executable(ex1_static)
    set_target_properties( ex1_static PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}" )
    target_sources(ex1_static
        PRIVATE   ex1.c)
    target_link_libraries(ex1_static
        PRIVATE
            ClamAV::libclamav_static)
    if(LLVM_FOUND)
        target_link_directories( ex1_static PUBLIC ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( ex1_static PUBLIC ${LLVM_LIBRARIES} )
    endif()
    if(WIN32)
        install(TARGETS ex1_static DESTINATION .)
    else()
        install(TARGETS ex1_static DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

add_executable(ex2_prescan)
target_sources(ex2_prescan
    PRIVATE   ex2_prescan.c)
set_target_properties(ex2_prescan PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries(ex2_prescan
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex2_prescan PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex2_prescan PUBLIC ${LLVM_LIBRARIES} )
endif()
if(WIN32)
    install(TARGETS ex2_prescan DESTINATION .)
else()
    install(TARGETS ex2_prescan DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

add_executable(ex3_file_inspection)
target_sources(ex3_file_inspection
    PRIVATE   ex3_file_inspection.c)
set_target_properties(ex3_file_inspection PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries(ex3_file_inspection
    PRIVATE
        ClamAV::libclamav)
if(LLVM_FOUND)
    target_link_directories( ex3_file_inspection PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( ex3_file_inspection PUBLIC ${LLVM_LIBRARIES} )
endif()
if(WIN32)
    install(TARGETS ex3_file_inspection DESTINATION .)
else()
    install(TARGETS ex3_file_inspection DESTINATION ${CMAKE_INSTALL_BINDIR})
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
