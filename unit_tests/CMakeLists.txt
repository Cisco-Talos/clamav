# Copyright (C) 2020-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Decrypt test files
#
add_subdirectory( input )

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()


if (ENABLE_UNRAR)
    add_definitions(-DHAVE_UNRAR)
endif()


add_definitions(-DTHIS_IS_LIBCLAMAV)

#
# Programs used by tests
#

# preprocessor defines for test programs
if(WIN32)
    file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR} OBJDIR)
    string(REPLACE "\\" "\\\\" OBJDIR ${OBJDIR})
    file(TO_NATIVE_PATH ${CMAKE_CURRENT_SOURCE_DIR} SRCDIR)
    string(REPLACE "\\" "\\\\" SRCDIR ${SRCDIR})
else()
    set(OBJDIR ${CMAKE_CURRENT_BINARY_DIR})
    set(SRCDIR ${CMAKE_CURRENT_SOURCE_DIR})
endif()

if(ENABLE_APP)
    # check_fpu_endian is used by the clamscan tests
    add_executable(check_fpu_endian)
    target_sources(check_fpu_endian
        PRIVATE
            checks.h
            check_fpu_endian.c)
    target_link_libraries(check_fpu_endian
        PRIVATE
            libcheck::check
            ClamAV::libclamav
            regex
            lzma_sdk
            yara
            tomsfastmath
            bytecode_runtime
            JSONC::jsonc
            ${LIBMSPACK}
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
            BZip2::BZip2
            PCRE2::pcre2
            LibXml2::LibXml2)
    if(ENABLE_SHARED_LIB)
        target_link_libraries(check_fpu_endian
            PRIVATE
                ClamAV::libunrar_iface_iface)
    else()
        if (ENABLE_UNRAR)
            target_link_libraries(check_fpu_endian
                PRIVATE
                    ClamAV::libunrar_iface_static)
            endif()
    endif()
    if(LLVM_FOUND)
        target_link_directories( check_fpu_endian PUBLIC ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( check_fpu_endian PUBLIC ${LLVM_LIBRARIES} )
    endif()
    target_include_directories(check_fpu_endian PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/libclamav ${CMAKE_BINARY_DIR})
    target_compile_definitions(check_fpu_endian PUBLIC OBJDIR="${OBJDIR}" SRCDIR="${SRCDIR}")

    # check_clamd is used by the clamd tests
    add_executable(check_clamd)
    target_sources(check_clamd
        PRIVATE   check_clamd.c checks.h)
    target_link_libraries(check_clamd
        PRIVATE
            libcheck::check
            ClamAV::common
            ClamAV::libclamav
            regex
            lzma_sdk
            yara
            tomsfastmath
            bytecode_runtime
            JSONC::jsonc
            ${LIBMSPACK}
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
            BZip2::BZip2
            PCRE2::pcre2
            LibXml2::LibXml2)
    if(ENABLE_SHARED_LIB)
        target_link_libraries(check_clamd
            PRIVATE
                ClamAV::libunrar_iface_iface)
    else()
        if (ENABLE_UNRAR)
            target_link_libraries(check_clamd
                PRIVATE
                    ClamAV::libunrar_iface_static)
        endif()
    endif()
    if(LLVM_FOUND)
        target_link_directories( check_clamd PUBLIC ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( check_clamd PUBLIC ${LLVM_LIBRARIES} )
    endif()
    target_include_directories(check_clamd PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/libclamav ${CMAKE_BINARY_DIR})
    target_compile_definitions(check_clamd PUBLIC OBJDIR="${OBJDIR}" SRCDIR="${SRCDIR}")
endif()

#
# Test executables
#
add_executable(check_clamav)
target_sources(check_clamav
    PRIVATE
        checks.h
        check_bytecode.c
        check_clamav.c
        check_disasm.c
        check_htmlnorm.c
        check_jsnorm.c
        check_matchers.c
        check_regex.c
        check_str.c
        check_uniq.c)
target_link_libraries(check_clamav
    PRIVATE
        libcheck::check
        ClamAV::libclamav
        regex
        lzma_sdk
        yara
        tomsfastmath
        bytecode_runtime
        JSONC::jsonc
        ${LIBMSPACK}
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        BZip2::BZip2
        PCRE2::pcre2
        LibXml2::LibXml2)
if (ENABLE_UNRAR)
    if(ENABLE_SHARED_LIB)
        target_link_libraries(check_clamav
            PRIVATE
                ClamAV::libunrar_iface_iface)
    else()
        if (ENABLE_UNRAR)
            target_link_libraries(check_clamav
                PRIVATE
                    ClamAV::libunrar_iface_static)
        endif()
    endif()
endif()

if(LLVM_FOUND)
    target_link_directories( check_clamav PUBLIC ${LLVM_LIBRARY_DIRS} )
    target_link_libraries( check_clamav PUBLIC ${LLVM_LIBRARIES} )
endif()
target_include_directories(check_clamav PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/libclamav ${CMAKE_BINARY_DIR})
target_compile_definitions(check_clamav PUBLIC OBJDIR="${OBJDIR}" SRCDIR="${SRCDIR}")
ADD_CUSTOM_COMMAND(TARGET check_clamav POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/input/clamav.hdb ${CMAKE_CURRENT_BINARY_DIR}/input/.)

#
# Paths to pass to our tests via environment variables
#
if(WIN32)
    file(TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}                                     SOURCE)
    file(TO_NATIVE_PATH ${CMAKE_BINARY_DIR}                                     BUILD)
    file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}                             TMP)

    file(TO_NATIVE_PATH $<TARGET_FILE:check_clamav>                             CHECK_CLAMAV)
    if(ENABLE_APP)
        file(TO_NATIVE_PATH $<TARGET_FILE:check_clamd>                              CHECK_CLAMD)
        file(TO_NATIVE_PATH $<TARGET_FILE:check_fpu_endian>                         CHECK_FPU_ENDIAN)

        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clambc.exe              CLAMBC)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamd.exe               CLAMD)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamdscan.exe           CLAMDSCAN)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamdtop.exe            CLAMDTOP)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamscan.exe            CLAMSCAN)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamsubmit.exe          CLAMSUBMIT)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamconf.exe            CLAMCONF)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/freshclam.exe           FRESHCLAM)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/sigtool.exe             SIGTOOL)
    endif()
else()
    set(LD_LIBRARY_PATH     $<TARGET_FILE_DIR:ClamAV::libclamav>:$<TARGET_FILE_DIR:${LIBMSPACK}>:$ENV{LD_LIBRARY_PATH})
    if(NOT ENABLE_LIBCLAMAV_ONLY)
        set(LD_LIBRARY_PATH $<TARGET_FILE_DIR:ClamAV::libfreshclam>:${LD_LIBRARY_PATH})
    endif()
    if (ENABLE_UNRAR)
        set(LD_LIBRARY_PATH ${LD_LIBRARY_PATH}:$<TARGET_FILE_DIR:ClamAV::libunrar_iface>:$<TARGET_FILE_DIR:ClamAV::libunrar>)
    endif()


    set(SOURCE             ${CMAKE_SOURCE_DIR})
    set(BUILD              ${CMAKE_BINARY_DIR})
    set(TMP                ${CMAKE_CURRENT_BINARY_DIR})

    set(CHECK_CLAMAV       $<TARGET_FILE:check_clamav>)
    if(ENABLE_APP)
        set(CHECK_CLAMD        $<TARGET_FILE:check_clamd>)
        set(CHECK_FPU_ENDIAN   $<TARGET_FILE:check_fpu_endian>)

        set(CLAMBC             $<TARGET_FILE:clambc>)
        set(CLAMD              $<TARGET_FILE:clamd>)
        set(CLAMDSCAN          $<TARGET_FILE:clamdscan>)
        set(CLAMDTOP           $<TARGET_FILE:clamdtop>)
        set(CLAMSCAN           $<TARGET_FILE:clamscan>)
        set(CLAMSUBMIT         $<TARGET_FILE:clamsubmit>)
        set(CLAMCONF           $<TARGET_FILE:clamconf>)
        set(FRESHCLAM          $<TARGET_FILE:freshclam-bin>)
        set(SIGTOOL            $<TARGET_FILE:sigtool>)
        if(ENABLE_MILTER)
            set(CLAMAV_MILTER      $<TARGET_FILE:clamav-milter>)
        endif()
        if(ENABLE_CLAMONACC)
            set(CLAMONACC          $<TARGET_FILE:clamonacc>)
        endif()
    endif()
endif()

set(ENVIRONMENT
    PYTHONTRACEMALLOC=1 VERSION=${PROJECT_VERSION}${VERSION_SUFFIX}
    SOURCE=${SOURCE} BUILD=${BUILD} TMP=${TMP}
    CK_FORK=no
    CK_DEFAULT_TIMEOUT=60
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
    SOURCE=${SOURCE}
    BUILD=${BUILD}
    TMP=${TMP}
    CHECK_CLAMAV=${CHECK_CLAMAV}
    CHECK_CLAMD=${CHECK_CLAMD}
    CHECK_FPU_ENDIAN=${CHECK_FPU_ENDIAN}
    CLAMBC=${CLAMBC}
    CLAMD=${CLAMD}
    CLAMDSCAN=${CLAMDSCAN}
    CLAMDTOP=${CLAMDTOP}
    CLAMSCAN=${CLAMSCAN}
    CLAMSUBMIT=${CLAMSUBMIT}
    CLAMCONF=${CLAMCONF}
    FRESHCLAM=${FRESHCLAM}
    SIGTOOL=${SIGTOOL}
    CLAMAV_MILTER=${CLAMAV_MILTER}
    CLAMONACC=${CLAMONACC}
)

#
# The Tests
# ~~~~~~~~~
#
# Run all tests with: `ctest`
#                 or: `ctest -V` for verbose output
#
# Run a specific test like this:
#                     `ctest -V -R libclamav_valgrind_test`
#

add_test(NAME libclamav COMMAND ${PythonTest_COMMAND};libclamav_test.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set_property(TEST libclamav PROPERTY ENVIRONMENT ${ENVIRONMENT})
if(Valgrind_FOUND)
    add_test(NAME libclamav_valgrind COMMAND ${PythonTest_COMMAND};libclamav_test.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST libclamav_valgrind PROPERTY ENVIRONMENT ${ENVIRONMENT} VALGRIND=${Valgrind_EXECUTABLE})
endif()

if(ENABLE_APP)
    add_test(NAME clamscan COMMAND ${PythonTest_COMMAND};clamscan_test.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST clamscan PROPERTY ENVIRONMENT ${ENVIRONMENT})
    if(Valgrind_FOUND)
        add_test(NAME clamscan_valgrind COMMAND ${PythonTest_COMMAND};clamscan_test.py
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_property(TEST clamscan_valgrind PROPERTY ENVIRONMENT ${ENVIRONMENT} VALGRIND=${Valgrind_EXECUTABLE})
    endif()

    add_test(NAME clamd COMMAND ${PythonTest_COMMAND};clamd_test.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST clamd PROPERTY ENVIRONMENT ${ENVIRONMENT})
    if(Valgrind_FOUND)
        add_test(NAME clamd_valgrind COMMAND ${PythonTest_COMMAND};clamd_test.py
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_property(TEST clamd_valgrind PROPERTY ENVIRONMENT ${ENVIRONMENT} VALGRIND=${Valgrind_EXECUTABLE})
    endif()

    add_test(NAME freshclam COMMAND ${PythonTest_COMMAND};freshclam_test.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST freshclam PROPERTY ENVIRONMENT ${ENVIRONMENT})
    if(Valgrind_FOUND)
        add_test(NAME freshclam_valgrind COMMAND ${PythonTest_COMMAND};freshclam_test.py
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_property(TEST freshclam_valgrind PROPERTY ENVIRONMENT ${ENVIRONMENT} VALGRIND=${Valgrind_EXECUTABLE})
    endif()

    add_test(NAME sigtool COMMAND ${PythonTest_COMMAND};sigtool_test.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST sigtool PROPERTY ENVIRONMENT ${ENVIRONMENT})
    if(Valgrind_FOUND)
        add_test(NAME sigtool_valgrind COMMAND ${PythonTest_COMMAND};sigtool_test.py
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_property(TEST sigtool_valgrind PROPERTY ENVIRONMENT ${ENVIRONMENT} VALGRIND=${Valgrind_EXECUTABLE})
    endif()
endif()

if(WIN32)
    #
    # Prepare a test install, with all our DLL dependencies co-located with our EXEs and DLLs
    #
    if(VCPKG_APPLOCAL_DEPS)
        #
        # Have CMake invoke itself to performa a local install for our test suite.
        #
        if(ENABLE_APP)
            add_custom_target(test_install
                ALL
                "${CMAKE_COMMAND}"
                -D CMAKE_INSTALL_CONFIG_NAME:string=$<CONFIG>
                -D CMAKE_INSTALL_PREFIX:string=$<TARGET_FILE_DIR:check_clamav>
                -P "${CMAKE_BINARY_DIR}/cmake_install.cmake"
                DEPENDS
                    check_clamav check_clamd check_fpu_endian
                    ClamAV::libclamav ClamAV::libfreshclam ClamAV::libunrar ClamAV::libunrar_iface ${LIBMSPACK}
                    clambc clamd clamdscan clamdtop clamscan clamsubmit clamconf freshclam-bin sigtool
            )
        else()
            add_custom_target(test_install
                ALL
                "${CMAKE_COMMAND}"
                -D CMAKE_INSTALL_CONFIG_NAME:string=$<CONFIG>
                -D CMAKE_INSTALL_PREFIX:string=$<TARGET_FILE_DIR:check_clamav>
                -P "${CMAKE_BINARY_DIR}/cmake_install.cmake"
                DEPENDS
                    check_clamav
                    ClamAV::libclamav ClamAV::libfreshclam ClamAV::libunrar ClamAV::libunrar_iface ClamAV::libmspack
            )
        endif()
    else()
        #
        # Generate GetLibs-$<CONFIG>.ctest which will collect all required DLL and EXE dependencies when `ctest` is run.
        #
        if(ENABLE_APP)
            set(GEN_SCRIPT [[
                # Collect runtime DLL dependencies for our libs and apps
                file(GET_RUNTIME_DEPENDENCIES
                    LIBRARIES
                        $<TARGET_FILE:ClamAV::libclamav>
                        $<TARGET_FILE:ClamAV::libfreshclam>
                    EXECUTABLES
                        $<TARGET_FILE:check_clamav>
                        $<TARGET_FILE:check_fpu_endian>
                        $<TARGET_FILE:check_clamd>
                        $<TARGET_FILE:clambc>
                        $<TARGET_FILE:clamd>
                        $<TARGET_FILE:clamdscan>
                        $<TARGET_FILE:clamdtop>
                        $<TARGET_FILE:clamscan>
                        $<TARGET_FILE:clamsubmit>
                        $<TARGET_FILE:clamconf>
                        $<TARGET_FILE:freshclam-bin>
                        $<TARGET_FILE:sigtool>
                    RESOLVED_DEPENDENCIES_VAR _r_deps
                    UNRESOLVED_DEPENDENCIES_VAR _u_deps
                    DIRECTORIES
                        $<TARGET_FILE_DIR:OpenSSL::SSL>
                        $<TARGET_FILE_DIR:OpenSSL::Crypto>
                        $<TARGET_FILE_DIR:ZLIB::ZLIB>
                        $<TARGET_FILE_DIR:BZip2::BZip2>
                        $<TARGET_FILE_DIR:PCRE2::pcre2>
                        $<TARGET_FILE_DIR:LibXml2::LibXml2>
                        $<TARGET_FILE_DIR:CURL::libcurl>
                        $<TARGET_FILE_DIR:JSONC::jsonc>
                    CONFLICTING_DEPENDENCIES_PREFIX CTEST_CONFLICTING_DEPENDENCIES
                )
                foreach(_file ${_r_deps})
                    string(TOLOWER ${_file} _file_lower)
                    if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                        message("Collecting DLL dependency: ${_file}")
                        file(COPY ${_file} DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                    endif()
                endforeach()

                # Collect our libs
                file(COPY $<TARGET_FILE:ClamAV::libclamav> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                if(NOT ENABLE_EXTERNAL_MSPACK)
                    file(COPY $<TARGET_FILE:ClamAV::libmspack> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                file(COPY $<TARGET_FILE:ClamAV::libfreshclam> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:ClamAV::libunrar> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:ClamAV::libunrar_iface> DESTINATION $<TARGET_FILE_DIR:check_clamav>)

                # Collect our apps
                file(COPY $<TARGET_FILE:check_fpu_endian> DESTINATION $<TARGET_FILE_DIR:check_fpu_endian>)
                file(COPY $<TARGET_FILE:check_clamd> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clambc> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clamd> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clamdscan> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clamdtop> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clamscan> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clamsubmit> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:clamconf> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:freshclam-bin> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:sigtool> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
            ]])
        else()
            # We don't have libfreshclam unit tests, so no need to check if ENABLE_LIBCLAMAV_ONLY is enabled.
            set(GEN_SCRIPT [[
                # Collect runtime DLL dependencies for our libs
                file(GET_RUNTIME_DEPENDENCIES
                    LIBRARIES
                        $<TARGET_FILE:ClamAV::libclamav>
                    EXECUTABLES
                        $<TARGET_FILE:check_clamav>
                    RESOLVED_DEPENDENCIES_VAR _r_deps
                    UNRESOLVED_DEPENDENCIES_VAR _u_deps
                    DIRECTORIES
                        $<TARGET_FILE_DIR:OpenSSL::SSL>
                        $<TARGET_FILE_DIR:OpenSSL::Crypto>
                        $<TARGET_FILE_DIR:ZLIB::ZLIB>
                        $<TARGET_FILE_DIR:BZip2::BZip2>
                        $<TARGET_FILE_DIR:PCRE2::pcre2>
                        $<TARGET_FILE_DIR:LibXml2::LibXml2>
                        $<TARGET_FILE_DIR:JSONC::jsonc>
                    CONFLICTING_DEPENDENCIES_PREFIX CTEST_CONFLICTING_DEPENDENCIES
                )
                foreach(_file ${_r_deps})
                    string(TOLOWER ${_file} _file_lower)
                    if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                        message("DEPENDENCY: ${_file}")
                        file(COPY ${_file} DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                    endif()
                endforeach()

                # Collect our libs
                file(COPY $<TARGET_FILE:ClamAV::libclamav> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                if(NOT ENABLE_EXTERNAL_MSPACK)
                    file(COPY $<TARGET_FILE:ClamAV::libmspack> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                file(COPY $<TARGET_FILE:ClamAV::libunrar> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                file(COPY $<TARGET_FILE:ClamAV::libunrar_iface> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
            ]])
        endif()

        file(GENERATE OUTPUT GetLibs-$<CONFIG>.ctest CONTENT ${GEN_SCRIPT})
        set_directory_properties(PROPERTIES TEST_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/Run-GetLibs.ctest)
    endif()
endif()
