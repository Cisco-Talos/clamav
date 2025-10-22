# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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
            ClamAV::libclamav
            libcheck::check)
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
            ClamAV::libclamav
            ClamAV::common
            libcheck::check)
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
        ClamAV::libclamav
        ClamAV::common
        libcheck::check)
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
if(LLVM_FOUND)
    string(REPLACE "-l" "" LLVM_LIBRARIES_TRIMMED "${LLVM_LIBRARIES}")
    list(JOIN LLVM_LIBRARIES_TRIMMED "," LLVM_LIBS)
    list(JOIN LLVM_LIBRARY_DIRS "," LLVM_DIRS)
endif()

set(CVD_CERTS_DIR         ${CMAKE_SOURCE_DIR}/unit_tests/input/signing/verify)

if(WIN32)
    file(TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}                                     SOURCE)
    file(TO_NATIVE_PATH ${CMAKE_BINARY_DIR}                                     BUILD)
    file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}                             TMP)

    set(NEW_PATH "$<TARGET_FILE_DIR:check_clamav>;$ENV{PATH}")

    file(TO_NATIVE_PATH $<TARGET_FILE:OpenSSL::SSL>                             LIBSSL)
    file(TO_NATIVE_PATH $<TARGET_FILE:OpenSSL::Crypto>                          LIBCRYPTO)
    file(TO_NATIVE_PATH $<TARGET_FILE:ZLIB::ZLIB>                               LIBZ)
    file(TO_NATIVE_PATH $<TARGET_FILE:BZip2::BZip2>                             LIBBZ2)
    file(TO_NATIVE_PATH $<TARGET_FILE:PCRE2::pcre2>                             LIBPCRE2)
    file(TO_NATIVE_PATH $<TARGET_FILE:LibXml2::LibXml2>                         LIBXML2)
    if(NOT ENABLE_LIBCLAMAV_ONLY)
        # libcurl not used by libclamav and so is not defined in libclamav-only mode.
        file(TO_NATIVE_PATH $<TARGET_FILE:CURL::libcurl>                            LIBCURL)
    endif()
    file(TO_NATIVE_PATH $<TARGET_FILE:JSONC::jsonc>                             LIBJSONC)
    file(TO_NATIVE_PATH $<TARGET_FILE:PThreadW32::pthreadw32>                   LIBPTHREADW32)
    file(TO_NATIVE_PATH $<TARGET_FILE:ClamAV::win32_compat>                     LIBWIN32COMPAT)

    if(ENABLE_STATIC_LIB)
        file(TO_NATIVE_PATH $<TARGET_FILE:clamav_static>                        LIBCLAMAV)
        if (ENABLE_UNRAR)
            file(TO_NATIVE_PATH $<TARGET_FILE:clamunrar_iface_static>           LIBCLAMUNRARIFACE)
            file(TO_NATIVE_PATH $<TARGET_FILE:clamunrar_static>                 LIBCLAMUNRAR)
        endif()
    else()
        file(TO_NATIVE_PATH $<TARGET_FILE:clamav>                               LIBCLAMAV)
    endif()
    file(TO_NATIVE_PATH $<TARGET_FILE:${LIBMSPACK}>                             LIBCLAMMSPACK)
    file(TO_NATIVE_PATH $<TARGET_FILE:check_clamav>                             CHECK_CLAMAV)
    if(ENABLE_APP)
        file(TO_NATIVE_PATH $<TARGET_FILE:check_clamd>                          CHECK_CLAMD)
        file(TO_NATIVE_PATH $<TARGET_FILE:check_fpu_endian>                     CHECK_FPU_ENDIAN)

        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clambc.exe          CLAMBC)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamd.exe           CLAMD)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamdscan.exe       CLAMDSCAN)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamdtop.exe        CLAMDTOP)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamscan.exe        CLAMSCAN)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamsubmit.exe      CLAMSUBMIT)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/clamconf.exe        CLAMCONF)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/freshclam.exe       FRESHCLAM)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/sigtool.exe         SIGTOOL)
    endif()
    if(ENABLE_EXAMPLES)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/ex_scan_callbacks.exe EX_SCAN_CALLBACKS)
        file(TO_NATIVE_PATH $<TARGET_FILE_DIR:check_clamav>/ex_cl_cvdunpack.exe   EX_CL_CVDUNPACK)
    endif()

    # Convert the CVD_CERTS_DIR to a native path for Windows (replacing forward slashes with backslashes).
    file(TO_NATIVE_PATH ${CVD_CERTS_DIR} CVD_CERTS_DIR)
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

    set(NEW_PATH "$ENV{PATH}")

    set(LIBSSL             $<TARGET_FILE:OpenSSL::SSL>)
    set(LIBCRYPTO          $<TARGET_FILE:OpenSSL::Crypto>)
    set(LIBZ               $<TARGET_FILE:ZLIB::ZLIB>)
    set(LIBBZ2             $<TARGET_FILE:BZip2::BZip2>)
    set(LIBPCRE2           $<TARGET_FILE:PCRE2::pcre2>)
    set(LIBXML2            $<TARGET_FILE:LibXml2::LibXml2>)
    if(NOT ENABLE_LIBCLAMAV_ONLY)
        # libcurl not used by libclamav and so is not defined in libclamav-only mode.
        set(LIBCURL            $<TARGET_FILE:CURL::libcurl>)
    endif()
    set(LIBJSONC           $<TARGET_FILE:JSONC::jsonc>)
    if(Iconv_FOUND AND NOT Iconv_IS_BUILT_IN)
        set(LIBICONV           ${Iconv_LIBRARIES})
    endif()

    if(ENABLE_STATIC_LIB)
        set(LIBCLAMAV            $<TARGET_FILE:clamav_static>)
        if (ENABLE_UNRAR)
            set(LIBCLAMUNRARIFACE    $<TARGET_FILE:clamunrar_iface_static>)
            set(LIBCLAMUNRAR         $<TARGET_FILE:clamunrar_static>)
        endif()
    else()
        set(LIBCLAMAV          $<TARGET_FILE:clamav>)
    endif()
    set(LIBCLAMMSPACK          $<TARGET_FILE:${LIBMSPACK}>)
    set(CHECK_CLAMAV           $<TARGET_FILE:check_clamav>)
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
        if(ENABLE_EXAMPLES)
            set(EX_SCAN_CALLBACKS  $<TARGET_FILE:ex_scan_callbacks>)
            set(EX_CL_CVDUNPACK    $<TARGET_FILE:ex_cl_cvdunpack>)
        endif()
    endif()
endif()

set(ENVIRONMENT
    PYTHONTRACEMALLOC=1 VERSION=${PROJECT_VERSION}${VERSION_SUFFIX}
    SOURCE=${SOURCE} BUILD=${BUILD} TMP=${TMP}
    CK_FORK=no
    CK_DEFAULT_TIMEOUT=300
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
    DYLD_LIBRARY_PATH=${LD_LIBRARY_PATH}
    CVD_CERTS_DIR=${CVD_CERTS_DIR}
    PATH=${NEW_PATH}
    LIBSSL=${LIBSSL}
    LIBCRYPTO=${LIBCRYPTO}
    LIBZ=${LIBZ}
    LIBBZ2=${LIBBZ2}
    LIBPCRE2=${LIBPCRE2}
    LIBXML2=${LIBXML2}
    LIBCURL=${LIBCURL}
    LIBJSONC=${LIBJSONC}
    LIBICONV=${LIBICONV}
    LLVM_LIBS=${LLVM_LIBS}
    LLVM_DIRS=${LLVM_LIBRARY_DIRS}
    LIBPTHREADW32=${LIBPTHREADW32}
    LIBWIN32COMPAT=${LIBWIN32COMPAT}
    LIBCLAMAV=${LIBCLAMAV}
    LIBCLAMMSPACK=${LIBCLAMMSPACK}
    LIBCLAMUNRARIFACE=${LIBCLAMUNRARIFACE}
    LIBCLAMUNRAR=${LIBCLAMUNRAR}
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
    EX_SCAN_CALLBACKS=${EX_SCAN_CALLBACKS}
    EX_CL_CVDUNPACK=${EX_CL_CVDUNPACK}
)


list(APPEND ENVIRONMENT "OPENSSL_DIR=${OPENSSL_DIR}")
list(APPEND ENVIRONMENT "OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")
if(NOT MSVC)
    # Setting OPENSSL_LIBS caused failures in testing for Windows.
    # It's possible they require a different format or the .lib or .dll extensions.
    # For now, we'll only set this for non-Windows builds.
    list(APPEND ENVIRONMENT "OPENSSL_LIBS=${OPENSSL_LIBS}")
endif()
list(APPEND ENVIRONMENT "OPENSSL_LIB_DIR=${OPENSSL_LIB_DIR}")
list(APPEND ENVIRONMENT "CONFIGURATION=$<CONFIG>")

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

add_rust_test(NAME libclamav_rust
    SOURCE_DIRECTORY "${CMAKE_SOURCE_DIR}/libclamav_rust"
    BINARY_DIRECTORY "${CMAKE_BINARY_DIR}"
    PRECOMPILE_TESTS FALSE # Cannot precompile, because `sudo make install` will fail. See notes in FindRust.cmake.
)
set_property(TEST libclamav_rust PROPERTY ENVIRONMENT ${ENVIRONMENT})

if(ENABLE_APP)
    add_test(NAME clamscan COMMAND ${PythonTest_COMMAND};clamscan
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST clamscan PROPERTY ENVIRONMENT ${ENVIRONMENT})
    if(Valgrind_FOUND)
        add_test(NAME clamscan_valgrind COMMAND ${PythonTest_COMMAND};clamscan
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

if(ENABLE_EXAMPLES)
    add_test(NAME examples COMMAND ${PythonTest_COMMAND};examples
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TEST examples PROPERTY ENVIRONMENT ${ENVIRONMENT})
    if(Valgrind_FOUND)
        add_test(NAME examples_valgrind COMMAND ${PythonTest_COMMAND};examples
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_property(TEST examples_valgrind PROPERTY ENVIRONMENT ${ENVIRONMENT} VALGRIND=${Valgrind_EXECUTABLE})
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
                    POST_EXCLUDE_REGEXES
                        "[cC]:[\\/][wW][iI][nN][dD][oO][wW][sS]"
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
                file(COPY $<TARGET_FILE:ClamAV::libfreshclam> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                if ($<TARGET_EXISTS:ClamAV::libmspack>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ClamAV::libmspack>,ClamAV::libmspack,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                if ($<TARGET_EXISTS:ClamAV::libunrar>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ClamAV::libunrar>,ClamAV::libunrar,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                if ($<TARGET_EXISTS:ClamAV::libunrar_iface>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ClamAV::libunrar_iface>,ClamAV::libunrar_iface,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()

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

                # Collect example programs, if built with ENABLE_EXAMPLES=ON
                if ($<TARGET_EXISTS:ex_scan_callbacks>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ex_scan_callbacks>,ex_scan_callbacks,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                if ($<TARGET_EXISTS:ex_cl_cvdunpack>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ex_cl_cvdunpack>,ex_cl_cvdunpack,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
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
                    POST_EXCLUDE_REGEXES
                        "[cC]:[\\/][wW][iI][nN][dD][oO][wW][sS]"
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
                if ($<TARGET_EXISTS:ClamAV::libmspack>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ClamAV::libmspack>,ClamAV::libmspack,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                if ($<TARGET_EXISTS:ClamAV::libunrar>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ClamAV::libunrar>,ClamAV::libunrar,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                if ($<TARGET_EXISTS:ClamAV::libunrar_iface>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ClamAV::libunrar_iface>,ClamAV::libunrar_iface,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()

                # Collect example programs, if built with ENABLE_EXAMPLES=ON
                if ($<TARGET_EXISTS:ex_scan_callbacks>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ex_scan_callbacks>,ex_scan_callbacks,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
                if ($<TARGET_EXISTS:ex_cl_cvdunpack>)
                    file(COPY $<TARGET_FILE:$<IF:$<TARGET_EXISTS:ex_cl_cvdunpack>,ex_cl_cvdunpack,check_clamav>> DESTINATION $<TARGET_FILE_DIR:check_clamav>)
                endif()
            ]])
        endif()

        file(GENERATE OUTPUT GetLibs-$<CONFIG>.ctest CONTENT ${GEN_SCRIPT})
        set_directory_properties(PROPERTIES TEST_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/Run-GetLibs.ctest)
    endif()
endif()
