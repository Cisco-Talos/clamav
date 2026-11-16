# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

set(SCAN_TARGETS
    ARCHIVE
    MAIL
    OLE2
    PDF
    HTML
    PE
    ELF
    SWF
    XMLDOCS
    HWP3)

set(DBLOAD_TARGETS
    CDB
    CFG
    CRB
    FP
    FTM
    HDB
    HSB
    IDB
    IGN
    IGN2
    LDB
    MDB
    MSB
    NDB
    PDB
    WDB
    YARA)

add_executable(clamav_scanmap_fuzzer)
target_sources(clamav_scanmap_fuzzer
    PRIVATE clamav_scanmap_fuzzer.cpp)
target_link_libraries(clamav_scanmap_fuzzer ClamAV::libclamav)
set_target_properties(clamav_scanmap_fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")

add_executable(clamav_scanfile_fuzzer)
target_sources(clamav_scanfile_fuzzer
    PRIVATE clamav_scanfile_fuzzer.cpp)
target_link_libraries(clamav_scanfile_fuzzer ClamAV::libclamav)
set_target_properties(clamav_scanfile_fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")

foreach(TARGET ${SCAN_TARGETS})
    add_executable(clamav_scanmap_${TARGET}_fuzzer)
    target_sources(clamav_scanmap_${TARGET}_fuzzer
        PRIVATE clamav_scanmap_fuzzer.cpp)
    target_compile_definitions(clamav_scanmap_${TARGET}_fuzzer PUBLIC CLAMAV_FUZZ_${TARGET})
    target_link_libraries(clamav_scanmap_${TARGET}_fuzzer ClamAV::libclamav)
    set_target_properties(clamav_scanmap_${TARGET}_fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")

    add_executable(clamav_scanfile_${TARGET}_fuzzer)
    target_sources(clamav_scanfile_${TARGET}_fuzzer
        PRIVATE clamav_scanfile_fuzzer.cpp)
    target_compile_definitions(clamav_scanfile_${TARGET}_fuzzer PUBLIC CLAMAV_FUZZ_${TARGET})
    target_link_libraries(clamav_scanfile_${TARGET}_fuzzer ClamAV::libclamav)
    set_target_properties(clamav_scanfile_${TARGET}_fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
endforeach()

foreach(TARGET ${DBLOAD_TARGETS})
    add_executable(clamav_dbload_${TARGET}_fuzzer)
    target_sources(clamav_dbload_${TARGET}_fuzzer
        PRIVATE clamav_dbload_fuzzer.cpp)
    target_compile_definitions(clamav_dbload_${TARGET}_fuzzer PUBLIC CLAMAV_FUZZ_${TARGET})
    target_link_libraries(clamav_dbload_${TARGET}_fuzzer ClamAV::libclamav)
    set_target_properties(clamav_dbload_${TARGET}_fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
endforeach()

if(ENABLE_UNRAR)
    # UnRAR casts the header type byte it reads to an enum without a range
    # check, which UBSan's enum check reports for any input with an unknown
    # type. On x86 it also loads words from unaligned addresses on purpose
    # (ALLOW_MISALIGNED), which the alignment check reports for ordinary
    # archives. That is how the library reads the format, not a defect to fuzz for.
    target_compile_options(clamunrar_static PRIVATE -fno-sanitize=enum -fno-sanitize=alignment)

    add_executable(clamav_unrar_iface_fuzzer)
    target_sources(clamav_unrar_iface_fuzzer
        PRIVATE clamav_unrar_iface_fuzzer.cpp)
    target_link_libraries(clamav_unrar_iface_fuzzer ClamAV::libunrar_iface_static ClamAV::libunrar_iface_iface)
    set_target_properties(clamav_unrar_iface_fuzzer PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")

    # The same target without the fuzzing engine, to replay inputs that once
    # failed. Each file in fuzz/regression/clamav_unrar_iface_fuzzer is a test.
    add_executable(clamav_unrar_iface_regression)
    target_sources(clamav_unrar_iface_regression
        PRIVATE
            clamav_unrar_iface_fuzzer.cpp
            standalone_fuzz_target_runner.cpp)
    target_link_libraries(clamav_unrar_iface_regression ClamAV::libunrar_iface_static ClamAV::libunrar_iface_iface)

    file(GLOB UNRAR_IFACE_REGRESSION_INPUTS CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/regression/clamav_unrar_iface_fuzzer/*)
    foreach(INPUT ${UNRAR_IFACE_REGRESSION_INPUTS})
        get_filename_component(INPUT_NAME ${INPUT} NAME)
        add_test(NAME unrar_iface_regression_${INPUT_NAME}
            COMMAND clamav_unrar_iface_regression ${INPUT})
        set_tests_properties(unrar_iface_regression_${INPUT_NAME} PROPERTIES
            TIMEOUT 30
            ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1;ASAN_OPTIONS=detect_leaks=1")
    endforeach()
endif()
