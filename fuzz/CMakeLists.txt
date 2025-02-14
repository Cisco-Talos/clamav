# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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
