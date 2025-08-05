# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Assemble xor'ed test files that might otherwise be detected by:
# - clamav.hdb
# - daily.cvd
# - another antivirus (E.g. heuristic detection of broken or packed PE files)
#
set(ENCRYPTED_TESTFILES
    clamav_hdb_scanfiles/clam.cab
    clamav_hdb_scanfiles/clam.exe
    clamav_hdb_scanfiles/clam.zip
    clamav_hdb_scanfiles/clam.arj
    clamav_hdb_scanfiles/clam.exe.rtf
    clamav_hdb_scanfiles/clam.exe.szdd
    clamav_hdb_scanfiles/clam.tar.gz
    clamav_hdb_scanfiles/clam.chm
    clamav_hdb_scanfiles/clam.sis
    clamav_hdb_scanfiles/clam-aspack.exe
    clamav_hdb_scanfiles/clam-pespin.exe
    clamav_hdb_scanfiles/clam-upx.exe
    clamav_hdb_scanfiles/clam-fsg.exe
    clamav_hdb_scanfiles/clam-mew.exe
    clamav_hdb_scanfiles/clam-nsis.exe
    clamav_hdb_scanfiles/clam-petite.exe
    clamav_hdb_scanfiles/clam-upack.exe
    clamav_hdb_scanfiles/clam-wwpack.exe
    clamav_hdb_scanfiles/clam.pdf
    clamav_hdb_scanfiles/clam.mail
    clamav_hdb_scanfiles/clam.ppt
    clamav_hdb_scanfiles/clam.tnef
    clamav_hdb_scanfiles/clam.ea05.exe
    clamav_hdb_scanfiles/clam.ea06.exe
    clamav_hdb_scanfiles/clam.d64.zip
    clamav_hdb_scanfiles/clam.exe.mbox.base64
    clamav_hdb_scanfiles/clam.exe.mbox.uu
    clamav_hdb_scanfiles/clam.exe.binhex
    clamav_hdb_scanfiles/clam.ole.doc
    clamav_hdb_scanfiles/clam.impl.zip
    clamav_hdb_scanfiles/clam.exe.html
    clamav_hdb_scanfiles/clam.bin-be.cpio
    clamav_hdb_scanfiles/clam.bin-le.cpio
    clamav_hdb_scanfiles/clam.newc.cpio
    clamav_hdb_scanfiles/clam.odc.cpio
    clamav_hdb_scanfiles/clam-yc.exe
    clamav_hdb_scanfiles/clam_IScab_int.exe
    clamav_hdb_scanfiles/clam_IScab_ext.exe
    clamav_hdb_scanfiles/clam_ISmsi_int.exe
    clamav_hdb_scanfiles/clam_ISmsi_ext.exe
    clamav_hdb_scanfiles/clam.7z
    clamav_hdb_scanfiles/clam_cache_emax.tgz
    clamav_hdb_scanfiles/clam.iso
    clamav_hdb_scanfiles/clamjol.iso
    clamav_hdb_scanfiles/clam.exe.bz2
    clamav_hdb_scanfiles/clam.bz2.zip
    clamav_hdb_scanfiles/clam.exe_and_mail.tar.gz
    clamav_hdb_scanfiles/clam.exe.2007.one
    clamav_hdb_scanfiles/clam.exe.2010.one
    clamav_hdb_scanfiles/clam.exe.webapp-export.one
    clamav_hdb_scanfiles/clam.split.oneseg.zip
    signing/sign/signing-test.key
)

if(ENABLE_UNRAR)
    set(ENCRYPTED_TESTFILES ${ENCRYPTED_TESTFILES}
        clamav_hdb_scanfiles/clam-v2.rar
        clamav_hdb_scanfiles/clam-v3.rar
    )
endif()

add_custom_target(tgt_build_unit_tests_directories ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/clamav_hdb_scanfiles
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/signing/sign
)

# Decrypt test file
function(decrypt_testfile test_file)
    add_custom_command(OUTPUT ${test_file}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/xor_testfile.py
                --in_file ${CMAKE_CURRENT_SOURCE_DIR}/${test_file}.xor
                --out_file ${CMAKE_CURRENT_BINARY_DIR}/${test_file}
        COMMENT "Decrypting test file ${test_file}...")
    # Replace / with _ in test_file to make it a valid target name
    string(REPLACE "/" "_" test_file_tgt ${test_file})
    add_custom_target(tgt_${test_file_tgt} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
    ADD_DEPENDENCIES(tgt_${test_file_tgt} tgt_build_unit_tests_directories)
endfunction()

foreach(TESTFILE ${ENCRYPTED_TESTFILES})
    decrypt_testfile(${TESTFILE})
endforeach()
