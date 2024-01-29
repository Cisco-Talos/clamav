# Copyright (C) 2020-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Assemble xor'ed test files that might otherwise be detected by:
# - clamav.hdb
# - daily.cvd
# - another antivirus (E.g. heuristic detection of broken or packed PE files)
#
set(TESTFILES
    clam.cab
    clam.exe
    clam.zip
    clam.arj
    clam.exe.rtf
    clam.exe.szdd
    clam.tar.gz
    clam.chm
    clam.sis
    clam-aspack.exe
    clam-pespin.exe
    clam-upx.exe
    clam-fsg.exe
    clam-mew.exe
    clam-nsis.exe
    clam-petite.exe
    clam-upack.exe
    clam-wwpack.exe
    clam.pdf
    clam.mail
    clam.ppt
    clam.tnef
    clam.ea05.exe
    clam.ea06.exe
    clam.d64.zip
    clam.exe.mbox.base64
    clam.exe.mbox.uu
    clam.exe.binhex
    clam.ole.doc
    clam.impl.zip
    clam.exe.html
    clam.bin-be.cpio
    clam.bin-le.cpio
    clam.newc.cpio
    clam.odc.cpio
    clam-yc.exe
    clam_IScab_int.exe
    clam_IScab_ext.exe
    clam_ISmsi_int.exe
    clam_ISmsi_ext.exe
    clam.7z
    clam_cache_emax.tgz
    clam.iso
    clamjol.iso
    clam.exe.bz2
    clam.bz2.zip
    clam.exe_and_mail.tar.gz
    clam.exe.2007.one
    clam.exe.2010.one
    clam.exe.webapp-export.one
)

if(ENABLE_UNRAR)
    set(TESTFILES ${TESTFILES}
        clam-v2.rar clam-v3.rar
    )
endif()

add_custom_target(tgt_clamav_hdb_scanfiles ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/clamav_hdb_scanfiles)

# Decrypt test file
function(decrypt_testfile test_file)
    add_custom_command(OUTPUT clamav_hdb_scanfiles/${test_file}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/xor_testfile.py
                --in_file ${CMAKE_CURRENT_SOURCE_DIR}/clamav_hdb_scanfiles/${test_file}.xor
                --out_file ${CMAKE_CURRENT_BINARY_DIR}/clamav_hdb_scanfiles/${test_file}
        COMMENT "Decrypting test file ${test_file}...")
    add_custom_target(tgt_${test_file} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/clamav_hdb_scanfiles/${test_file})
    ADD_DEPENDENCIES(tgt_${test_file} tgt_clamav_hdb_scanfiles)
endfunction()

foreach(TESTFILE ${TESTFILES})
    decrypt_testfile(${TESTFILE})
endforeach()
