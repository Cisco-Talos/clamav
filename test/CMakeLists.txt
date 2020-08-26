# Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

#
# Assemble split files found in test/.split
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
)

if(ENABLE_UNRAR)
    set(TESTFILES ${TESTFILES}
        clam-v2.rar clam-v3.rar
    )
endif()

# Assemble split test file
function(assemble_testfile test_file)
    add_custom_command(OUTPUT ${test_file}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/assemble_testfile.py
            ${test_file}
            --build_dir ${CMAKE_CURRENT_BINARY_DIR}
            --split_dir ${CMAKE_CURRENT_SOURCE_DIR}/.split
        COMMENT "Assembling test file ${test_file} of ${original}")
    add_custom_target(tgt_${test_file} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
    #install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${test_file} DESTINATION ${CMAKE_INSTALL_BINDIR})
endfunction()

foreach(TESTFILE ${TESTFILES})
    assemble_testfile(${TESTFILE})
endforeach()
