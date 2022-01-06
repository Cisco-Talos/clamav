# Copyright (C) 2020-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

cmake_minimum_required( VERSION 3.12...3.13 )

include_directories(
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    $<TARGET_PROPERTY:ClamAV::libclamunrar_iface_iface,INTERFACE_INCLUDE_DIRECTORIES>
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

configure_file(version.h.in version.h)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DHAVE_STRUCT_TIMESPEC)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

# 3rd party libraries included in libclamav
add_library( regex OBJECT )
target_sources( regex
    PRIVATE
        regex/strlcpy.c
        regex/regcomp.c
        regex/regerror.c
        regex/regexec.c
        regex/regfree.c
    PUBLIC
        regex/cclass.h
        regex/cname.h
        regex/regex.h
        regex/regex2.h
        regex/utils.h )
target_include_directories( regex
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
set_target_properties(regex PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries( regex
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )

add_library( lzma_sdk OBJECT )
target_sources( lzma_sdk
    PRIVATE
        7z/7zAlloc.c
        7z/7zBuf.c
        7z/7zBuf2.c
        7z/7zCrc.c
        7z/7zCrcOpt.c
        7z/7zDec.c
        7z/7zFile.c
        7z/7zIn.c
        7z/7zStream.c
        7z/Bcj2.c
        7z/Bra.c
        7z/Bra86.c
        7z/BraIA64.c
        7z/CpuArch.c
        7z/Delta.c
        7z/Lzma2Dec.c
        7z/LzmaDec.c
        7z/Ppmd7.c
        7z/Ppmd7Dec.c
        7z/Xz.c
        7z/XzCrc64.c
        7z/XzDec.c
        7z/XzIn.c
    PUBLIC
        7z/7z.h
        7z/Xz.h
        7z/Alloc.h
        7z/7zFile.h
        7z/XzCrc64.h
        7z/RotateDefs.h
        7z/Types.h
        7z/Ppmd7.h
        7z/LzmaDec.h
        7z/Ppmd.h
        7z/Lzma2Dec.h
        7z/Delta.h
        7z/CpuArch.h
        7z/CpuArch.h
        7z/Bra.h
        7z/Bcj2.h
        7z/7zVersion.h
        7z/7zCrc.h
        7z/7zBuf.h
        7z/7zAlloc.h )
target_include_directories( lzma_sdk
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
set_target_properties(lzma_sdk PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries( lzma_sdk
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )

if(MAINTAINER_MODE)
    bison_target( yara_grammar
        yara_grammar.y ${CMAKE_CURRENT_SOURCE_DIR}/yara_grammar.c )
    flex_target( yara_lexer
        yara_lexer.l ${CMAKE_CURRENT_SOURCE_DIR}/yara_lexer.c )
    add_flex_bison_dependency(yara_lexer yara_grammar)
endif()

add_library( yara OBJECT )
target_sources( yara
    PRIVATE
        yara_compiler.c
        yara_exec.c
        yara_hash.c
        yara_parser.c
        yara_arena.c
        ${BISON_yara_grammar_OUTPUTS}
        ${FLEX_yara_lexer_OUTPUTS}
    PUBLIC
        yara_arena.h
        yara_compiler.h
        yara_clam.h
        yara_hash.h
        yara_exec.h
        yara_parser.h )

if(MAINTAINER_MODE)
    target_sources( yara
        PRIVATE
            ${BISON_yara_grammar_OUTPUTS}
            ${FLEX_yara_lexer_OUTPUTS} )
else()
    target_sources( yara
        PRIVATE
            yara_grammar.c
            yara_lexer.c )
endif()

target_include_directories( yara
    PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR} )
set_target_properties(yara PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")
target_link_libraries( yara
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )

add_library( tomsfastmath OBJECT )
target_sources( tomsfastmath
    PRIVATE
        tomsfastmath/addsub/fp_add.c
        tomsfastmath/addsub/fp_add_d.c
        tomsfastmath/addsub/fp_addmod.c
        tomsfastmath/addsub/fp_cmp.c
        tomsfastmath/addsub/fp_cmp_d.c
        tomsfastmath/addsub/fp_cmp_mag.c
        tomsfastmath/addsub/fp_sub.c
        tomsfastmath/addsub/fp_sub_d.c
        tomsfastmath/addsub/fp_submod.c
        tomsfastmath/addsub/s_fp_add.c
        tomsfastmath/addsub/s_fp_sub.c
        tomsfastmath/bin/fp_radix_size.c
        tomsfastmath/bin/fp_read_radix.c
        tomsfastmath/bin/fp_read_signed_bin.c
        tomsfastmath/bin/fp_read_unsigned_bin.c
        tomsfastmath/bin/fp_reverse.c
        tomsfastmath/bin/fp_s_rmap.c
        tomsfastmath/bin/fp_signed_bin_size.c
        tomsfastmath/bin/fp_to_signed_bin.c
        tomsfastmath/bin/fp_to_unsigned_bin.c
        tomsfastmath/bin/fp_toradix.c
        tomsfastmath/bin/fp_toradix_n.c
        tomsfastmath/bin/fp_unsigned_bin_size.c
        tomsfastmath/bit/fp_cnt_lsb.c
        tomsfastmath/bit/fp_count_bits.c
        tomsfastmath/bit/fp_div_2.c
        tomsfastmath/bit/fp_div_2d.c
        tomsfastmath/bit/fp_lshd.c
        tomsfastmath/bit/fp_mod_2d.c
        tomsfastmath/bit/fp_rshd.c
        tomsfastmath/divide/fp_div.c
        tomsfastmath/divide/fp_div_d.c
        tomsfastmath/divide/fp_mod.c
        tomsfastmath/divide/fp_mod_d.c
        tomsfastmath/exptmod/fp_2expt.c
        tomsfastmath/exptmod/fp_exptmod.c
        tomsfastmath/misc/fp_ident.c
        tomsfastmath/misc/fp_set.c
        tomsfastmath/mont/fp_montgomery_calc_normalization.c
        tomsfastmath/mont/fp_montgomery_reduce.c
        tomsfastmath/mont/fp_montgomery_setup.c
        tomsfastmath/mul/fp_mul.c
        tomsfastmath/mul/fp_mul_comba.c
        tomsfastmath/mul/fp_mul_2.c
        tomsfastmath/mul/fp_mul_2d.c
        tomsfastmath/mul/fp_mul_comba_12.c
        tomsfastmath/mul/fp_mul_comba_17.c
        tomsfastmath/mul/fp_mul_comba_20.c
        tomsfastmath/mul/fp_mul_comba_24.c
        tomsfastmath/mul/fp_mul_comba_28.c
        tomsfastmath/mul/fp_mul_comba_3.c
        tomsfastmath/mul/fp_mul_comba_32.c
        tomsfastmath/mul/fp_mul_comba_4.c
        tomsfastmath/mul/fp_mul_comba_48.c
        tomsfastmath/mul/fp_mul_comba_6.c
        tomsfastmath/mul/fp_mul_comba_64.c
        tomsfastmath/mul/fp_mul_comba_7.c
        tomsfastmath/mul/fp_mul_comba_8.c
        tomsfastmath/mul/fp_mul_comba_9.c
        tomsfastmath/mul/fp_mul_comba_small_set.c
        tomsfastmath/mul/fp_mul_d.c
        tomsfastmath/mul/fp_mulmod.c
        tomsfastmath/numtheory/fp_invmod.c
        tomsfastmath/sqr/fp_sqr.c
        tomsfastmath/sqr/fp_sqr_comba_12.c
        tomsfastmath/sqr/fp_sqr_comba_17.c
        tomsfastmath/sqr/fp_sqr_comba_20.c
        tomsfastmath/sqr/fp_sqr_comba_24.c
        tomsfastmath/sqr/fp_sqr_comba_28.c
        tomsfastmath/sqr/fp_sqr_comba_3.c
        tomsfastmath/sqr/fp_sqr_comba_32.c
        tomsfastmath/sqr/fp_sqr_comba_4.c
        tomsfastmath/sqr/fp_sqr_comba_48.c
        tomsfastmath/sqr/fp_sqr_comba_6.c
        tomsfastmath/sqr/fp_sqr_comba_64.c
        tomsfastmath/sqr/fp_sqr_comba_7.c
        tomsfastmath/sqr/fp_sqr_comba_8.c
        tomsfastmath/sqr/fp_sqr_comba_9.c
        tomsfastmath/sqr/fp_sqr_comba_generic.c
        tomsfastmath/sqr/fp_sqr_comba_small_set.c
        tomsfastmath/sqr/fp_sqrmod.c
    PUBLIC
        bignum.h
        bignum_fast.h )
target_include_directories( tomsfastmath
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
set_target_properties(tomsfastmath PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")

# Bytecode Runtime
add_library( bytecode_runtime OBJECT )
if(LLVM_FOUND)
    target_sources( bytecode_runtime
        PRIVATE
            c++/detect.cpp
            c++/ClamBCRTChecks.cpp
            c++/bytecode2llvm.cpp
            bytecode_priv.h
            bytecode.h )
    set_target_properties(bytecode_runtime PROPERTIES
        COMPILE_FLAGS "${WARNCXXFLAGS} ${CXX1XCXXFLAGS}")
else()
    target_sources( bytecode_runtime
        PRIVATE
            bytecode_nojit.c
            bytecode_priv.h
            bytecode.h )
    set_target_properties(bytecode_runtime PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}")
endif()
target_include_directories( bytecode_runtime
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries( bytecode_runtime
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )

# clamav clamav_obj
add_library( clamav_obj OBJECT )
target_sources( clamav_obj
    PRIVATE
        # Utils
        blob.c              blob.h
        conv.c              conv.h
        fpu.c               fpu.h
        hashtab.c           hashtab.h
        iowrap.c            iowrap.h
        json_api.c          json_api.h
        jsparse/textbuf.h
        others_common.c     others.h
        qsort.c
        sf_base64decode.c   sf_base64decode.h
        str.c               str.h
        strlcat.c
        table.c             table.h
        text.c              text.h
        uniq.c              uniq.h
        www.c               www.h
        # Utils Disasm
        disasm-common.h     disasm.c    disasm.h    disasmpriv.h
        # Matcher
        filtering.c         filtering.h
        matcher-ac.c        matcher-ac.h
        matcher-bm.c        matcher-bm.h
        matcher-byte-comp.c matcher-byte-comp.h
        matcher-hash.c      matcher-hash.h
        matcher-pcre.c      matcher-pcre.h
        matcher.c           matcher.h
        regex_pcre.c        regex_pcre.h
        # Database
        cvd.c               cvd.h
        dconf.c             dconf.h
        dsig.c              dsig.h
        readdb.c            readdb.h
        # Core
        cache.c             cache.h
        crtmgr.c            crtmgr.h
        crypto.c
        default.h
        filetypes_int.h     filetypes.c     filetypes.h
        fmap.c              fmap.h
        mpool.c             mpool.h
        others.c
        perflogging.c       perflogging.h
        scanners.c          scanners.h
        textdet.c           textdet.h
        version.c
        # file normalization (for matching)
        htmlnorm.c          htmlnorm.h
        jsparse/generated/keywords.h
        jsparse/generated/operators.h
        jsparse/js-norm.c
        jsparse/js-norm.h
        jsparse/lexglobal.h
        textnorm.c          textnorm.h
        # heuristics (hardcoded exploit/malware detection)
        partition_intersection.c partition_intersection.h
        special.c           special.h
        # clamav statistics
        hostid_internal.c   hostid_internal.h
        stats_json.c        stats_json.h
        stats.c             stats.h
        # clamav bytecode support
        bcfeatures.h
        builtin_bytecodes.h
        bytecode_api_decl.c
        bytecode_api_impl.h
        bytecode_api.c      bytecode_api.h
        bytecode_detect.c   bytecode_detect.h
        bytecode_hooks.h
        bytecode_priv.h
        bytecode_vm.c
        bytecode.c          bytecode.h
        events.c            events.h
        type_desc.h
        # utils: compression
        7z_iface.c          7z_iface.h
        explode.c           explode.h
        inffixed64.h
        inflate64_priv.h    inflate64.c     inflate64.h
        lzma_iface.c        lzma_iface.h
        lzw/lzwdec.c        lzw/lzwdec.h
        xz_iface.c          xz_iface.h
        # utils: encryption
        arc4.c              arc4.h
        rijndael.c          rijndael.h
        # utils: text conversion
        encoding_aliases.h
        entconv.c           entconv.h
        entitylist.h
        # Data-Loss-Prevention
        dlp.c               dlp.h
        #
        # FILE PARSERS
        #
        # autoit
        autoit.c            autoit.h
        # binhex
        binhex.c            binhex.h
        # cpio
        cpio.c              cpio.h
        # install shield
        ishield.c           ishield.h
        # cab / chm
        libmspack.c         libmspack.h
        # msszdd
        msexpand.c          msexpand.h
        # nsis
        nsis/bzlib_private.h
        nsis/bzlib.c
        nsis/infblock.c
        nsis/nsis_bzlib.h
        nsis/nsis_zconf.h
        nsis/nsis_zlib.h
        nsis/nsis_zutil.h
        nsis/nulsft.c       nsis/nulsft.h
        # office docs
        hwp.c               hwp.h
        msdoc.c             msdoc.h
        msxml_parser.c      msxml_parser.h
        msxml.c             msxml.h
        ole2_extract.c      ole2_extract.h
        xlm_extract.c       xlm_extract.h
        ooxml.c             ooxml.h
        rtf.c               rtf.h
        vba_extract.c       vba_extract.h
        # executables
        asn1.c              asn1.h
        elf.c               elf.h
        execs.c             execs.h
        macho.c             macho.h
        pe_icons.c          pe_icons.h
        pe_structs.h
        pe.c                pe.h
        rebuildpe.c         rebuildpe.h
        # executable unpackers
        aspack.c            aspack.h
        fsg.c               fsg.h
        mew.c               mew.h
        packlibs.c          packlibs.h
        petite.c            petite.h
        spin.c              spin.h
        unsp.c              unsp.h
        upack.c             upack.h
        upx.c               upx.h
        wwunpack.c          wwunpack.h
        yc.c                yc.h
        # mail & phishing
        iana_cctld.h
        iana_tld.h
        line.c              line.h
        mbox.c              mbox.h
        message.c           message.h
        phish_domaincheck_db.c phish_domaincheck_db.h
        phish_whitelist.c   phish_whitelist.h
        phishcheck.c        phishcheck.h
        regex_list.c        regex_list.h
        regex_suffix.c      regex_suffix.h
        # sis
        sis.c               sis.h
        # tnef
        tnef.c              tnef.h
        # uuencode
        uuencode.c          uuencode.h
        # swf (flash)
        swf.c               swf.h
        # pdf
        pdf.c               pdf.h
        pdfng.c
        pdfdecode.c         pdfdecode.h
        # xdp
        xdp.c               xdp.h
        # ARJ archive
        unarj.c             unarj.h
        # TAR archive
        is_tar.c            is_tar.h
        untar.c             untar.h
        # ZIP archive
        unzip.c             unzip.h
        # DMG archive
        adc.c               adc.h
        dmg.c               dmg.h
        # XAR archive
        xar.c               xar.h
        # EGG archive
        egg.c               egg.h
        # Master Boot Record partition
        mbr.c               mbr.h
        # GUID Parition Table partition
        gpt.c               gpt.h
        # Apple Partition Map partition
        apm.c               apm.h
        # HFS+ partition
        hfsplus.c           hfsplus.h
        # iso9660 partition
        iso9660.c           iso9660.h
        # OpenIOC
        openioc.c           openioc.h
        # JPEG image format checker
        jpeg.c              jpeg.h
        # PNG image format checker
        png.c               png.h
        # TIFF image format checker
        tiff.c              tiff.h
        # GIF image format checker
        gif.c               gif.h
    PUBLIC
        clamav.h )

if(WIN32)
    target_sources( clamav_obj PRIVATE libclamav_main.c )
endif()

target_include_directories( clamav_obj
    PRIVATE   ${CMAKE_BINARY_DIR} ${JSONC_INCLUDE_DIRS}
    PUBLIC    ${CMAKE_CURRENT_SOURCE_DIR}
    INTERFACE ${CMAKE_BINARY_DIR} )
target_link_libraries( clamav_obj
    PUBLIC
        regex
        lzma_sdk
        yara
        tomsfastmath
        bytecode_runtime
        ClamAV::libmspack
        ClamAV::libclamunrar_iface_iface
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        BZip2::BZip2
        PCRE2::pcre2
        LibXml2::LibXml2
        JSONC::jsonc )
if (WIN32)
    target_link_libraries( clamav_obj
        PUBLIC
            PThreadW32::pthreadw32
            ClamAV::win32_compat
            wsock32 ws2_32 )
else()
    target_link_libraries( clamav_obj
        PUBLIC
            Threads::Threads
            Iconv::Iconv
            ${CMAKE_DL_LIBS}
            m )
endif()
set_target_properties(clamav_obj PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")

if(ENABLE_SHARED_LIB)
    # The clamav shared library.
    add_library( clamav SHARED )
    set_target_properties(clamav PROPERTIES
        VERSION ${LIBCLAMAV_VERSION}
        SOVERSION ${LIBCLAMAV_SOVERSION})
    target_sources( clamav
        PUBLIC
            clamav.h )
    target_link_libraries( clamav
        PUBLIC
            clamav_obj
            regex
            lzma_sdk
            yara
            tomsfastmath
            bytecode_runtime
            ClamAV::libmspack
            ClamAV::libclamunrar_iface_iface
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
            BZip2::BZip2
            PCRE2::pcre2
            LibXml2::LibXml2
            JSONC::jsonc )
    set_target_properties(clamav PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}"
        VERSION ${LIBCLAMAV_VERSION} SOVERSION ${LIBCLAMAV_SOVERSION})
    if(WIN32)
        set_target_properties(clamav PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    else()
        target_link_libraries( clamav PUBLIC Iconv::Iconv )
    endif()
    if(WIN32)
        install(TARGETS clamav DESTINATION ${CMAKE_INSTALL_PREFIX})
    else()
        install(TARGETS clamav DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()

    if(LLVM_FOUND)
        target_link_directories( clamav PRIVATE ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( clamav PRIVATE ${LLVM_LIBRARIES} )
    endif()

    add_library( ClamAV::libclamav ALIAS clamav )
endif()

if(ENABLE_STATIC_LIB)
    # The clamav static library.
    add_library(clamav_static STATIC)
    target_sources(clamav_static
        PUBLIC
            clamav.h )
    target_link_libraries(clamav_static
        PUBLIC
            clamav_obj
            regex
            lzma_sdk
            yara
            tomsfastmath
            bytecode_runtime
            ClamAV::libmspack
            ClamAV::libclamunrar_iface_iface
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
            BZip2::BZip2
            PCRE2::pcre2
            LibXml2::LibXml2
            JSONC::jsonc )
    if(NOT WIN32)
        target_link_libraries( clamav PUBLIC Iconv::Iconv )
    endif()
    set_target_properties(clamav_static PROPERTIES
        ARCHIVE_OUTPUT_NAME clamav_static
        COMPILE_FLAGS       "${WARNCFLAGS}"
        VERSION ${LIBCLAMAV_VERSION} SOVERSION ${LIBCLAMAV_SOVERSION})
    target_compile_definitions(clamav_static PUBLIC clamav_staticLIB)
    if(WIN32)
        install(TARGETS clamav_static DESTINATION ${CMAKE_INSTALL_PREFIX})
    else()
        install(TARGETS clamav_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()

    add_library( ClamAV::libclamav_static ALIAS clamav_static )
endif()

install(
    FILES
        clamav.h
        ${CMAKE_BINARY_DIR}/clamav-types.h
        ${CMAKE_BINARY_DIR}/clamav-version.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
