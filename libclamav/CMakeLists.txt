# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

include_directories(
    ${LIBXML2_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    $<TARGET_PROPERTY:ClamAV::libunrar_iface_iface,INTERFACE_INCLUDE_DIRECTORIES>
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

configure_file(version.h.in version.h)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)

    # Windows compatibility headers
    include_directories(${CMAKE_SOURCE_DIR}/win32/compat)
endif()

add_definitions(-DTHIS_IS_LIBCLAMAV)

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
set_target_properties( regex PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( regex
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )
if(WIN32)
    target_link_libraries( regex PRIVATE ClamAV::win32_compat )
endif()

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
set_target_properties( lzma_sdk PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( lzma_sdk
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )
if(WIN32)
    target_link_libraries( lzma_sdk PRIVATE ClamAV::win32_compat )
endif()

if(MAINTAINER_MODE)
    bison_target( yara_grammar
        yara_grammar.y ${CMAKE_CURRENT_SOURCE_DIR}/yara_grammar.c )
    flex_target( yara_lexer
        yara_lexer.l ${CMAKE_CURRENT_SOURCE_DIR}/yara_lexer.c )
    add_flex_bison_dependency( yara_lexer yara_grammar )
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
set_target_properties( yara PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}" )
target_link_libraries( yara
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )
if(WIN32)
    target_link_libraries( yara PRIVATE ClamAV::win32_compat )
endif()

# Bytecode Runtime
add_library( bytecode_runtime OBJECT )
if(LLVM_FOUND)
    target_sources( bytecode_runtime
        PRIVATE
            c++/detect.cpp
            c++/bytecode2llvm.cpp
            bytecode_priv.h
            bytecode.h )
    set_target_properties( bytecode_runtime PROPERTIES
        COMPILE_FLAGS "${WARNCXXFLAGS} ${CXX1XCXXFLAGS}" )
    target_compile_definitions( bytecode_runtime PRIVATE -D LLVM_VERSION=${LLVM_VERSION} )
    target_include_directories( bytecode_runtime PRIVATE ${LLVM_INCLUDE_DIRS} )
else()
    target_sources( bytecode_runtime
        PRIVATE
            bytecode_nojit.c
            bytecode_priv.h
            bytecode.h )
    set_target_properties( bytecode_runtime PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}" )
endif()
target_include_directories( bytecode_runtime
    PRIVATE ${CMAKE_BINARY_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries( bytecode_runtime
    PRIVATE
        PCRE2::pcre2
        JSONC::jsonc )
if(WIN32)
    target_link_libraries( bytecode_runtime PRIVATE ClamAV::win32_compat )
endif()

# not using an object library for the sake of Xcode compatibility
# See: https://cmake.org/pipermail/cmake/2016-May/063479.html
set(LIBCLAMAV_SOURCES
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
    matcher-hash.c      matcher-hash.h      matcher-hash-types.h
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
    scan_layer.c        scan_layer.h
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
    phish_allow_list.c  phish_allow_list.h
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
    # GUID Partition Table partition
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
    # UDF partition
    udf.c               udf.h
)

if(ENABLE_SHARED_LIB)
    # The clamav shared library.
    add_library( clamav SHARED )
    set_target_properties( clamav PROPERTIES
        VERSION ${LIBCLAMAV_VERSION}
        SOVERSION ${LIBCLAMAV_SOVERSION}
        LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libclamav.map)
    target_sources( clamav
        PRIVATE
            ${LIBCLAMAV_SOURCES}
        PUBLIC
            clamav.h )
    if(WIN32)
        target_sources( clamav PRIVATE libclamav_main.c )
    endif()

    target_include_directories( clamav
        PRIVATE   ${CMAKE_BINARY_DIR} ${JSONC_INCLUDE_DIRS}
        PUBLIC    ${CMAKE_CURRENT_SOURCE_DIR}
        INTERFACE ${CMAKE_BINARY_DIR} )

    target_link_libraries( clamav
        PUBLIC
            regex
            lzma_sdk
            yara
            bytecode_runtime
            ${LIBMSPACK}
            ClamAV::libclamav_rust
            ClamAV::libunrar_iface_iface
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
            BZip2::BZip2
            PCRE2::pcre2
            LibXml2::LibXml2
            JSONC::jsonc )

    if(WIN32)
        target_link_libraries( clamav
            PUBLIC
                PThreadW32::pthreadw32
                ClamAV::win32_compat
                wsock32 ws2_32 bcrypt )
    else()
        target_link_libraries( clamav
            PUBLIC
                Threads::Threads
                Iconv::Iconv
                ${CMAKE_DL_LIBS}
                m )
    endif()

    if(APPLE)
        target_link_libraries( clamav
            PUBLIC
                ${APPLE_CORE_FOUNDATION} )
    endif()

    set_target_properties( clamav PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}"
        VERSION ${LIBCLAMAV_VERSION} SOVERSION ${LIBCLAMAV_SOVERSION} )

    if (APPLE AND CLAMAV_SIGN_FILE)
        set_target_properties( clamav PROPERTIES
            XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY}
            XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEVELOPMENT_TEAM_ID}
        )
    endif()

    if(WIN32)
        set_target_properties( clamav PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON )
    else()
        target_link_libraries( clamav PUBLIC Iconv::Iconv )
    endif()
    if(UNIX AND NOT APPLE AND NOT AIX)
        target_link_options( clamav PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libclamav.map")
        if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
            # Solaris 11.4 linker supports a subset of GNU ld version scripts, but requires a special option to enable
            target_link_options( clamav PRIVATE "-Wl,-z,gnu-version-script-compat")
        endif()
    endif()
    install( TARGETS clamav COMPONENT libraries )
    if(WIN32)
	    install( FILES $<TARGET_PDB_FILE:clamav> TYPE BIN OPTIONAL COMPONENT libraries )
        if(ENABLE_WINDOWS_INSTALL_THIRDPARTY_DEPENDENCIES)
            # Also install shared library (DLL) dependencies
            install( CODE [[
                file(GET_RUNTIME_DEPENDENCIES
                    LIBRARIES
                        $<TARGET_FILE:ClamAV::libclamav>
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
                )
                foreach(_file ${_r_deps})
                    string(TOLOWER ${_file} _file_lower)
                    if(NOT ${_file_lower} MATCHES "c:[\\/]windows[\\/]system32.*")
                        file(INSTALL
                            DESTINATION "${CMAKE_INSTALL_PREFIX}"
                            TYPE SHARED_LIBRARY
                            FOLLOW_SYMLINK_CHAIN
                            FILES "${_file}"
                        )
                    endif()
                endforeach()
                #message("UNRESOLVED_DEPENDENCIES_VAR: ${_u_deps}")
                ]]
                COMPONENT libraries )
        endif()
    endif()

    if(LLVM_FOUND)
        target_link_directories( clamav PUBLIC ${LLVM_LIBRARY_DIRS} )
        target_link_libraries( clamav PUBLIC ${LLVM_LIBRARIES} )
    endif()

    add_library( ClamAV::libclamav ALIAS clamav )
endif()

if(ENABLE_STATIC_LIB)
    # The clamav static library.
    add_library( clamav_static STATIC)
    target_sources( clamav_static
        PRIVATE
            ${LIBCLAMAV_SOURCES}
        PUBLIC
            clamav.h )
    if(WIN32)
        target_sources( clamav_static PRIVATE libclamav_main.c )
    endif()

    target_include_directories( clamav_static
        PRIVATE   ${CMAKE_BINARY_DIR} ${JSONC_INCLUDE_DIRS}
        PUBLIC    ${CMAKE_CURRENT_SOURCE_DIR}
        INTERFACE ${CMAKE_BINARY_DIR} )

    target_link_libraries( clamav_static
        PUBLIC
            regex
            lzma_sdk
            yara
            bytecode_runtime
            ${LIBMSPACK}
            ClamAV::libclamav_rust
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
            BZip2::BZip2
            PCRE2::pcre2
            LibXml2::LibXml2
            JSONC::jsonc )
        if (ENABLE_UNRAR)
            target_link_libraries( clamav_static PUBLIC ClamAV::libunrar_iface_static ClamAV::libunrar_iface_iface)
        endif()

    if (WIN32)
        target_link_libraries( clamav_static
            PUBLIC
                PThreadW32::pthreadw32
                ClamAV::win32_compat
                wsock32 ws2_32 bcrypt )
    else()
        target_link_libraries( clamav_static
            PUBLIC
                Threads::Threads
                Iconv::Iconv
                ${CMAKE_DL_LIBS}
                m )
    endif()

    if(APPLE)
        target_link_libraries( clamav_static
            PUBLIC
                ${APPLE_CORE_FOUNDATION} )
    endif()

    set_target_properties( clamav_static PROPERTIES
        ARCHIVE_OUTPUT_NAME clamav_static
        COMPILE_FLAGS       "${WARNCFLAGS}"
        VERSION ${LIBCLAMAV_VERSION} SOVERSION ${LIBCLAMAV_SOVERSION} )
    target_compile_definitions( clamav_static PUBLIC clamav_staticLIB )
    install( TARGETS clamav_static COMPONENT libraries )

    add_library( ClamAV::libclamav_static ALIAS clamav_static )
    if(NOT ENABLE_SHARED_LIB)
        add_library( ClamAV::libclamav ALIAS clamav_static )
    endif()
endif()

install(
    FILES
        clamav.h
        ${CMAKE_BINARY_DIR}/clamav-types.h
        ${CMAKE_BINARY_DIR}/clamav-version.h
    TYPE INCLUDE
    COMPONENT libraries)
