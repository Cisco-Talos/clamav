
#
# man pages
#
# .1 files
configure_file(man/clamscan.1.in            man/clamscan.1)
configure_file(man/freshclam.1.in           man/freshclam.1)
configure_file(man/sigtool.1.in             man/sigtool.1)
configure_file(man/clamdscan.1.in           man/clamdscan.1)
configure_file(man/clamconf.1.in            man/clamconf.1)
configure_file(man/clamdtop.1.in            man/clamdtop.1)
configure_file(man/clamsubmit.1.in          man/clamsubmit.1)
configure_file(man/clambc.1.in              man/clambc.1)
# .5 files
configure_file(man/clamd.conf.5.in          man/clamd.conf.5)
configure_file(man/clamav-milter.conf.5.in  man/clamav-milter.conf.5)
configure_file(man/freshclam.conf.5.in      man/freshclam.conf.5)
# .8 files
configure_file(man/clamd.8.in               man/clamd.8)
configure_file(man/clamav-milter.8.in       man/clamav-milter.8)
if(LINUX)
    configure_file(man/clamonacc.8.in           man/clamonacc.8)
endif()

set(MAN1_FILES
    man/clamscan.1
    man/freshclam.1
    man/sigtool.1
    man/clamdscan.1
    man/clamconf.1
    man/clamdtop.1
    man/clamsubmit.1
    man/clambc.1)
foreach(m IN LISTS MAN1_FILES)
    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${m}
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/man/man1)
endforeach()

set(MAN5_FILES
    man/clamd.conf.5
    man/clamav-milter.conf.5
    man/freshclam.conf.5)
foreach(m IN LISTS MAN5_FILES)
    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${m}
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/man/man5)
endforeach()

set(MAN8_FILES
    man/clamd.8
    man/clamav-milter.8)
foreach(m IN LISTS MAN8_FILES)
    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${m}
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/man/man8)
endforeach()

if(LINUX)
    # Also install Linux-only manpage
    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/man/clamonacc.8
        DESTINATION
            ${CMAKE_INSTALL_PREFIX}/share/man/man8)
endif()

if(ENABLE_DOXYGEN)
    #
    # clamav.h doxygen docs
    #
    find_package(Doxygen REQUIRED)

    set(DOXYGEN_GENERATE_HTML       YES)
    set(DOXYGEN_GENERATE_MAN        NO)
    set(DOXYGEN_OUTPUT_DIRECTORY    ${CMAKE_CURRENT_BINARY_DIR})

    set(EXTRACT_ALL                 YES)
    set(HIDE_UNDOC_MEMBERS          YES)
    set(JAVADOC_AUTOBRIEF           YES)
    set(OPTIMIZE_OUTPUT_FOR_C       YES)
    set(FULL_PATH_NAMES             NO)
    set(GENERATE_LATEX              NO)

    doxygen_add_docs(doxygen
        ${CMAKE_SOURCE_DIR}/libclamav/clamav.h
        ${CMAKE_SOURCE_DIR}/libfreshclam/libfreshclam.h
        COMMENT "Generate html documentation"
    )

    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
        DESTINATION ${CMAKE_INSTALL_DOCDIR}
        COMPONENT "docs" OPTIONAL)
endif()
