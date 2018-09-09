#!/bin/sh
#
#       Compilation scripts initialization for the OS/400 implementation.
#
#       See Copyright for the status of this software.
#
#       Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
#


case "${SCRIPTDIR}" in
/*)     ;;
*)      SCRIPTDIR="`pwd`/${SCRIPTDIR}"
esac

while true
do      case "${SCRIPTDIR}" in
        */.)    SCRIPTDIR="${SCRIPTDIR%/.}";;
        *)      break;;
        esac
done

#  The script directory is supposed to be in $TOPDIR/os400.

TOPDIR=`dirname "${SCRIPTDIR}"`
export SCRIPTDIR TOPDIR


setenv()

{
        #       Define and export.

        eval ${1}="${2}"
        export ${1}
}


################################################################################
#
#                       Tunable configuration parameters.
#
################################################################################

setenv TARGETLIB        'LIBXML2'       # Target OS/400 program library.
setenv STATBNDDIR       'LIBXML2_A'     # Static binding directory.
setenv DYNBNDDIR        'LIBXML2'       # Dynamic binding directory.
setenv SRVPGM           "LIBXML2"       # Service program.
setenv TGTCCSID         '500'           # Target CCSID of objects.
setenv DEBUG            '*ALL'          # Debug level.
setenv OPTIMIZE         '10'            # Optimisation level.
setenv OUTPUT           '*NONE'         # Compilation output option.
setenv TGTRLS           'V6R1M0'        # Target OS release.
setenv IFSDIR           '/libxml2'      # Installation IFS directory.


################################################################################
#
#                       Conditional compilation parameters.
#
################################################################################

setenv WITH_TRIO                1    # Configure trio support.
setenv WITH_THREADS             1    # Configure thread support.
setenv WITH_THREAD_ALLOC        1    # Whether allocation hooks are per-thread.
setenv WITH_TREE                1    # Compile DOM tree API.
setenv WITH_OUTPUT              1    # Compile serialization/saving support.
setenv WITH_PUSH                1    # Compile push parser.
setenv WITH_READER              1    # Compile parsing interface.
setenv WITH_PATTERN             1    # Compile pattern node selection interface.
setenv WITH_WRITER              1    # Compile saving interface.
setenv WITH_SAX1                1    # Compile SAX version 1 interface.
setenv WITH_FTP                 1    # Compile FTP support.
setenv WITH_HTTP                1    # Compile HTTP support.
setenv WITH_VALID               1    # Compile DTD validation support.
setenv WITH_HTML                1    # Compile HTML support.
setenv WITH_LEGACY              1    # Compile deprecated API.
setenv WITH_C14N                1    # Compile canonicalization support.
setenv WITH_CATALOG             1    # Compile catalog support.
setenv WITH_DOCB                1    # Compile SGML Docbook support.
setenv WITH_XPATH               1    # Compile XPath support.
setenv WITH_XPTR                1    # Compile XPointer support.
setenv WITH_XINCLUDE            1    # Compile XInclude support.
setenv WITH_ICONV               1    # Whether iconv support is available.
setenv WITH_ICU                 0    # Whether icu support is available.
setenv WITH_ISO8859X            1    # Compile ISO-8859-* support if no iconv.
setenv WITH_DEBUG               1    # Compile debugging module.
setenv WITH_MEM_DEBUG           1    # Compile memory debugging module.
setenv WITH_RUN_DEBUG           1    # Compile runtime debugging.
setenv WITH_REGEXPS             1    # Compile regular expression interfaces.
setenv WITH_SCHEMAS             1    # Compile schema validation interface.
setenv WITH_SCHEMATRON          1    # Compile schematron validation interface.
setenv WITH_MODULES             1    # Compile module interfaces.
setenv WITH_ZLIB                0    # Whether zlib is available.
setenv WITH_LZMA                0    # Whether LZMA is available.

#       Define ZLIB locations. This is ignored if WITH_ZLIB is 0.

setenv ZLIB_INCLUDE             '/zlib/include' # ZLIB include IFS directory.
setenv ZLIB_LIB                 'ZLIB'          # ZLIB library.
setenv ZLIB_BNDDIR              'ZLIB_A'        # ZLIB binding directory.

################################################################################
#
#                       OS/400 specific definitions.
#
################################################################################

setenv LIBIFSNAME               "/QSYS.LIB/${TARGETLIB}.LIB"
setenv MODULE_EXTENSION         '.SRVPGM'


################################################################################
#
#                       Extract version information.
#
################################################################################


#       Transitional: get file name of configure script.

AUTOCONFSCRIPT="${TOPDIR}/configure.ac"

if [ ! -f "${AUTOCONFSCRIPT}" ]
then    AUTOCONFSCRIPT="${TOPDIR}/configure.in"
fi

#       Need to get the version definitions.

eval "`grep '^LIBXML_[A-Z]*_VERSION=' \"${AUTOCONFSCRIPT}\"`"
eval "`grep '^LIBXML_MICRO_VERSION_SUFFIX=' \"${AUTOCONFSCRIPT}\"`"
LIBXML_VERSION="${LIBXML_MAJOR_VERSION}.${LIBXML_MINOR_VERSION}"
LIBXML_VERSION="${LIBXML_VERSION}.${LIBXML_MICRO_VERSION}"
LIBXML_VERSION="${LIBXML_VERSION}${LIBXML_MICRO_VERSION_SUFFIX}"
LIBXML_VERSION_NUMBER=`expr "${LIBXML_MAJOR_VERSION}" \* 10000 +        \
                            "${LIBXML_MINOR_VERSION}" \* 100 +          \
                            "${LIBXML_MICRO_VERSION}"`
export LIBXML_MAJOR_VERSION LIBXML_MINOR_VERSION
export LIBXML_MICRO_VERSION LIBXML_MICROVERSION_SUFFIX
export LIBXML_VERSION LIBXML_VERSION_NUMBER
setenv LIBXML_VERSION_EXTRA ''
setenv VERSION  "${LIBXML_VERSION}"


################################################################################
#
#                               Procedures.
#
################################################################################

#       action_needed dest [src]
#
#       dest is an object to build
#       if specified, src is an object on which dest depends.
#
#       exit 0 (succeeds) if some action has to be taken, else 1.

action_needed()

{
        [ ! -e "${1}" ] && return 0
        [ "${2}" ] || return 1
        [ "${1}" -ot "${2}" ] && return 0
        return 1
}


#       make_module [option] module_name source_name
#
#       Compile source name into ASCII module if needed.
#       As side effect, append the module name to variable MODULES.
#       Set LINK to "YES" if the module has been compiled.
#       Options are:
#         --define <additional definitions>
#         --ebcdic
#         --sysiconv

make_module()

{
        DEFN=
        EBCDIC=
        SYSICONV=
        while true
        do      case "${1}" in
                --define)
                        DEFN="${2}"
                        shift
                        ;;
                --ebcdic)
                        EBCDIC=yes
                        ;;
                --sysiconv)
                        SYSICONV=yes
                        ;;
                *)      break
                esac
                shift
        done
        MODULES="${MODULES} ${1}"
        MODIFSNAME="${LIBIFSNAME}/${1}.MODULE"
        action_needed "${MODIFSNAME}" "${2}" || return 0;

        #       #pragma convert has to be in the source file itself, i.e.
        #               putting it in an include file makes it only active
        #               for that include file.
        #       Thus we build a temporary file with the pragma prepended to
        #               the source file and we compile that temporary file.

        rm -f __tmpsrcf.c
        if [ -z "${EBCDIC}" ]
        then    echo "#line 1 \"${2}\"" >> __tmpsrcf.c
                echo "#pragma convert(819)" >> __tmpsrcf.c
                echo '#include "wrappers.h"' >> __tmpsrcf.c
        fi
        echo "#line 1 \"${2}\"" >> __tmpsrcf.c
        cat "${2}" >> __tmpsrcf.c
        CMD="CRTCMOD MODULE(${TARGETLIB}/${1}) SRCSTMF('__tmpsrcf.c')"
#       CMD="${CMD} OPTION(*INCDIRFIRST *SHOWINC *SHOWSYS)"
        CMD="${CMD} OPTION(*INCDIRFIRST) FLAG(10)"
        CMD="${CMD} SYSIFCOPT(*IFS64IO) LANGLVL(*EXTENDED) LOCALETYPE(*LOCALE)"
        CMD="${CMD} INCDIR("
        if [  -z "${SYSICONV}" ]
        then    CMD="${CMD} '${TOPDIR}/os400/iconv'"
        fi
        if [ -z "${EBCDIC}" ]
        then    CMD="${CMD} '/qibm/proddata/qadrt/include'"
        fi
        CMD="${CMD} '${TOPDIR}/os400' '${TOPDIR}/os400/dlfcn'"
        CMD="${CMD} '${IFSDIR}/include/libxml' '${IFSDIR}/include'"
        if [ "${ZLIB_INCLUDE}" ]
        then    CMD="${CMD} '${ZLIB_INCLUDE}'"
        fi
        CMD="${CMD} '${TOPDIR}' ${INCLUDES})"
        CMD="${CMD} TGTCCSID(${TGTCCSID}) TGTRLS(${TGTRLS})"
        CMD="${CMD} OUTPUT(${OUTPUT})"
        CMD="${CMD} OPTIMIZE(${OPTIMIZE})"
        CMD="${CMD} DBGVIEW(${DEBUG})"
        CMD="${CMD} DEFINE('_REENTRANT' 'TRIO_HAVE_CONFIG_H' 'NDEBUG' ${DEFN})"

        system "${CMD}"
        rm -f __tmpsrcf.c
        LINK=YES
}


#       Determine DB2 object name from IFS name.

db2_name()

{
        if [ "${2}" = 'nomangle' ]
        then    basename "${1}"                                         |
                tr 'a-z-' 'A-Z_'                                        |
                sed -e 's/\..*//'                                       \
                    -e 's/^\(..........\).*$/\1/'
        else    basename "${1}"                                         |
                tr 'a-z-' 'A-Z_'                                        |
                sed -e 's/\..*//'                                       \
                    -e 's/^TEST/T/'                                     \
                    -e 's/^XML/X/'                                      \
                    -e 's/^\(.\).*\(.........\)$/\1\2/'
        fi
}


#       Copy IFS file replacing version & configuration info.

versioned_copy()

{
    sed -e "s/@LIBXML_VERSION@/${LIBXML_VERSION}/g"                     \
                                                                        \
        -e "s#@LIBXML_MAJOR_VERSION@#${LIBXML_MAJOR_VERSION}#g"         \
        -e "s#@LIBXML_MINOR_VERSION@#${LIBXML_MINOR_VERSION}#g"         \
        -e "s#@LIBXML_MICRO_VERSION@#${LIBXML_MICRO_VERSION}#g"         \
        -e "s#@LIBXML_MICRO_VERSION_SUFFIX@#${LIBXML_MICRO_VERSION_SUFFIX}#g" \
        -e "s#@LIBXML_VERSION@#${LIBXML_VERSION}#g"                     \
        -e "s#@LIBXML_VERSION_NUMBER@#${LIBXML_VERSION_NUMBER}#g"       \
        -e "s#@LIBXML_VERSION_EXTRA@#${LIBXML_VERSION_EXTRA}#g"         \
        -e "s#@VERSION@#${VERSION}#g"                                   \
        -e "s#@WITH_TRIO@#${WITH_TRIO}#g"                               \
        -e "s#@WITH_THREADS@#${WITH_THREADS}#g"                         \
        -e "s#@WITH_THREAD_ALLOC@#${WITH_THREAD_ALLOC}#g"               \
        -e "s#@WITH_TREE@#${WITH_TREE}#g"                               \
        -e "s#@WITH_OUTPUT@#${WITH_OUTPUT}#g"                           \
        -e "s#@WITH_PUSH@#${WITH_PUSH}#g"                               \
        -e "s#@WITH_READER@#${WITH_READER}#g"                           \
        -e "s#@WITH_PATTERN@#${WITH_PATTERN}#g"                         \
        -e "s#@WITH_WRITER@#${WITH_WRITER}#g"                           \
        -e "s#@WITH_SAX1@#${WITH_SAX1}#g"                               \
        -e "s#@WITH_FTP@#${WITH_FTP}#g"                                 \
        -e "s#@WITH_HTTP@#${WITH_HTTP}#g"                               \
        -e "s#@WITH_VALID@#${WITH_VALID}#g"                             \
        -e "s#@WITH_HTML@#${WITH_HTML}#g"                               \
        -e "s#@WITH_LEGACY@#${WITH_LEGACY}#g"                           \
        -e "s#@WITH_C14N@#${WITH_C14N}#g"                               \
        -e "s#@WITH_CATALOG@#${WITH_CATALOG}#g"                         \
        -e "s#@WITH_DOCB@#${WITH_DOCB}#g"                               \
        -e "s#@WITH_XPATH@#${WITH_XPATH}#g"                             \
        -e "s#@WITH_XPTR@#${WITH_XPTR}#g"                               \
        -e "s#@WITH_XINCLUDE@#${WITH_XINCLUDE}#g"                       \
        -e "s#@WITH_ICONV@#${WITH_ICONV}#g"                             \
        -e "s#@WITH_ICU@#${WITH_ICU}#g"                                 \
        -e "s#@WITH_ISO8859X@#${WITH_ISO8859X}#g"                       \
        -e "s#@WITH_DEBUG@#${WITH_DEBUG}#g"                             \
        -e "s#@WITH_MEM_DEBUG@#${WITH_MEM_DEBUG}#g"                     \
        -e "s#@WITH_RUN_DEBUG@#${WITH_RUN_DEBUG}#g"                     \
        -e "s#@WITH_REGEXPS@#${WITH_REGEXPS}#g"                         \
        -e "s#@WITH_SCHEMAS@#${WITH_SCHEMAS}#g"                         \
        -e "s#@WITH_SCHEMATRON@#${WITH_SCHEMATRON}#g"                   \
        -e "s#@WITH_MODULES@#${WITH_MODULES}#g"                         \
        -e "s#@WITH_ZLIB@#${WITH_ZLIB}#g"                               \
        -e "s#@WITH_LZMA@#${WITH_LZMA}#g"
}
