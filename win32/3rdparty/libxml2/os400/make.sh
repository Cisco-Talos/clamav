#!/bin/sh
#
#       libxml2 compilation script for the OS/400.
#       This is a shell script since make is not a standard component of OS/400.
#
#       See Copyright for the status of this software.
#
#       Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
#

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}"


#       Create the OS/400 library if it does not exist.

if action_needed "${LIBIFSNAME}"
then    CMD="CRTLIB LIB(${TARGETLIB})"
        CMD="${CMD} TEXT('libxml2: XML parser and toolkit API')"
        system "${CMD}"
fi


#       Create the DOCS source file if it does not exist.

if action_needed "${LIBIFSNAME}/DOCS.FILE"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/DOCS) RCDLEN(112)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('Documentation texts')"
        system "${CMD}"
fi


#       Copy some documentation files if needed.

for TEXT in "${TOPDIR}/AUTHORS" "${TOPDIR}/ChangeLog"                   \
    "${TOPDIR}/Copyright" "${TOPDIR}/CONTRIBUTING" "${TOPDIR}/README"        \
    "${TOPDIR}/MAINTAINERS" "${TOPDIR}/NEWS" "${TOPDIR}/TODO"           \
    "${TOPDIR}/TODO_SCHEMAS" "${TOPDIR}/os400/README400"
do      if [ -f "${TEXT}" ]
        then    MEMBER="`basename \"${TEXT}\" .OS400`"
                MEMBER="${LIBIFSNAME}/DOCS.FILE/`db2_name \"${MEMBER}\"`.MBR"

                if action_needed "${MEMBER}" "${TEXT}"
                then    # Sources are in UTF-8.
                        rm -f "${TOPDIR}/tmpfile"[12]
                        CMD="CPY OBJ('${TEXT}') TOOBJ('${TOPDIR}/tmpfile1')"
                        CMD="${CMD} FROMCCSID(1208) TOCCSID(${TGTCCSID})"
                        CMD="${CMD} DTAFMT(*TEXT) REPLACE(*YES)"
                        system "${CMD}"
                        # Make sure all lines are < 100 characters.
                        sed -e 's/.\{99\}/&\
/g' -e 's/\n$//' "${TOPDIR}/tmpfile1" > "${TOPDIR}/tmpfile2"
                        CMD="CPY OBJ('${TOPDIR}/tmpfile2') TOOBJ('${MEMBER}')"
                        CMD="${CMD} TOCCSID(${TGTCCSID})"
                        CMD="${CMD} DTAFMT(*TEXT) REPLACE(*YES)"
                        system "${CMD}"
                fi
        fi
done


#       Build files from template.

configFile()

{
        args=`set | sed -e '/^[A-Za-z_][A-Za-z0-9_]*=/!d'               \
                        -e 's/[\/\\\\&]/\\\\&/g'                        \
                        -e "s/'/'\\\\\\''/g"                            \
                        -e 's/^\([^=]*\)=\(.*\)$/-e '\''s\/@\1@\/\2\/g'\'/`
        eval sed ${args} < "${1}".in > "${1}"
}

configFile include/libxml/xmlversion.h
configFile os400/os400config.h
mv os400/os400config.h config.h


#       Build in each directory.

for SUBDIR in include rpg src
do      "${SCRIPTDIR}/make-${SUBDIR}.sh"
done
