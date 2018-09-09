#!/bin/sh
#
#       Installation of the C header files in the OS/400 library.
#
#       See Copyright for the status of this software.
#
#       Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
#

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/include"


#       Create the OS/400 source program file for the C header files.

SRCPF="${LIBIFSNAME}/LIBXML.FILE"

if action_needed "${SRCPF}"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/LIBXML) RCDLEN(112)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('libxml2: C/C++ header files')"
        system "${CMD}"
fi


#       Create the IFS directory for the C header files.

if action_needed "${IFSDIR}/include/libxml"
then    mkdir -p "${IFSDIR}/include/libxml"
fi



#       Enumeration values may be used as va_arg tagfields, so they MUST be
#               integers.

copy_hfile()

{
        sed -e '1i\
#pragma enum(int)\
' "${@}" -e '$a\
#pragma enum(pop)\
'
}

#       Copy the header files to DB2 library. Link from IFS include directory.

for HFILE in "${TOPDIR}/os400/transcode.h" libxml/*.h libxml/*.h.in
do      CMD="cat \"${HFILE}\""
        DEST="${SRCPF}/`db2_name \"${HFILE}\" nomangle`.MBR"

        case "`basename \"${HFILE}\"`" in

        xmlwin32version.h*)
                continue;;      # Not on M$W !

        *.in)   CMD="${CMD} | versioned_copy";;

        xmlschemastypes.h)      #       Special case: rename colliding file.
                DEST="${SRCPF}/SCHMTYPES.MBR";;

        esac

        if action_needed "${DEST}" "${HFILE}"
        then    eval "${CMD}" | copy_hfile > tmphdrfile

                #       Need to translate to target CCSID.

                CMD="CPY OBJ('`pwd`/tmphdrfile') TOOBJ('${DEST}')"
                CMD="${CMD} TOCCSID(${TGTCCSID}) DTAFMT(*TEXT) REPLACE(*YES)"
                system "${CMD}"
        fi

        IFSFILE="${IFSDIR}/include/libxml/`basename \"${HFILE}\" .in`"

        if action_needed "${IFSFILE}" "${DEST}"
        then    rm -f "${IFSFILE}"
                ln -s "${DEST}" "${IFSFILE}"
        fi
done
