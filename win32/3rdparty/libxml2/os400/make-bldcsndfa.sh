#!/bin/sh
#
#       Compilation script for the iconv names DFA builer.
#
#       See Copyright for the status of this software.
#
#       Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
#

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/os400/iconv/bldcsndfa"


# This is for old XML library (bootstrapping).
#rm -rf xml.h xml
#ln -s /QSYS.LIB/XML.LIB/H.FILE/XML.MBR xml.h
#mkdir xml
#mkdir xml/h
#ln -s /QSYS.LIB/XML.LIB/H.FILE/UTF8.MBR xml/h/utf8


#       Compile.

CMD="CRTCMOD MODULE(${TARGETLIB}/BLDCSNDFA) SRCSTMF('bldcsndfa.c')"
CMD="${CMD} SYSIFCOPT(*IFS64IO) LANGLVL(*EXTENDED) LOCALETYPE(*LOCALE)"
CMD="${CMD} INCDIR("
CMD="${CMD} '${IFSDIR}/include' ${INCLUDES})"
CMD="${CMD} TGTCCSID(${TGTCCSID}) TGTRLS(${TGTRLS})"
CMD="${CMD} OUTPUT(${OUTPUT})"
CMD="${CMD} OPTIMIZE(10)"
CMD="${CMD} DBGVIEW(${DEBUG})"
#CMD="${CMD} DEFINE('OLDXML' 'xmlXPathSetContextNode=xmlXPathSetCurrentNode')"

system "${CMD}"

#       Link

CMD="CRTPGM PGM(${TARGETLIB}/BLDCSNDFA) MODULE(${TARGETLIB}/BLDCSNDFA)"
CMD="${CMD} BNDDIR(${TARGETLIB}/${DYNBNDDIR})"
#CMD="${CMD} BNDDIR(XML/XML)"
CMD="${CMD} TGTRLS(${TGTRLS})"
system "${CMD}"
