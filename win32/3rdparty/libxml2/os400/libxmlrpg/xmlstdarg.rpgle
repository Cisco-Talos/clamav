      * Summary: va_list support for ILE/RPG.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_STDARG_H__)
      /define XML_STDARG_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"

      * The va_list object.

     d xmlVaList       ds                  based(######typedef######)
     d                                     align qualified
     d  current                        *
     d  next                           *

      * Procedures.

     d xmlVaStart      pr                  extproc('__xmlVaStart')
     d  list                               likeds(xmlVaList)
     d  lastargaddr                    *   value
     d  lastargsize                        value like(xmlCsize_t)

     d xmlVaArg        pr              *   extproc('__xmlVaArg')
     d  list                               likeds(xmlVaList)
     d  dest                           *   value
     d  argsize                            value like(xmlCsize_t)

     d xmlVaEnd        pr                  extproc('__xmlVaEnd')
     d  list                               likeds(xmlVaList)

      /endif                                                                    XML_STDARG_H__
