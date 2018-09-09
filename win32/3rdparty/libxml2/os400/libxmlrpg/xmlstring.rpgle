      * Summary: set of routines to process strings
      * Description: type and interfaces needed for the internal string
      *              handling of the library, especially UTF8 processing.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_STRING_H__)
      /define XML_STRING_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/xmlstdarg"

      * xmlChar:
      *
      * This is a basic byte in an UTF-8 encoded string.
      * It's unsigned allowing to pinpoint case where char * are assigned
      * to xmlChar * (possibly making serialization back impossible).

     d xmlChar         s                   based(######typedef######)
     d                                     like(xmlCuchar)

      * xmlChar handling

     d xmlStrdup       pr              *   extproc('xmlStrdup')                 xmlChar *
     d  cur                            *   value options(*string)               const xmlChar *

     d xmlStrndup      pr              *   extproc('xmlStrndup')                xmlChar *
     d  cur                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlCharStrndup  pr              *   extproc('xmlCharStrndup')            xmlChar *
     d  cur                            *   value options(*string)               const char *
     d  len                                value like(xmlCint)

     d xmlCharStrdup   pr              *   extproc('xmlCharStrdup')             xmlChar *
     d  cur                            *   value options(*string)               const char *

     d xmlStrsub       pr              *   extproc('xmlStrsub')                 const xmlChar *
     d  str                            *   value options(*string)               const xmlChar *
     d  start                              value like(xmlCint)
     d  len                                value like(xmlCint)

     d xmlStrchr       pr              *   extproc('xmlStrchr')                 const xmlChar *
     d  str                            *   value options(*string)               const xmlChar *
     d  val                                value like(xmlChar)

     d xmlStrstr       pr              *   extproc('xmlStrstr')                 const xmlChar *
     d  str                            *   value options(*string)               const xmlChar *
     d  val                            *   value options(*string)               const xmlChar *

     d xmlStrcasestr   pr              *   extproc('xmlStrcasestr')             const xmlChar *
     d  str                            *   value options(*string)               const xmlChar *
     d  val                            *   value options(*string)               const xmlChar *

     d xmlStrcmp       pr                  extproc('xmlStrcmp')
     d                                     like(xmlCint)
     d  str1                           *   value options(*string)               const xmlChar *
     d  str2                           *   value options(*string)               const xmlChar *

     d xmlStrncmp      pr                  extproc('xmlStrncmp')
     d                                     like(xmlCint)
     d  str1                           *   value options(*string)               const xmlChar *
     d  str2                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlStrcasecmp   pr                  extproc('xmlStrcasecmp')
     d                                     like(xmlCint)
     d  str1                           *   value options(*string)               const xmlChar *
     d  str2                           *   value options(*string)               const xmlChar *

     d xmlStrncasecmp  pr                  extproc('xmlStrncasecmp')
     d                                     like(xmlCint)
     d  str1                           *   value options(*string)               const xmlChar *
     d  str2                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlStrEqual     pr                  extproc('xmlStrEqual')
     d                                     like(xmlCint)
     d  str1                           *   value options(*string)               const xmlChar *
     d  str2                           *   value options(*string)               const xmlChar *

     d xmlStrQEqual    pr                  extproc('xmlStrQEqual')
     d                                     like(xmlCint)
     d  pref                           *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  stre                           *   value options(*string)               const xmlChar *

     d xmlStrlen       pr                  extproc('xmlStrlen')
     d                                     like(xmlCint)
     d  str                            *   value options(*string)               const xmlChar *

     d xmlStrcat       pr              *   extproc('xmlStrcat')                 xmlChar *
     d  cur                            *   value options(*string)               xmlChar *
     d  add                            *   value options(*string)               const xmlChar *

     d xmlStrncat      pr              *   extproc('xmlStrncat')                xmlChar *
     d  cur                            *   value options(*string)               xmlChar *
     d  add                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlStrncatNew   pr              *   extproc('xmlStrncatNew')             xmlChar *
     d  str1                           *   value options(*string)               const xmlChar *
     d  str2                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

      * xmlStrPrintf() is a vararg function.
      * The following prototype supports up to 8 pointer arguments.
      * Other argument signature can be achieved by defining alternate
      *   prototypes redirected to the same function.

     d xmlStrPrintf    pr                  extproc('xmlStrPrintf')
     d                                     like(xmlCint)
     d  buf                            *   value options(*string)               xmlChar *
     d  len                                value like(xmlCint)
     d  msg                            *   value options(*string)               const char *
     d  arg1                           *   value options(*string: *nopass)
     d  arg2                           *   value options(*string: *nopass)
     d  arg3                           *   value options(*string: *nopass)
     d  arg4                           *   value options(*string: *nopass)
     d  arg5                           *   value options(*string: *nopass)
     d  arg6                           *   value options(*string: *nopass)
     d  arg7                           *   value options(*string: *nopass)
     d  arg8                           *   value options(*string: *nopass)

     d xmlStrVPrintf   pr                  extproc('xmlStrVPrintf')
     d                                     like(xmlCint)
     d  buf                            *   value options(*string)               xmlChar *
     d  len                                value like(xmlCint)
     d  msg                            *   value options(*string)               const char *
     d  ap                                 likeds(xmlVaList)

     d xmlGetUTF8Char  pr                  extproc('xmlGetUTF8Char')
     d                                     like(xmlCint)
     d  utf                            *   value options(*string)               const uns. char *
     d  len                                like(xmlCint)

     d xmlCheckUTF8    pr                  extproc('xmlCheckUTF8')
     d                                     like(xmlCint)
     d  utf                            *   value options(*string)               const uns. char *

     d xmlUTF8Strsize  pr                  extproc('xmlUTF8Strsize')
     d                                     like(xmlCint)
     d  utf                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlUTF8Strndup  pr              *   extproc('xmlUTF8Strndup')            xmlChar *
     d  utf                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlUTF8Strpos   pr              *   extproc('xmlUTF8Strpos')             const xmlChar *
     d  utf                            *   value options(*string)               const xmlChar *
     d  pos                                value like(xmlCint)

     d xmlUTF8Strloc   pr                  extproc('xmlUTF8Strloc')
     d                                     like(xmlCint)
     d  utf                            *   value options(*string)               const xmlChar *
     d  utfchar                        *   value options(*string)               const xmlChar *

     d xmlUTF8Strsub   pr              *   extproc('xmlUTF8Strsub')             xmlChar *
     d  utf                            *   value options(*string)               const xmlChar *
     d  start                              value like(xmlCint)
     d  len                                value like(xmlCint)

     d xmlUTF8Strlen   pr                  extproc('xmlUTF8Strlen')
     d                                     like(xmlCint)
     d  utf                            *   value options(*string)               const xmlChar *

     d xmlUTF8Size     pr                  extproc('xmlUTF8Size')
     d                                     like(xmlCint)
     d  utf                            *   value options(*string)               const xmlChar *

     d xmlUTF8Charcmp  pr                  extproc('xmlUTF8Charcmp')
     d                                     like(xmlCint)
     d  utf1                           *   value options(*string)               const xmlChar *
     d  utf2                           *   value options(*string)               const xmlChar *

      /endif                                                                    XML_STRING_H__
