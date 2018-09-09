      * Supplementary character code conversion functions for
      *   EBCDIC environments.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(TRANSCODE_H__)
      /define TRANSCODE_H__

      /include "libxmlrpg/dict"
      /include "libxmlrpg/xmlstdarg"

     d xmlZapDict      pr                  extproc('xmlZapDict')
     d  dict                               like(xmlDictPtr)

     d xmlTranscodeResult...
     d                 pr              *   extproc('xmlTranscodeResult')        const char *
     d  s                              *   value options(*string)               const xmlChar *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)
     d  freeproc                       *   value procptr

     d xmlTranscodeString...
     d                 pr              *   extproc('xmlTranscodeString')        const xmlChar *
     d  s                              *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)

     d xmlTranscodeWString...
     d                 pr              *   extproc('xmlTranscodeWString')       const xmlChar *
     d  s                              *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)

     d xmlTranscodeHString...
     d                 pr              *   extproc('xmlTranscodeHString')       const xmlChar *
     d  s                              *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)

      /if not defined(XML_NO_SHORT_NAMES)
     d xmlTR           pr              *   extproc('xmlTranscodeResult')        const char *
     d  s                              *   value options(*string)               const xmlChar *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)
     d  freeproc                       *   value procptr

     d xmlTS           pr              *   extproc('xmlTranscodeString')        const xmlChar *
     d  s                              *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)

     d xmlTW           pr              *   extproc('xmlTranscodeWString')       const xmlChar *
     d  s                              *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)

     d xmlTH           pr              *   extproc('xmlTranscodeHString')       const xmlChar *
     d  s                              *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  dict                               like(xmlDictPtr) options(*omit)
      /endif

     d xmlVasprintf    pr              *   extproc('xmlVasprintf')
     d  dict                               like(xmlDictPtr) options(*omit)
     d  encoding                       *   value options(*string)               const char *
     d  fmt                            *   value options(*string)               const xmlChar *
     d  args                               likeds(xmlVaList)

      /endif
