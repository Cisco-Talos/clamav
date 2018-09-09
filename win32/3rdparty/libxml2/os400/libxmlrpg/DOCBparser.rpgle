      * Summary: old DocBook SGML parser
      * Description: interface for a DocBook SGML non-verifying parser
      * This code is DEPRECATED, and should not be used anymore.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(DOCB_PARSER_H__)
      /define DOCB_PARSER_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_DOCB_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/parser"
      /include "libxmlrpg/parserInternals"

      * Most of the back-end structures from XML and SGML are shared.

     d docbParserCtxtPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlParserCtxtPtr)

     d docbParserCtxt  ds                  based(docbParserCtxtPtr)
     d                                     likeds(xmlParserCtxt)

     d docbSAXHandlerPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlSAXHandlerPtr)

     d docbSAXHandler  ds                  based(docbSAXHandlerPtr)
     d                                     likeds(xmlSAXHandler)

     d docbParserInputPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlParserInputPtr)

     d docbParserInput...
     d                 ds                  based(docbParserInputPtr)
     d                                     likeds(xmlParserInput)

     d docbDocPtr      s                   based(######typedef######)
     d                                     like(xmlDocPtr)

      * There is only few public functions.

     d docbEncodeEntities...
     d                 pr                  extproc('docbEncodeEntities')
     d                                     like(xmlCint)
     d  out                            *   value options(*string)               unsigned char *
     d  outlen                         *   value                                int *
     d  in                             *   value options(*string)               const unsigned char
     d                                                                          *
     d  inlen                          *   value                                int *
     d  quoteChar                          value like(xmlCint)

     d docbSAXParseDoc...
     d                 pr                  extproc('docbSAXParseDoc')
     d                                     like(docbDocPtr)
     d  cur                            *   value options(*string)               xmlChar *
     d  encoding                       *   value options(*string)               const char *
     d  sax                                value like(docbSAXHandlerPtr)
     d  userData                       *   value                                void *

     d docbParseDoc    pr                  extproc('docbParseDoc')
     d                                     like(docbDocPtr)
     d  cur                            *   value options(*string)               xmlChar *
     d  encoding                       *   value options(*string)               const char *

     d docbSAXParseFile...
     d                 pr                  extproc('docbSAXParseFile')
     d                                     like(docbDocPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  sax                                value like(docbSAXHandlerPtr)
     d  userData                       *   value                                void *

     d docbParseFile   pr                  extproc('docbParseFile')
     d                                     like(docbDocPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *

      * Interfaces for the Push mode.

     d docbFreeParserCtxt...
     d                 pr                  extproc('docbFreeParserCtxt')
     d  ctxt                               value like(docbParserCtxtPtr)

     d docbCreatePushParserCtxt...
     d                 pr                  extproc('docbCreatePushParserCtxt')
     d                                     like(docbParserCtxtPtr)
     d  sax                                value like(docbSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  enc                                value like(xmlCharEncoding)

     d docbParseChunk  pr                  extproc('docbParseChunk')
     d                                     like(xmlCint)
     d  ctxt                               value like(docbParserCtxtPtr)
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  terminate                          value like(xmlCint)

     d docbCreateFileParserCtxt...
     d                 pr                  extproc('docbCreateFileParserCtxt')
     d                                     like(docbParserCtxtPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *

     d docbParseDocument...
     d                 pr                  extproc('docbParseDocument')
     d                                     like(xmlCint)
     d  ctxt                               value like(docbParserCtxtPtr)

      /endif                                                                    LIBXML_DOCB_ENABLED
      /endif                                                                    DOCB_PARSER_H__
