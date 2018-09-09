      * Summary: XML Schemastron implementation
      * Description: interface to the XML Schematron validity checking.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_SCHEMATRON_H__)
      /define XML_SCHEMATRON_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_SCHEMATRON_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"

     d xmlSchematronValidOptions...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_SCHEMATRON_OUT_QUIET...                                             Quiet no report
     d                 c                   X'0001'
     d  XML_SCHEMATRON_OUT_TEXT...                                              Build textual report
     d                 c                   X'0002'
     d  XML_SCHEMATRON_OUT_XML...                                               Output SVRL
     d                 c                   X'0004'
     d  XML_SCHEMATRON_OUT_ERROR...                                             Output to error func
     d                 c                   X'0008'
     d  XML_SCHEMATRON_OUT_FILE...                                              Output to file descr
     d                 c                   X'0100'
     d  XML_SCHEMATRON_OUT_BUFFER...                                            Output to a buffer
     d                 c                   X'0200'
     d  XML_SCHEMATRON_OUT_IO...                                                Output to I/O mech
     d                 c                   X'0400'

      * The schemas related types are kept internal

     d xmlSchematronPtr...
     d                 s               *   based(######typedef######)

      * xmlSchematronValidityErrorFunc:
      * @ctx: the validation context
      * @msg: the message
      * @...: extra arguments
      *
      * Signature of an error callback from a Schematron validation

     d xmlSchematronValidityErrorFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlSchematronValidityWarningFunc:
      * @ctx: the validation context
      * @msg: the message
      * @...: extra arguments
      *
      * Signature of a warning callback from a Schematron validation

     d xmlSchematronValidityWarningFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * A schemas validation context

     d xmlSchematronParserCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlSchematronValidCtxtPtr...
     d                 s               *   based(######typedef######)

      * Interfaces for parsing.

     d xmlSchematronNewParserCtxt...
     d                 pr                  extproc('xmlSchematronNewParserCtxt')
     d                                     like(xmlSchematronParserCtxtPtr)
     d  URL                            *   value options(*string)               const char *

     d xmlSchematronNewMemParserCtxt...
     d                 pr                  extproc(
     d                                     'xmlSchematronNewMemParserCtxt')
     d                                     like(xmlSchematronParserCtxtPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)

     d xmlSchematronNewDocParserCtxt...
     d                 pr                  extproc(
     d                                     'xmlSchematronNewDocParserCtxt')
     d                                     like(xmlSchematronParserCtxtPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlSchematronFreeParserCtxt...
     d                 pr                  extproc(
     d                                     'xmlSchematronFreeParserCtxt')
     d  ctxt                               value
     d                                     like(xmlSchematronParserCtxtPtr)

      /if defined(DISABLED)
     d xmlSchematronSetParserErrors...
     d                 pr                  extproc(
     d                                     'xmlSchematronSetParserErrors')
     d  ctxt                               value
     d                                     like(xmlSchematronParserCtxtPtr)
     d  err                                value
     d                                     like(xmlSchematronValidityErrorFunc)
     d  warn                               value like(
     d                                       xmlSchematronValidityWarningFunc)
     d  ctx                            *   value                                void *

     d xmlSchematronGetParserErrors...
     d                 pr                  extproc(
     d                                     'xmlSchematronGetParserErrors')
     d                                     like(xmlCint)
     d  ctxt                               value
     d                                     like(xmlSchematronParserCtxtPtr)
     d  err                                like(xmlSchematronValidityErrorFunc)
     d  warn                               like(
     d                                       xmlSchematronValidityWarningFunc)
     d  ctx                            *                                        void *(*)

     d xmlSchematronIsValid...
     d                 pr                  extproc('xmlSchematronIsValid')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
      /endif

     d xmlSchematronParse...
     d                 pr                  extproc('xmlSchematronParse')
     d                                     like(xmlSchematronPtr)
     d  ctxt                               value
     d                                     like(xmlSchematronParserCtxtPtr)

     d xmlSchematronFree...
     d                 pr                  extproc('xmlSchematronFree')
     d  schema                             value like(xmlSchematronPtr)

      * Interfaces for validating

     d xmlSchematronSetValidStructuredErrors...
     d                 pr                  extproc('xmlSchematronSetValidStruct-
     d                                     uredErrors')
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
     d  serror                             value like(xmlStructuredErrorFunc)
     d  ctx                            *   value                                void *

      /if defined(DISABLED)
     d xmlSchematronSetValidErrors...
     d                 pr                  extproc(
     d                                     'xmlSchematronSetValidErrors')
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
     d  err                                value
     d                                     like(xmlSchematronValidityErrorFunc)
     d  warn                               value like(
     d                                     xmlSchematronValidityWarningFunc)
     d  ctx                            *   value                                void *

     d xmlSchematronGetValidErrors...
     d                 pr                  extproc(
     d                                     'xmlSchematronGetValidErrors')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
     d  err                                like(xmlSchematronValidityErrorFunc)
     d  warn                               like(
     d                                       xmlSchematronValidityWarningFunc)
     d  ctx                            *                                        void *(*)

     d xmlSchematronSetValidOptions...
     d                 pr                  extproc(
     d                                     'xmlSchematronSetValidOptions')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
     d  options                            value like(xmlCint)

     d xmlSchematronValidCtxtGetOptions...
     d                 pr                  extproc(
     d                                     'xmlSchematronValidCtxtGetOptions')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)

     d xmlSchematronValidateOneElement...
     d                 pr                  extproc(
     d                                     'xmlSchematronValidateOneElement')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
     d  elem                               value like(xmlNodePtr)
      /endif

     d xmlSchematronNewValidCtxt...
     d                 pr                  extproc('xmlSchematronNewValidCtxt')
     d                                     like(xmlSchematronValidCtxtPtr)
     d  schema                             value like(xmlSchematronPtr)
     d  options                            value like(xmlCint)

     d xmlSchematronFreeValidCtxt...
     d                 pr                  extproc('xmlSchematronFreeValidCtxt')
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)

     d xmlSchematronValidateDoc...
     d                 pr                  extproc('xmlSchematronValidateDoc')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSchematronValidCtxtPtr)
     d  instance                           value like(xmlDocPtr)

      /endif                                                                    _SCHEMATRON_ENABLED
      /endif                                                                    XML_SCHEMATRON_H__
