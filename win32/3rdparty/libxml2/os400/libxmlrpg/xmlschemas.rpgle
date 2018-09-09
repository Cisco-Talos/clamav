      * Summary: incomplete XML Schemas structure implementation
      * Description: interface to the XML Schemas handling and schema validity
      *              checking, it is incomplete right now.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_SCHEMA_H__)
      /define XML_SCHEMA_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_SCHEMAS_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"

      * This error codes are obsolete; not used any more.

     d xmlSchemaValidError...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_SCHEMAS_ERR_OK...
     d                 c                   0
     d  XML_SCHEMAS_ERR_NOROOT...
     d                 c                   1
     d  XML_SCHEMAS_ERR_UNDECLAREDELEM...
     d                 c                   2
     d  XML_SCHEMAS_ERR_NOTTOPLEVEL...
     d                 c                   3
     d  XML_SCHEMAS_ERR_MISSING...
     d                 c                   4
     d  XML_SCHEMAS_ERR_WRONGELEM...
     d                 c                   5
     d  XML_SCHEMAS_ERR_NOTYPE...
     d                 c                   6
     d  XML_SCHEMAS_ERR_NOROLLBACK...
     d                 c                   7
     d  XML_SCHEMAS_ERR_ISABSTRACT...
     d                 c                   8
     d  XML_SCHEMAS_ERR_NOTEMPTY...
     d                 c                   9
     d  XML_SCHEMAS_ERR_ELEMCONT...
     d                 c                   10
     d  XML_SCHEMAS_ERR_HAVEDEFAULT...
     d                 c                   11
     d  XML_SCHEMAS_ERR_NOTNILLABLE...
     d                 c                   12
     d  XML_SCHEMAS_ERR_EXTRACONTENT...
     d                 c                   13
     d  XML_SCHEMAS_ERR_INVALIDATTR...
     d                 c                   14
     d  XML_SCHEMAS_ERR_INVALIDELEM...
     d                 c                   15
     d  XML_SCHEMAS_ERR_NOTDETERMINIST...
     d                 c                   16
     d  XML_SCHEMAS_ERR_CONSTRUCT...
     d                 c                   17
     d  XML_SCHEMAS_ERR_INTERNAL...
     d                 c                   18
     d  XML_SCHEMAS_ERR_NOTSIMPLE...
     d                 c                   19
     d  XML_SCHEMAS_ERR_ATTRUNKNOWN...
     d                 c                   20
     d  XML_SCHEMAS_ERR_ATTRINVALID...
     d                 c                   21
     d  XML_SCHEMAS_ERR_VALUE...
     d                 c                   22
     d  XML_SCHEMAS_ERR_FACET...
     d                 c                   23
     d  XML_SCHEMAS_ERR_...
     d                 c                   24
     d  XML_SCHEMAS_ERR_XXX...
     d                 c                   25

      * ATTENTION: Change xmlSchemaSetValidOptions's check
      * for invalid values, if adding to the validation
      * options below.

      * xmlSchemaValidOption:
      *
      * This is the set of XML Schema validation options.

     d xmlSchemaValidOption...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
      *
      * Default/fixed: create an attribute node
      * or an element's text node on the instance.
      *
     d  XML_SCHEMA_VAL_VC_I_CREATE...
     d                 c                   X'0001'
      /if defined(DISABLED)
      *
      * assemble schemata using
      * xsi:schemaLocation and
      * xsi:noNamespaceSchemaLocation
      *
     d  XML_SCHEMA_VAL_XSI_ASSEMBLE...
     d                 c                   X'0002'
      /endif

      * The schemas related types are kept internal

     d xmlSchemaPtr    s               *   based(######typedef######)

      * xmlSchemaValidityErrorFunc:
      * @ctx: the validation context
      * @msg: the message
      * @...: extra arguments
      *
      * Signature of an error callback from an XSD validation

     d xmlSchemaValidityErrorFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlSchemaValidityWarningFunc:
      * @ctx: the validation context
      * @msg: the message
      * @...: extra arguments
      *
      * Signature of a warning callback from an XSD validation

     d xmlSchemaValidityWarningFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * A schemas validation context

     d xmlSchemaParserCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaValidCtxtPtr...
     d                 s               *   based(######typedef######)

      * xmlSchemaValidityLocatorFunc:
      * @ctx: user provided context
      * @file: returned file information
      * @line: returned line information
      *
      * A schemas validation locator, a callback called by the validator.
      * This is used when file or node informations are not available
      * to find out what file and line number are affected
      *
      * Returns: 0 in case of success and -1 in case of error

     d xmlSchemaValidityLocatorFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * Interfaces for parsing.

     d xmlSchemaNewParserCtxt...
     d                 pr                  extproc('xmlSchemaNewParserCtxt')
     d                                     like(xmlSchemaParserCtxtPtr)
     d URL                             *   value options(*string)               const char *

     d xmlSchemaNewMemParserCtxt...
     d                 pr                  extproc('xmlSchemaNewMemParserCtxt')
     d                                     like(xmlSchemaParserCtxtPtr)
     d buffer                          *   value options(*string)               const char *
     d size                                value like(xmlCint)

     d xmlSchemaNewDocParserCtxt...
     d                 pr                  extproc('xmlSchemaNewDocParserCtxt')
     d                                     like(xmlSchemaParserCtxtPtr)
     d doc                                 value like(xmlDocPtr)

     d xmlSchemaFreeParserCtxt...
     d                 pr                  extproc('xmlSchemaFreeParserCtxt')
     d ctxt                                value like(xmlSchemaParserCtxtPtr)

     d xmlSchemaSetParserErrors...
     d                 pr                  extproc('xmlSchemaSetParserErrors')
     d ctxt                                value like(xmlSchemaParserCtxtPtr)
     d err                                 value
     d                                     like(xmlSchemaValidityErrorFunc)
     d warn                                value
     d                                     like(xmlSchemaValidityWarningFunc)
     d ctx                             *   value                                void *

     d xmlSchemaSetParserStructuredErrors...
     d                 pr                  extproc(
     d                                     'xmlSchemaSetParserStructuredErrors')
     d ctxt                                value like(xmlSchemaParserCtxtPtr)
     d serror                              value like(xmlStructuredErrorFunc)
     d ctx                             *   value                                void *

     d xmlSchemaGetParserErrors...
     d                 pr                  extproc('xmlSchemaGetParserErrors')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaParserCtxtPtr)
     d err                                 like(xmlSchemaValidityErrorFunc)
     d warn                                like(xmlSchemaValidityWarningFunc)
     d ctx                             *                                        void *(*)

     d xmlSchemaIsValid...
     d                 pr                  extproc('xmlSchemaIsValid')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)

     d xmlSchemaParse  pr                  extproc('xmlSchemaParse')
     d                                     like(xmlSchemaPtr)
     d ctxt                                value like(xmlSchemaParserCtxtPtr)

     d xmlSchemaFree   pr                  extproc('xmlSchemaFree')
     d schema                              value like(xmlSchemaPtr)

      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlSchemaDump   pr                  extproc('xmlSchemaDump')
     d output                          *   value                                FILE *
     d schema                              value like(xmlSchemaPtr)
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      * Interfaces for validating

     d xmlSchemaSetValidErrors...
     d                 pr                  extproc('xmlSchemaSetValidErrors')
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d err                                 value
     d                                     like(xmlSchemaValidityErrorFunc)
     d warn                                value
     d                                     like(xmlSchemaValidityWarningFunc)
     d ctx                             *   value                                void *

     d xmlSchemaSetValidStructuredErrors...
     d                 pr                  extproc(
     d                                     'xmlSchemaSetValidStructuredErrors')
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d serror                              value like(xmlStructuredErrorFunc)
     d ctx                             *   value                                void *

     d xmlSchemaGetValidErrors...
     d                 pr                  extproc('xmlSchemaGetValidErrors')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d err                                 like(xmlSchemaValidityErrorFunc)
     d warn                                like(xmlSchemaValidityWarningFunc)
     d ctx                             *                                        void *(*)

     d xmlSchemaSetValidOptions...
     d                 pr                  extproc('xmlSchemaSetValidOptions')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d options                             value like(xmlCint)

     d xmlSchemaValidateSetFilename...
     d                 pr                  extproc(
     d                                     'xmlSchemaValidateSetFilename')
     d vctxt                               value like(xmlSchemaValidCtxtPtr)
     d filename                        *   value options(*string)               const char *

     d xmlSchemaValidCtxtGetOptions...
     d                 pr                  extproc(
     d                                     'xmlSchemaValidCtxtGetOptions')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)

     d xmlSchemaNewValidCtxt...
     d                 pr                  extproc('xmlSchemaNewValidCtxt')
     d                                     like(xmlSchemaValidCtxtPtr)
     d schema                              value like(xmlSchemaPtr)

     d xmlSchemaFreeValidCtxt...
     d                 pr                  extproc('xmlSchemaFreeValidCtxt')
     d ctxt                                value like(xmlSchemaValidCtxtPtr)

     d xmlSchemaValidateDoc...
     d                 pr                  extproc('xmlSchemaValidateDoc')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d instance                            value like(xmlDocPtr)

     d xmlSchemaValidateOneElement...
     d                 pr                  extproc(
     d                                     'xmlSchemaValidateOneElement')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d elem                                value like(xmlNodePtr)

     d xmlSchemaValidateStream...
     d                 pr                  extproc('xmlSchemaValidateStream')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d input                               value like(xmlParserInputBufferPtr)
     d enc                                 value like(xmlCharEncoding)
     d sax                                 value like(xmlSAXHandlerPtr)
     d user_data                       *   value                                void *

     d xmlSchemaValidateFile...
     d                 pr                  extproc('xmlSchemaValidateFile')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d filename                        *   value options(*string)               const char *
     d options                             value like(xmlCint)

     d xmlSchemaValidCtxtGetParserCtxt...
     d                 pr                  extproc(
     d                                     'xmlSchemaValidCtxtGetParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)

      * Interface to insert Schemas SAX validation in a SAX stream

     d xmlSchemaSAXPlugPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaSAXPlug...
     d                 pr                  extproc('xmlSchemaSAXPlug')
     d                                     like(xmlSchemaSAXPlugPtr)
     d ctxt                                value like(xmlSchemaValidCtxtPtr)
     d sax                                 like(xmlSAXHandlerPtr)
     d user_data                       *                                        void *(*)

     d xmlSchemaSAXUnplug...
     d                 pr                  extproc('xmlSchemaSAXUnplug')
     d                                     like(xmlCint)
     d plug                                value like(xmlSchemaSAXPlugPtr)

     d xmlSchemaValidateSetLocator...
     d                 pr                  extproc(
     d                                     'xmlSchemaValidateSetLocator')
     d vctxt                               value like(xmlSchemaValidCtxtPtr)
     d f                                   value
     d                                     like(xmlSchemaValidityLocatorFunc)
     d ctxt                            *   value                                void *

      /endif                                                                    LIBXML_SCHEMAS_ENBLD
      /endif                                                                    XML_SCHEMA_H__
