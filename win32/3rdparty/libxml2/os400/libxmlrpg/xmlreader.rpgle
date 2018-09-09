      * Summary: the XMLReader implementation
      * Description: API of the XML streaming API based on C# interfaces.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_XMLREADER_H__)
      /define XML_XMLREADER_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/xmlIO"

      /if defined(LIBXML_SCHEMAS_ENABLED)
      /include "libxmlrpg/relaxng"
      /include "libxmlrpg/xmlschemas"
      /endif

      * xmlParserSeverities:
      *
      * How severe an error callback is when the per-reader error callback API
      * is used.

     d xmlParserSeverities...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_PARSER_SEVERITY_VALIDITY_WARNING...
     d                 c                   1
     d  XML_PARSER_SEVERITY_VALIDITY_ERROR...
     d                 c                   2
     d  XML_PARSER_SEVERITY_WARNING...
     d                 c                   3
     d  XML_PARSER_SEVERITY_ERROR...
     d                 c                   4

      /if defined(LIBXML_READER_ENABLED)

      * xmlTextReaderMode:
      *
      * Internal state values for the reader.

     d xmlTextReaderMode...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_TEXTREADER_MODE_INITIAL...
     d                 c                   0
     d  XML_TEXTREADER_MODE_INTERACTIVE...
     d                 c                   1
     d  XML_TEXTREADER_MODE_ERROR...
     d                 c                   2
     d  XML_TEXTREADER_MODE_EOF...
     d                 c                   3
     d  XML_TEXTREADER_MODE_CLOSED...
     d                 c                   4
     d  XML_TEXTREADER_MODE_READING...
     d                 c                   5

      * xmlParserProperties:
      *
      * Some common options to use with xmlTextReaderSetParserProp, but it
      * is better to use xmlParserOption and the xmlReaderNewxxx and
      * xmlReaderForxxx APIs now.

     d xmlParserProperties...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_PARSER_LOADDTD...
     d                 c                   1
     d  XML_PARSER_DEFAULTATTRS...
     d                 c                   2
     d  XML_PARSER_VALIDATE...
     d                 c                   3
     d  XML_PARSER_SUBST_ENTITIES...
     d                 c                   4

      * xmlReaderTypes:
      *
      * Predefined constants for the different types of nodes.

     d xmlReaderTypes  s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_READER_TYPE_NONE...
     d                 c                   0
     d  XML_READER_TYPE_ELEMENT...
     d                 c                   1
     d  XML_READER_TYPE_ATTRIBUTE...
     d                 c                   2
     d  XML_READER_TYPE_TEXT...
     d                 c                   3
     d  XML_READER_TYPE_CDATA...
     d                 c                   4
     d  XML_READER_TYPE_ENTITY_REFERENCE...
     d                 c                   5
     d  XML_READER_TYPE_ENTITY...
     d                 c                   6
     d  XML_READER_TYPE_PROCESSING_INSTRUCTION...
     d                 c                   7
     d  XML_READER_TYPE_COMMENT...
     d                 c                   8
     d  XML_READER_TYPE_DOCUMENT...
     d                 c                   9
     d  XML_READER_TYPE_DOCUMENT_TYPE...
     d                 c                   10
     d  XML_READER_TYPE_DOCUMENT_FRAGMENT...
     d                 c                   11
     d  XML_READER_TYPE_NOTATION...
     d                 c                   12
     d  XML_READER_TYPE_WHITESPACE...
     d                 c                   13
     d  XML_READER_TYPE_SIGNIFICANT_WHITESPACE...
     d                 c                   14
     d  XML_READER_TYPE_END_ELEMENT...
     d                 c                   15
     d  XML_READER_TYPE_END_ENTITY...
     d                 c                   16
     d  XML_READER_TYPE_XML_DECLARATION...
     d                 c                   17

      * xmlTextReaderPtr:
      *
      * Pointer to an xmlReader context.

     d xmlTextReaderPtr...
     d                 s               *   based(######typedef######)

      * Constructors & Destructor

     d xmlNewTextReader...
     d                 pr                  extproc('xmlNewTextReader')
     d                                     like(xmlTextReaderPtr)
     d  input                              value like(xmlParserInputBufferPtr)
     d  URI                            *   value options(*string)               const char *

     d xmlNewTextReaderFilename...
     d                 pr                  extproc('xmlNewTextReaderFilename')
     d                                     like(xmlTextReaderPtr)
     d  URI                            *   value options(*string)               const char *

     d xmlFreeTextReader...
     d                 pr                  extproc('xmlFreeTextReader')
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderSetup...
     d                 pr                  extproc('xmlTextReaderSetup')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  input                              value like(xmlParserInputBufferPtr)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

      * Iterators

     d xmlTextReaderRead...
     d                 pr                  extproc('xmlTextReaderRead')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

      /if defined(LIBXML_WRITER_ENABLED)
     d xmlTextReaderReadInnerXml...
     d                 pr              *   extproc('xmlTextReaderReadInnerXml') xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderReadOuterXml...
     d                 pr              *   extproc('xmlTextReaderReadOuterXml') xmlChar *
     d  reader                             value like(xmlTextReaderPtr)
      /endif

     d xmlTextReaderReadString...
     d                 pr              *   extproc('xmlTextReaderReadString')   xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderReadAttributeValue...
     d                 pr                  extproc(
     d                                     'xmlTextReaderReadAttributeValue')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

      * Attributes of the node

     d xmlTextReaderAttributeCount...
     d                 pr                  extproc(
     d                                     'xmlTextReaderAttributeCount')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderDepth...
     d                 pr                  extproc('xmlTextReaderDepth')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderHasAttributes...
     d                 pr                  extproc('xmlTextReaderHasAttributes')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderHasValue...
     d                 pr                  extproc('xmlTextReaderHasValue')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderIsDefault...
     d                 pr                  extproc('xmlTextReaderIsDefault')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderIsEmptyElement...
     d                 pr                  extproc(
     d                                     'xmlTextReaderIsEmptyElement')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderNodeType...
     d                 pr                  extproc('xmlTextReaderNodeType')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderQuoteChar...
     d                 pr                  extproc('xmlTextReaderQuoteChar')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderReadState...
     d                 pr                  extproc('xmlTextReaderReadState')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderIsNamespaceDecl...
     d                 pr                  extproc(
     d                                     'xmlTextReaderIsNamespaceDecl')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstBaseUri...
     d                 pr              *   extproc('xmlTextReaderConstBaseUri') const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstLocalName...
     d                 pr              *   extproc(                             const xmlChar *
     d                                     'xmlTextReaderConstLocalName')
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstName...
     d                 pr              *   extproc('xmlTextReaderConstName')    const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstNamespaceUri...
     d                 pr              *   extproc(                             const xmlChar *
     d                                     'xmlTextReaderConstNamespaceUri')
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstPrefix...
     d                 pr              *   extproc('xmlTextReaderConstPrefix')  const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstXmlLang...
     d                 pr              *   extproc('xmlTextReaderConstXmlLang') const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstString...
     d                 pr              *   extproc('xmlTextReaderConstString')  const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)
     d  str                            *   value options(*string)               const xmlChar *

     d xmlTextReaderConstValue...
     d                 pr              *   extproc('xmlTextReaderConstValue')   const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

      * use the Const version of the routine for
      * better performance and simpler code

     d xmlTextReaderBaseUri...
     d                 pr              *   extproc('xmlTextReaderBaseUri')      xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderLocalName...
     d                 pr              *   extproc('xmlTextReaderLocalName')    xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderName...
     d                 pr              *   extproc('xmlTextReaderName')         xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderNamespaceUri...
     d                 pr              *   extproc('xmlTextReaderNamespaceUri') xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderPrefix...
     d                 pr              *   extproc('xmlTextReaderPrefix')       xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderXmlLang...
     d                 pr              *   extproc('xmlTextReaderXmlLang')      xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderValue...
     d                 pr              *   extproc('xmlTextReaderValue')        xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

      * Methods of the XmlTextReader

     d xmlTextReaderClose...
     d                 pr                  extproc('xmlTextReaderClose')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderGetAttributeNo...
     d                 pr              *   extproc(                             xmlChar *
     d                                     'xmlTextReaderGetAttributeNo')
     d  reader                             value like(xmlTextReaderPtr)
     d  no                                 value like(xmlCint)

     d xmlTextReaderGetAttribute...
     d                 pr              *   extproc('xmlTextReaderGetAttribute') xmlChar *
     d  reader                             value like(xmlTextReaderPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextReaderGetAttributeNs...
     d                 pr              *   extproc(                             xmlChar *
     d                                     'xmlTextReaderGetAttributeNs')
     d  reader                             value like(xmlTextReaderPtr)
     d  localName                      *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *

     d xmlTextReaderGetRemainder...
     d                 pr                  extproc('xmlTextReaderGetRemainder')
     d                                     like(xmlParserInputBufferPtr)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderLookupNamespace...
     d                 pr              *   extproc(                             xmlChar *
     d                                     'xmlTextReaderLookupNamespace')
     d  reader                             value like(xmlTextReaderPtr)
     d  prefix                         *   value options(*string)               const xmlChar *

     d xmlTextReaderMoveToAttributeNo...
     d                 pr                  extproc(
     d                                     'xmlTextReaderMoveToAttributeNo')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  no                                 value like(xmlCint)

     d xmlTextReaderMoveToAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextReaderMoveToAttribute')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextReaderMoveToAttributeNs...
     d                 pr                  extproc(
     d                                     'xmlTextReaderMoveToAttributeNs')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  localName                      *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *

     d xmlTextReaderMoveToFirstAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextReaderMoveToFirstAttribute')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderMoveToNextAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextReaderMoveToNextAttribute')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderMoveToElement...
     d                 pr                  extproc('xmlTextReaderMoveToElement')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderNormalization...
     d                 pr                  extproc('xmlTextReaderNormalization')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderConstEncoding...
     d                 pr              *   extproc('xmlTextReaderConstEncoding')const xmlChar *
     d  reader                             value like(xmlTextReaderPtr)

      * Extensions

     d xmlTextReaderSetParserProp...
     d                 pr                  extproc('xmlTextReaderSetParserProp')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  prop                               value like(xmlCint)
     d  value                              value like(xmlCint)

     d xmlTextReaderGetParserProp...
     d                 pr                  extproc('xmlTextReaderGetParserProp')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  prop                               value like(xmlCint)

     d xmlTextReaderCurrentNode...
     d                 pr                  extproc('xmlTextReaderCurrentNode')
     d                                     like(xmlNodePtr)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderGetParserLineNumber...
     d                 pr                  extproc(
     d                                     'xmlTextReaderGetParserLineNumber')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderGetParserColumnNumber...
     d                 pr                  extproc(
     d                                     'xmlTextReaderGetParserColumnNumber')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderPreserve...
     d                 pr                  extproc('xmlTextReaderPreserve')
     d                                     like(xmlNodePtr)
     d  reader                             value like(xmlTextReaderPtr)

      /if defined(LIBXML_PATTERN_ENABLED)
     d xmlTextReaderPreservePattern...
     d                 pr                  extproc(
     d                                     'xmlTextReaderPreservePattern')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  pattern                        *   value options(*string)               const xmlChar *
     d  namespaces                     *                                        const xmlChar *(*)
      /endif                                                                    LIBXML_PATTERN_ENBLD

     d xmlTextReaderCurrentDoc...
     d                 pr                  extproc('xmlTextReaderCurrentDoc')
     d                                     like(xmlDocPtr)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderExpand...
     d                 pr                  extproc('xmlTextReaderExpand')
     d                                     like(xmlNodePtr)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderNext...
     d                 pr                  extproc('xmlTextReaderNext')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderNextSibling...
     d                 pr                  extproc('xmlTextReaderNextSibling')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderIsValid...
     d                 pr                  extproc('xmlTextReaderIsValid')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

      /if defined(LIBXML_SCHEMAS_ENABLED)
     d xmlTextReaderRelaxNGValidate...
     d                 pr                  extproc(
     d                                     'xmlTextReaderRelaxNGValidate')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  rng                            *   value options(*string)               const char *

     d xmlTextReaderRelaxNGValidateCtxt...
     d                 pr                  extproc(
     d                                     'xmlTextReaderRelaxNGValidateCtxt')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  options                            value like(xmlCint)

     d xmlTextReaderRelaxNGSetSchema...
     d                 pr                  extproc(
     d                                     'xmlTextReaderRelaxNGSetSchema')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  schema                             value like(xmlRelaxNGPtr)

     d xmlTextReaderSchemaValidate...
     d                 pr                  extproc(
     d                                     'xmlTextReaderSchemaValidate')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  xsd                            *   value options(*string)               const char *

     d xmlTextReaderSchemaValidateCtxt...
     d                 pr                  extproc(
     d                                     'xmlTextReaderSchemaValidateCtxt')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  ctxt                               value like(xmlSchemaValidCtxtPtr)
     d  options                            value like(xmlCint)

     d xmlTextReaderSetSchema...
     d                 pr                  extproc('xmlTextReaderSetSchema')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  schema                             value like(xmlSchemaPtr)
      /endif

     d xmlTextReaderConstXmlVersion...
     d                 pr              *   extproc(                             const xmlChar *
     d                                     'xmlTextReaderConstXmlVersion')
     d  reader                             value like(xmlTextReaderPtr)

     d xmlTextReaderStandalone...
     d                 pr                  extproc('xmlTextReaderStandalone')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)

      * Index lookup

     d xmlTextReaderByteConsumed...
     d                 pr                  extproc('xmlTextReaderByteConsumed')
     d                                     like(xmlClong)
     d  reader                             value like(xmlTextReaderPtr)

      * New more complete APIs for simpler creation and reuse of readers

     d xmlReaderWalker...
     d                 pr                  extproc('xmlReaderWalker')
     d                                     like(xmlTextReaderPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlReaderForDoc...
     d                 pr                  extproc('xmlReaderForDoc')
     d                                     like(xmlTextReaderPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderForFile...
     d                 pr                  extproc('xmlReaderForFile')
     d                                     like(xmlTextReaderPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderForMemory...
     d                 pr                  extproc('xmlReaderForMemory')
     d                                     like(xmlTextReaderPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderForFd  pr                  extproc('xmlReaderForFd')
     d                                     like(xmlTextReaderPtr)
     d  fd                                 value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderForIO  pr                  extproc('xmlReaderForIO')
     d                                     like(xmlTextReaderPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderNewWalker...
     d                 pr                  extproc('xmlReaderNewWalker')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlReaderNewDoc...
     d                 pr                  extproc('xmlReaderNewDoc')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderNewFile...
     d                 pr                  extproc('xmlReaderNewFile')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderNewMemory...
     d                 pr                  extproc('xmlReaderNewMemory')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderNewFd  pr                  extproc('xmlReaderNewFd')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  fd                                 value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReaderNewIO  pr                  extproc('xmlReaderNewIO')
     d                                     like(xmlCint)
     d  reader                             value like(xmlTextReaderPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

      * Error handling extensions

     d xmlTextReaderLocatorPtr...
     d                 s               *   based(######typedef######)           void *

      * xmlTextReaderErrorFunc:
      * @arg: the user argument
      * @msg: the message
      * @severity: the severity of the error
      * @locator: a locator indicating where the error occurred
      *
      * Signature of an error callback from a reader parser

     d xmlTextReaderErrorFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

     d xmlTextReaderLocatorLineNumber...
     d                 pr                  extproc(
     d                                     'xmlTextReaderLocatorLineNumber')
     d                                     like(xmlCint)
     d  locator                            value like(xmlTextReaderLocatorPtr)

     d xmlTextReaderLocatorBaseURI...
     d                 pr              *   extproc(                             xmlChar *
     d                                     'xmlTextReaderLocatorBaseURI')
     d  locator                            value like(xmlTextReaderLocatorPtr)

     d xmlTextReaderSetErrorHandler...
     d                 pr                  extproc(
     d                                     'xmlTextReaderSetErrorHandler')
     d  reader                             value like(xmlTextReaderPtr)
     d  f                                  value like(xmlTextReaderErrorFunc)
     d  arg                            *   value                                void *

     d xmlTextReaderSetStructuredErrorHandler...
     d                 pr                  extproc('xmlTextReaderSetStructuredE-
     d                                     rrorHandler')
     d  reader                             value like(xmlTextReaderPtr)
     d  f                                  value like(xmlStructuredErrorFunc)
     d  arg                            *   value                                void *

     d xmlTextReaderGetErrorHandler...
     d                 pr                  extproc(
     d                                     'xmlTextReaderGetErrorHandler')
     d  reader                             value like(xmlTextReaderPtr)
     d  f                                  like(xmlTextReaderErrorFunc)
     d  arg                            *                                        void *(*)

      /endif                                                                    LIBXML_READER_ENABLD
      /endif                                                                    XML_XMLREADER_H__
