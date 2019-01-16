      * Summary: interface for an HTML 4.0 non-verifying parser
      * Description: this module implements an HTML 4.0 non-verifying parser
      *              with API compatible with the XML parser ones. It should
      *              be able to parse "real world" HTML, even if severely
      *              broken from a specification point of view.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(HTML_PARSER_H__)
      /define HTML_PARSER_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_HTML_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/parser"

      * Most of the back-end structures from XML and HTML are shared.

     d htmlParserCtxtPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlParserCtxtPtr)

     d htmlParserCtxt  ds                  based(htmlParserCtxtPtr)
     d                                     likeds(xmlParserCtxt)

     d htmlParserNodeInfoPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlParserNodeInfoPtr)

     d htmlParserNodeInfo...
     d                 ds                  based(htmlParserNodeInfoPtr)
     d                                     likeds(xmlParserNodeInfo)

     d htmlSAXHandlerPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlSAXHandlerPtr)

     d htmlSAXHandler  ds                  based(htmlSAXHandlerPtr)
     d                                     likeds(xmlSAXHandler)

     d htmlParserInputPtr...
     d                 s                   based(######typedef######)
     d                                     like(xmlParserInputPtr)

     d htmlParserInput...
     d                 ds                  based(htmlParserInputPtr)
     d                                     likeds(xmlParserInput)

     d htmlDocPtr      s                   based(######typedef######)
     d                                     like(xmlDocPtr)

     d htmlNodePtr     s                   based(######typedef######)
     d                                     like(xmlNodePtr)

      * Internal description of an HTML element, representing HTML 4.01
      * and XHTML 1.0 (which share the same structure).

     d htmlElemDescPtr...
     d                 s               *   based(######typedef######)

     d htmlElemDesc    ds                  based(htmlElemDescPtr)
     d                                     align qualified
     d  name                           *                                        const char *
     d  startTag                           like(xmlCchar)                       Start tag implied ?
     d  endTag                             like(xmlCchar)                       End tag implied ?
     d  saveEndTag                         like(xmlCchar)                       Save end tag ?
     d  empty                              like(xmlCchar)                       Empty element ?
     d  depr                               like(xmlCchar)                       Deprecated element ?
     d  dtd                                like(xmlCchar)                       Loose DTD/Frameset
     d  isinline                           like(xmlCchar)                       Block 0/inline elem?
     d  desc                           *                                        const char *
      *
      * New fields encapsulating HTML structure
      *
      * Bugs:
      *      This is a very limited representation.  It fails to tell us when
      *      an element *requires* subelements (we only have whether they're
      *      allowed or not), and it doesn't tell us where CDATA and PCDATA
      *      are allowed.  Some element relationships are not fully represented:
      *      these are flagged with the word MODIFIER
      *
     d  subelts                        *                                        const char * *
     d  defaultsubelt                  *                                        const char *
     d  attrs_opt                      *                                        const char * *
     d  attrs_depr                     *                                        const char * *
     d  attrs_req                      *                                        const char * *

      * Internal description of an HTML entity.

     d htmlEntityDescPtr...
     d                 s               *   based(######typedef######)

     d htmlEntityDesc...
     d                 ds                  based(htmlEntityDescPtr)
     d                                     align qualified
     d  value                              like(xmlCuint)
     d  name                           *                                        const char *
     d  desc                           *                                        const char *

      * There is only few public functions.

     d htmlTagLookup   pr                  extproc('htmlTagLookup')
     d                                     like(htmlElemDescPtr)                const
     d  tag                            *   value options(*string)               const xmlChar *

     d htmlEntityLookup...
     d                 pr                  extproc('htmlEntityLookup')
     d                                     like(htmlEntityDescPtr)              const
     d  name                           *   value options(*string)               const xmlChar *

     d htmlEntityValueLookup...
     d                 pr                  extproc('htmlEntityValueLookup')
     d                                     like(htmlEntityDescPtr)              const
     d  value                              value like(xmlCuint)

     d htmlIsAutoClosed...
     d                 pr                  extproc('htmlIsAutoClosed')
     d                                     like(xmlCint)
     d  doc                                value like(htmlDocPtr)
     d  elem                               value like(htmlNodePtr)

     d htmlAutoCloseTag...
     d                 pr                  extproc('htmlAutoCloseTag')
     d                                     like(xmlCint)
     d  doc                                value like(htmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  elem                               value like(htmlNodePtr)

     d htmlParseEntityRef...
     d                 pr                  extproc('htmlParseEntityRef')
     d                                     like(htmlEntityDescPtr)              const
     d  ctxt                               value like(htmlParserCtxtPtr)
     d  str                            *                                        const xmlChar *(*)

     d htmlParseCharRef...
     d                 pr                  extproc('htmlParseCharRef')
     d                                     like(xmlCint)
     d  ctxt                               value like(htmlParserCtxtPtr)

     d htmlParseElement...
     d                 pr                  extproc('htmlParseElement')
     d  ctxt                               value like(htmlParserCtxtPtr)

     d htmlNewParserCtxt...
     d                 pr                  extproc('htmlNewParserCtxt')
     d                                     like(htmlParserCtxtPtr)

     d htmlCreateMemoryParserCtxt...
     d                 pr                  extproc('htmlCreateMemoryParserCtxt')
     d                                     like(htmlParserCtxtPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)

     d htmlParseDocument...
     d                 pr                  extproc('htmlParseDocument')
     d                                     like(xmlCint)
     d  ctxt                               value like(htmlParserCtxtPtr)

     d htmlSAXParseDoc...
     d                 pr                  extproc('htmlSAXParseDoc')
     d                                     like(htmlDocPtr)
     d  cur                            *   value options(*string)               xmlChar *
     d  encoding                       *   value options(*string)               const char *
     d  sax                                value like(htmlSAXHandlerPtr)
     d  userData                       *   value                                void *

     d htmlParseDoc    pr                  extproc('htmlParseDoc')
     d                                     like(htmlDocPtr)
     d  cur                            *   value options(*string)               xmlChar *
     d  encoding                       *   value options(*string)               const char *

     d htmlSAXParseFile...
     d                 pr                  extproc('htmlSAXParseFile')
     d                                     like(htmlDocPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  sax                                value like(htmlSAXHandlerPtr)
     d  userData                       *   value                                void *

     d htmlParseFile   pr                  extproc('htmlParseFile')
     d                                     like(htmlDocPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *

     d UTF8ToHtml      pr                  extproc('UTF8ToHtml')
     d                                     like(xmlCint)
     d  out                       65535    options(*varsize)                    unsigned char []
     d  outlen                             like(xmlCint)
     d  in                             *   value options(*string)               const unsigned char*
     d  inlen                              like(xmlCint)

     d htmlEncodeEntities...
     d                 pr                  extproc('htmlEncodeEntities')
     d                                     like(xmlCint)
     d  out                       65535    options(*varsize)                    unsigned char []
     d  outlen                             like(xmlCint)
     d  in                             *   value options(*string)               const unsigned char*
     d  inlen                              like(xmlCint)
     d  quoteChar                          value like(xmlCint)

     d htmlIsScriptAttribute...
     d                 pr                  extproc('htmlIsScriptAttribute')
     d                                     like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *

     d htmlHandleOmittedElem...
     d                 pr                  extproc('htmlHandleOmittedElem')
     d                                     like(xmlCint)
     d  val                                value like(xmlCint)

      /if defined(LIBXML_PUSH_ENABLED)

      * Interfaces for the Push mode.

     d htmlCreatePushParserCtxt...
     d                 pr                  extproc('htmlCreatePushParserCtxt')
     d                                     like(htmlParserCtxtPtr)
     d  sax                                value like(htmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  enc                                value like(xmlCharEncoding)

     d htmlParseChunk  pr                  extproc('htmlParseChunk')
     d                                     like(xmlCint)
     d  ctxt                               value like(htmlParserCtxtPtr)
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  terminate                          value like(xmlCint)
      /endif                                                                    LIBXML_PUSH_ENABLED

     d htmlFreeParserCtxt...
     d                 pr                  extproc('htmlFreeParserCtxt')
     d  ctxt                               value like(htmlParserCtxtPtr)

      * New set of simpler/more flexible APIs

      * xmlParserOption:
      *
      * This is the set of XML parser options that can be passed down
      * to the xmlReadDoc() and similar calls.

     d htmlParserOption...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  HTML_PARSE_RECOVER...                                                   Relaxed parsing
     d                 c                   X'00000001'
     d  HTML_PARSE_NODEFDTD...                                                  No default doctype
     d                 c                   X'00000004'
     d  HTML_PARSE_NOERROR...                                                   No error reports
     d                 c                   X'00000020'
     d  HTML_PARSE_NOWARNING...                                                 No warning reports
     d                 c                   X'00000040'
     d  HTML_PARSE_PEDANTIC...                                                  Pedantic err reports
     d                 c                   X'00000080'
     d  HTML_PARSE_NOBLANKS...                                                  Remove blank nodes
     d                 c                   X'00000100'
     d  HTML_PARSE_NONET...                                                     Forbid net access
     d                 c                   X'00000800'
     d  HTML_PARSE_NOIMPLIED...                                                 No implied html/body
     d                 c                   X'00002000'
     d  HTML_PARSE_COMPACT...                                                   compact small txtnod
     d                 c                   X'00010000'
     d  HTML_PARSE_IGNORE_ENC...                                                Ignore encoding hint
     d                 c                   X'00200000'

     d htmlCtxtReset   pr                  extproc('htmlCtxtReset')
     d ctxt                                value like(htmlParserCtxtPtr)

     d htmlCtxtUseOptions...
     d                 pr                  extproc('htmlCtxtUseOptions')
     d                                     like(xmlCint)
     d ctxt                                value like(htmlParserCtxtPtr)
     d options                             value like(xmlCint)

     d htmlReadDoc     pr                  extproc('htmlReadDoc')
     d                                     like(htmlDocPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlReadFile    pr                  extproc('htmlReadFile')
     d                                     like(htmlDocPtr)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlReadMemory  pr                  extproc('htmlReadMemory')
     d                                     like(htmlDocPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlReadFd      pr                  extproc('htmlReadFd')
     d                                     like(htmlDocPtr)
     d  fd                                 value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlReadIO      pr                  extproc('htmlReadIO')
     d                                     like(htmlDocPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlCtxtReadDoc...
     d                 pr                  extproc('htmlCtxtReadDoc')
     d                                     like(htmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlCtxtReadFile...
     d                 pr                  extproc('htmlCtxtReadFile')
     d                                     like(htmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlCtxtReadMemory...
     d                 pr                  extproc('htmlCtxtReadMemory')
     d                                     like(htmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlCtxtReadFd  pr                  extproc('htmlCtxtReadFd')
     d                                     like(htmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  fd                                 value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d htmlCtxtReadIO  pr                  extproc('htmlCtxtReadIO')
     d                                     like(htmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

      * Further knowledge of HTML structure

     d htmlStatus      s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  HTML_NA        c                   X'0000'                              No check at all
     d  HTML_INVALID   c                   X'0001'
     d  HTML_DEPRECATED...
     d                 c                   X'0002'
     d  HTML_VALID     c                   X'0004'
     d  HTML_REQUIRED  c                   X'000C'                              HTML_VALID ored-in

      * Using htmlElemDesc rather than name here, to emphasise the fact
      *  that otherwise there's a lookup overhead

     d htmlAttrAllowed...
     d                 pr                  extproc('htmlAttrAllowed')
     d                                     like(htmlStatus)
     d  #param1                            value like(htmlElemDescPtr)          const
     d  #param2                        *   value options(*string)               const xmlChar *
     d  #param3                            value like(xmlCint)

     d htmlElementAllowedHere...
     d                 pr                  extproc('htmlElementAllowedHere')
     d                                     like(xmlCint)
     d  #param1                            value like(htmlElemDescPtr)          const
     d  #param2                        *   value options(*string)               const xmlChar *

     d htmlElementStatusHere...
     d                 pr                  extproc('htmlElementStatusHere')
     d                                     like(htmlStatus)
     d  #param1                            value like(htmlElemDescPtr)          const
     d  #param2                            value like(htmlElemDescPtr)          const

     d htmlNodeStatus  pr                  extproc('htmlNodeStatus')
     d                                     like(htmlStatus)
     d  #param1                            value like(htmlNodePtr)
     d  #param2                            value like(xmlCint)

      * C macros implemented as procedures for ILE/RPG support.

     d htmlDefaultSubelement...
     d                 pr              *   extproc('__htmlDefaultSubelement')   const char *
     d  elt                            *   value                                const htmlElemDesc *

     d htmlElementAllowedHereDesc...
     d                 pr                  extproc(
     d                                     '__htmlElementAllowedHereDesc')
     d                                     like(xmlCint)
     d  parent                         *   value                                const htmlElemDesc *
     d  elt                            *   value                                const htmlElemDesc *

     d htmlRequiredAttrs...
     d                 pr              *   extproc('__htmlRequiredAttrs')        const char * *
     d  elt                            *   value                                const htmlElemDesc *

      /endif                                                                    LIBXML_HTML_ENABLED
      /endif                                                                    HTML_PARSER_H__
