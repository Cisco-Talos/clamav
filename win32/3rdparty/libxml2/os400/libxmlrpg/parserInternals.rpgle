      * Summary: internals routines and limits exported by the parser.
      * Description: this module exports a number of internal parsing routines
      *              they are not really all intended for applications but
      *              can prove useful doing low level processing.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_PARSER_INTERNALS_H__)
      /define XML_PARSER_INTERNALS_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/parser"
      /include "libxmlrpg/HTMLparser"
      /include "libxmlrpg/chvalid"

      * xmlParserMaxDepth:
      *
      * arbitrary depth limit for the XML documents that we allow to
      * process. This is not a limitation of the parser but a safety
      * boundary feature, use XML_PARSE_HUGE option to override it.

     d xmlParserMaxDepth...
     d                 s                   import('xmlParserMaxDepth')
     d                                     like(xmlCuint)

      * XML_MAX_TEXT_LENGTH:
      *
      * Maximum size allowed for a single text node when building a tree.
      * This is not a limitation of the parser but a safety boundary feature,
      * use XML_PARSE_HUGE option to override it.
      * Introduced in 2.9.0

     d XML_MAX_TEXT_LENGTH...
     d                 c                   10000000

      * XML_MAX_NAME_LENGTH:
      *
      * Maximum size allowed for a markup identitier
      * This is not a limitation of the parser but a safety boundary feature,
      * use XML_PARSE_HUGE option to override it.
      * Note that with the use of parsing dictionaries overriding the limit
      * may result in more runtime memory usage in face of "unfriendly' content
      * Introduced in 2.9.0

     d XML_MAX_NAME_LENGTH...
     d                 c                   50000

      * XML_MAX_DICTIONARY_LIMIT:
      *
      * Maximum size allowed by the parser for a dictionary by default
      * This is not a limitation of the parser but a safety boundary feature,
      * use XML_PARSE_HUGE option to override it.
      * Introduced in 2.9.0

     d XML_MAX_DICTIONARY_LIMIT...
     d                 c                   10000000

      * XML_MAX_LOOKUP_LIMIT:
      *
      * Maximum size allowed by the parser for ahead lookup
      * This is an upper boundary enforced by the parser to avoid bad
      * behaviour on "unfriendly' content
      * Introduced in 2.9.0

     d XML_MAX_LOOKUP_LIMIT...
     d                 c                   10000000

      * XML_MAX_NAMELEN:
      *
      * Identifiers can be longer, but this will be more costly
      * at runtime.

     d XML_MAX_NAMELEN...
     d                 c                   100

      * INPUT_CHUNK:
      *
      * The parser tries to always have that amount of input ready.
      * One of the point is providing context when reporting errors.

     d INPUT_CHUNK     c                   250

      * Global variables used for predefined strings.

     d xmlStringText   s              4    import('xmlStringText')              \0 in 5th byte

     d xmlStringTextNoenc...
     d                 s              9    import('xmlStringTextNoenc')         \0 in 10th byte

     d xmlStringComment...
     d                 s              7    import('xmlStringComment')           \0 in 8th byte

      * Function to finish the work of the macros where needed.

     d xmlIsLetter     pr                  extproc('xmlIsLetter')
     d                                     like(xmlCint)
     d c                                   value like(xmlCint)

      * Parser context.

     d xmlCreateFileParserCtxt...
     d                 pr                  extproc('xmlCreateFileParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d filename                        *   value options(*string)               const char *

     d xmlCreateURLParserCtxt...
     d                 pr                  extproc('xmlCreateURLParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d filename                        *   value options(*string)               const char *
     d options                             value like(xmlCint)

     d xmlCreateMemoryParserCtxt...
     d                 pr                  extproc('xmlCreateMemoryParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d buffer                          *   value options(*string)               const char *
     d size                                value like(xmlCint)

     d xmlCreateEntityParserCtxt...
     d                 pr                  extproc('xmlCreateEntityParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d URL                             *   value options(*string)               const xmlChar *
     d ID                              *   value options(*string)               const xmlChar *
     d base                            *   value options(*string)               const xmlChar *

     d xmlSwitchEncoding...
     d                 pr                  extproc('xmlSwitchEncoding')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d enc                                 value like(xmlCharEncoding)

     d xmlSwitchToEncoding...
     d                 pr                  extproc('xmlSwitchToEncoding')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d handler                             value like(xmlCharEncodingHandlerPtr)

     d xmlSwitchInputEncoding...
     d                 pr                  extproc('xmlSwitchInputEncoding')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d input                               value like(xmlParserInputPtr)
     d handler                             value like(xmlCharEncodingHandlerPtr)

      * Input Streams.

     d xmlNewStringInputStream...
     d                 pr                  extproc('xmlNewStringInputStream')
     d                                     like(xmlParserInputPtr)
     d ctxt                                value like(xmlParserCtxtPtr)
     d buffer                          *   value options(*string)               const xmlChar *

     d xmlNewEntityInputStream...
     d                 pr                  extproc('xmlNewEntityInputStream')
     d                                     like(xmlParserInputPtr)
     d ctxt                                value like(xmlParserCtxtPtr)
     d entity                              value like(xmlEntityPtr)

     d xmlPushInput    pr                  extproc('xmlPushInput')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d input                               value like(xmlParserInputPtr)

     d xmlPopInput     pr                  extproc('xmlPopInput')
     d                                     like(xmlChar)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlFreeInputStream...
     d                 pr                  extproc('xmlFreeInputStream')
     d input                               value like(xmlParserInputPtr)

     d xmlNewInputFromFile...
     d                 pr                  extproc('xmlNewInputFromFile')
     d                                     like(xmlParserInputPtr)
     d ctxt                                value like(xmlParserCtxtPtr)
     d filename                        *   value options(*string)               const char *

     d xmlNewInputStream...
     d                 pr                  extproc('xmlNewInputStream')
     d                                     like(xmlParserInputPtr)
     d ctxt                                value like(xmlParserCtxtPtr)

      * Namespaces.

     d xmlSplitQName   pr              *   extproc('xmlSplitQName')             xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d name                            *   value options(*string)               const xmlChar *
     d prefix                          *                                        xmlChar *(*)

      * Generic production rules.

     d xmlParseName    pr              *   extproc('xmlParseName')              const xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseNmtoken...
     d                 pr              *   extproc('xmlParseNmtoken')           xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEntityValue...
     d                 pr              *   extproc('xmlParseEntityValue')       xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d orig                            *                                        xmlChar *(*)

     d xmlParseAttValue...
     d                 pr              *   extproc('xmlParseAttValue')          xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseSystemLiteral...
     d                 pr              *   extproc('xmlParseSystemLiteral')     xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParsePubidLiteral...
     d                 pr              *   extproc('xmlParsePubidLiteral')      xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseCharData...
     d                 pr                  extproc('xmlParseCharData')
     d ctxt                                value like(xmlParserCtxtPtr)
     d cdata                               value like(xmlCint)

     d xmlParseExternalID...
     d                 pr              *   extproc('xmlParseExternalID')        xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d publicID                        *                                        xmlChar *(*)
     d strict                              value like(xmlCint)

     d xmlParseComment...
     d                 pr                  extproc('xmlParseComment')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParsePITarget...
     d                 pr              *   extproc('xmlParsePITarget')          const xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParsePI      pr                  extproc('xmlParsePI')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseNotationDecl...
     d                 pr                  extproc('xmlParseNotationDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEntityDecl...
     d                 pr                  extproc('xmlParseEntityDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseDefaultDecl...
     d                 pr                  extproc('xmlParseDefaultDecl')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d value                           *                                        xmlChar *(*)

     d xmlParseNotationType...
     d                 pr                  extproc('xmlParseNotationType')
     d                                     like(xmlEnumerationPtr)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEnumerationType...
     d                 pr                  extproc('xmlParseEnumerationType')
     d                                     like(xmlEnumerationPtr)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEnumeratedType...
     d                 pr                  extproc('xmlParseEnumeratedType')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d tree                            *   value                                xmlEnumerationPtr *

     d xmlParseAttributeType...
     d                 pr                  extproc('xmlParseAttributeType')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d tree                            *   value                                xmlEnumerationPtr *

     d xmlParseAttributeListDecl...
     d                 pr                  extproc('xmlParseAttributeListDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseElementMixedContentDecl...
     d                 pr                  extproc(
     d                                     'xmlParseElementMixedContentDecl')
     d                                     like(xmlElementContentPtr)
     d ctxt                                value like(xmlParserCtxtPtr)
     d inputchk                            value like(xmlCint)

     d xmlParseElementChildrenContentDecl...
     d                 pr                  extproc(
     d                                     'xmlParseElementChildrenContentDecl')
     d                                     like(xmlElementContentPtr)
     d ctxt                                value like(xmlParserCtxtPtr)
     d inputchk                            value like(xmlCint)

     d xmlParseElementContentDecl...
     d                 pr                  extproc('xmlParseElementContentDecl')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d name                            *   value options(*string)               const xmlChar *
     d result                          *   value                                xmlElementContentPtr
     d                                                                          *

     d xmlParseElementDecl...
     d                 pr                  extproc('xmlParseElementDecl')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseMarkupDecl...
     d                 pr                  extproc('xmlParseMarkupDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseCharRef...
     d                 pr                  extproc('xmlParseCharRef')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEntityRef...
     d                 pr                  extproc('xmlParseEntityRef')
     d                                     like(xmlEntityPtr)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseReference...
     d                 pr                  extproc('xmlParseReference')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParsePEReference...
     d                 pr                  extproc('xmlParsePEReference')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseDocTypeDecl...
     d                 pr                  extproc('xmlParseDocTypeDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

      /if defined(LIBXML_SAX1_ENABLED)
     d xmlParseAttribute...
     d                 pr              *   extproc('xmlParseAttribute')         const xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d value                           *                                        xmlChar *(*)

     d xmlParseStartTag...
     d                 pr              *   extproc('xmlParseStartTag')          const xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEndTag  pr                  extproc('xmlParseEndTag')
     d ctxt                                value like(xmlParserCtxtPtr)
      /endif                                                                    LIBXML_SAX1_ENABLED

     d xmlParseCDSect  pr                  extproc('xmlParseCDSect')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseContent...
     d                 pr                  extproc('xmlParseContent')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseElement...
     d                 pr                  extproc('xmlParseElement')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseVersionNum...
     d                 pr              *   extproc('xmlParseVersionNum')        xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseVersionInfo...
     d                 pr              *   extproc('xmlParseVersionInfo')       xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEncName...
     d                 pr              *   extproc('xmlParseEncName')           xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseEncodingDecl...
     d                 pr              *   extproc('xmlParseEncodingDecl')      const xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseSDDecl  pr                  extproc('xmlParseSDDecl')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseXMLDecl...
     d                 pr                  extproc('xmlParseXMLDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseTextDecl...
     d                 pr                  extproc('xmlParseTextDecl')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseMisc    pr                  extproc('xmlParseMisc')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseExternalSubset...
     d                 pr                  extproc('xmlParseExternalSubset')
     d ctxt                                value like(xmlParserCtxtPtr)
     d ExternalID                      *   value options(*string)               const xmlChar *
     d SystemID                        *   value options(*string)               const xmlChar *

      * XML_SUBSTITUTE_NONE:
      *
      * If no entities need to be substituted.

     d XML_SUBSTITUTE_NONE...
     d                 c                   0

      * XML_SUBSTITUTE_REF:
      *
      * Whether general entities need to be substituted.

     d XML_SUBSTITUTE_REF...
     d                 c                   1

      * XML_SUBSTITUTE_PEREF:
      *
      * Whether parameter entities need to be substituted.

     d XML_SUBSTITUTE_PEREF...
     d                 c                   2

      * XML_SUBSTITUTE_BOTH:
      *
      * Both general and parameter entities need to be substituted.

     d XML_SUBSTITUTE_BOTH...
     d                 c                   3

     d xmlStringDecodeEntities...
     d                 pr              *   extproc('xmlStringDecodeEntities')   xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d str                             *   value options(*string)               const xmlChar *
     d what                                value like(xmlCint)
     d end                                 value like(xmlChar)
     d end2                                value like(xmlChar)
     d end3                                value like(xmlChar)

     d xmlStringLenDecodeEntities...
     d                 pr              *   extproc('xmlStringLenDecodeEntities')xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d str                             *   value options(*string)               const xmlChar *
     d len                                 value like(xmlCint)
     d what                                value like(xmlCint)
     d end                                 value like(xmlChar)
     d end2                                value like(xmlChar)
     d end3                                value like(xmlChar)

      * Generated by MACROS on top of parser.c c.f. PUSH_AND_POP.

     d nodePush        pr                  extproc('nodePush')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d value                               value like(xmlNodePtr)

     d nodePop         pr                  extproc('nodePop')
     d                                     like(xmlNodePtr)
     d ctxt                                value like(xmlParserCtxtPtr)

     d inputPush       pr                  extproc('inputPush')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d value                               value like(xmlParserInputPtr)

     d inputPop        pr                  extproc('inputPop')
     d                                     like(xmlParserInputPtr)
     d ctxt                                value like(xmlParserCtxtPtr)

     d namePop         pr              *   extproc('namePop')                   const xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d namePush        pr                  extproc('namePush')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d value                           *   value options(*string)               const xmlChar *

      * other commodities shared between parser.c and parserInternals.

     d xmlSkipBlankChars...
     d                 pr                  extproc('xmlSkipBlankChars')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlStringCurrentChar...
     d                 pr                  extproc('xmlStringCurrentChar')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d cur                             *   value options(*string)               const xmlChar *
     d len                             *   value                                int *

     d xmlParserHandlePEReference...
     d                 pr                  extproc('xmlParserHandlePEReference')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlCheckLanguageID...
     d                 pr                  extproc('xmlCheckLanguageID')
     d                                     like(xmlCint)
     d lang                            *   value options(*string)               const xmlChar *

      * Really core function shared with HTML parser.

     d xmlCurrentChar  pr                  extproc('xmlCurrentChar')
     d                                     like(xmlCint)
     d ctxt                                value like(xmlParserCtxtPtr)
     d len                             *   value                                int *

     d xmlCopyCharMultiByte...
     d                 pr                  extproc('xmlCopyCharMultiByte')
     d                                     like(xmlCint)
     d out                             *   value options(*string)               xmlChar *
     d val                                 value like(xmlCint)

     d xmlCopyChar     pr                  extproc('xmlCopyChar')
     d                                     like(xmlCint)
     d len                                 value like(xmlCint)
     d out                             *   value options(*string)               xmlChar *
     d val                                 value like(xmlCint)

     d xmlNextChar     pr                  extproc('xmlNextChar')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParserInputShrink...
     d                 pr                  extproc('xmlParserInputShrink')
     d in                                  value like(xmlParserInputPtr)

      /if defined(LIBXML_HTML_ENABLED)

      * Actually comes from the HTML parser but launched from the init stuff.

     d htmlInitAutoClose...
     d                 pr                  extproc('htmlInitAutoClose')

     d htmlCreateFileParserCtxt...
     d                 pr                  extproc('htmlCreateFileParserCtxt')
     d                                     like(htmlParserCtxtPtr)
     d filename                        *   value options(*string)               const char *
     d encoding                        *   value options(*string)               const char *
      /endif

      * Specific function to keep track of entities references
      * and used by the XSLT debugger.

      /if defined(LIBXML_LEGACY_ENABLED)
      * xmlEntityReferenceFunc:
      * @ent: the entity
      * @firstNode:  the fist node in the chunk
      * @lastNode:  the last nod in the chunk
      *
      * Callback function used when one needs to be able to track back the
      * provenance of a chunk of nodes inherited from an entity replacement.

     d xmlEntityReferenceFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

     d xmlSetEntityReferenceFunc...
     d                 pr                  extproc('xmlSetEntityReferenceFunc')
     d func                                value like(xmlEntityReferenceFunc)

     d xmlParseQuotedString...
     d                 pr              *   extproc('xmlParseQuotedString')      xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParseNamespace...
     d                 pr                  extproc('xmlParseNamespace')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlNamespaceParseNSDef...
     d                 pr              *   extproc('xmlNamespaceParseNSDef')    xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlScanName     pr              *   extproc('xmlScanName')               xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlNamespaceParseNCName...
     d                 pr              *   extproc('xmlNamespaceParseNCName')   xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlParserHandleReference...
     d                 pr                  extproc('xmlParserHandleReference')
     d ctxt                                value like(xmlParserCtxtPtr)

     d xmlNamespaceParseQName...
     d                 pr              *   extproc('xmlNamespaceParseQName')    xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d prefix                          *                                        xmlChar *(*)

      * Entities

     d xmlDecodeEntities...
     d                 pr              *   extproc('xmlDecodeEntities')         xmlChar *
     d ctxt                                value like(xmlParserCtxtPtr)
     d len                                 value like(xmlCint)
     d what                                value like(xmlCint)
     d end                                 value like(xmlChar)
     d end2                                value like(xmlChar)
     d end3                                value like(xmlChar)

     d xmlHandleEntity...
     d                 pr                  extproc('xmlHandleEntity')
     d ctxt                                value like(xmlParserCtxtPtr)
     d entity                              value like(xmlEntityPtr)
      /endif                                                                    LIBXML_LEGACY_ENABLD

      /endif
