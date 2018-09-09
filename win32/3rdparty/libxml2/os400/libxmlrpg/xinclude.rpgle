      * Summary: implementation of XInclude
      * Description: API to handle XInclude processing,
      * implements the
      * World Wide Web Consortium Last Call Working Draft 10 November 2003
      * http://www.w3.org/TR/2003/WD-xinclude-20031110
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_XINCLUDE_H__)
      /define XML_XINCLUDE_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"

      /if defined(LIBXML_XINCLUDE_ENABLED)

      * XINCLUDE_NS:
      *
      * Macro defining the Xinclude namespace: http://www.w3.org/2003/XInclude

     d XINCLUDE_NS     c                   'http://www.w3.org/2003/XInclude'


      * XINCLUDE_OLD_NS:
      *
      * Define the draft Xinclude namespace: http://www.w3.org/2001/XInclude

     d XINCLUDE_OLD_NS...
     d                 c                   'http://www.w3.org/2001/XInclude'

      * XINCLUDE_NODE:
      *
      * Macro defining "include"

     d XINCLUDE_NODE   c                   'include'

      * XINCLUDE_FALLBACK:
      *
      * Macro defining "fallback"

     d XINCLUDE_FALLBACK...
     d                 c                   'fallback'

      * XINCLUDE_HREF:
      *
      * Macro defining "href"

     d XINCLUDE_HREF   c                   'href'

      * XINCLUDE_PARSE:
      *
      * Macro defining "parse"

     d XINCLUDE_PARSE  c                   'parse'

      * XINCLUDE_PARSE_XML:
      *
      * Macro defining "xml"

     d XINCLUDE_PARSE_XML...
     d                 c                   'xml'

      * XINCLUDE_PARSE_TEXT:
      *
      * Macro defining "text"

     d XINCLUDE_PARSE_TEXT...
     d                 c                   'text'

      * XINCLUDE_PARSE_ENCODING:
      *
      * Macro defining "encoding"

     d XINCLUDE_PARSE_ENCODING...
     d                 c                   'encoding'

      * XINCLUDE_PARSE_XPOINTER:
      *
      * Macro defining "xpointer"

     d XINCLUDE_PARSE_XPOINTER...
     d                 c                   'xpointer'

     d xmlXIncludeCtxtPtr...
     d                 s               *   based(######typedef######)

      * standalone processing

     d xmlXIncludeProcess...
     d                 pr                  extproc('xmlXIncludeProcess')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)

     d xmlXIncludeProcessFlags...
     d                 pr                  extproc('xmlXIncludeProcessFlags')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  flags                              value like(xmlCint)

     d xmlXIncludeProcessFlagsData...
     d                 pr                  extproc(
     d                                     'xmlXIncludeProcessFlagsData')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  flags                              value like(xmlCint)
     d  data                           *   value                                void *

     d xmlXIncludeProcessTreeFlagsData...
     d                 pr                  extproc(
     d                                     'xmlXIncludeProcessTreeFlagsData')
     d                                     like(xmlCint)
     d  tree                               value like(xmlNodePtr)
     d  flags                              value like(xmlCint)
     d  data                           *   value                                void *

     d xmlXIncludeProcessTree...
     d                 pr                  extproc('xmlXIncludeProcessTree')
     d                                     like(xmlCint)
     d  tree                               value like(xmlNodePtr)

     d xmlXIncludeProcessTreeFlags...
     d                 pr                  extproc(
     d                                     'xmlXIncludeProcessTreeFlags')
     d                                     like(xmlCint)
     d  tree                               value like(xmlNodePtr)
     d  flags                              value like(xmlCint)


      * contextual processing

     d xmlXIncludeNewContext...
     d                 pr                  extproc('xmlXIncludeNewContext')
     d                                     like(xmlXIncludeCtxtPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlXIncludeSetFlags...
     d                 pr                  extproc('xmlXIncludeSetFlags')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlXIncludeCtxtPtr)
     d  flags                              value like(xmlCint)

     d xmlXIncludeFreeContext...
     d                 pr                  extproc('xmlXIncludeFreeContext')
     d  ctxt                               value like(xmlXIncludeCtxtPtr)

     d xmlXIncludeProcessNode...
     d                 pr                  extproc('xmlXIncludeProcessNode')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlXIncludeCtxtPtr)
     d  tree                               value like(xmlNodePtr)

      /endif                                                                    XINCLUDE_ENABLED
      /endif                                                                    XML_XINCLUDE_H__
