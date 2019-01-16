      * Summary: pattern expression handling
      * Description: allows to compile and test pattern expressions for nodes
      *              either in a tree or based on a parser state.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_PATTERN_H__)
      /define XML_PATTERN_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_PATTERN_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/dict"

      * xmlPattern:
      *
      * A compiled (XPath based) pattern to select nodes

     d xmlPatternPtr...
     d                 s               *   based(######typedef######)

      * xmlPatternFlags:
      *
      * This is the set of options affecting the behaviour of pattern
      * matching with this module

     d xmlPatternFlags...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_PATTERN_DEFAULT...                                                  Simple pattern match
     d                 c                   X'0000'
     d  XML_PATTERN_XPATH...                                                    Std XPath pattern
     d                 c                   X'0001'
     d  XML_PATTERN_XSSEL...                                                    Schm sel XPth subset
     d                 c                   X'0002'
     d  XML_PATTERN_XSFIELD...                                                  Schm fld XPth subset
     d                 c                   X'0004'

     d xmlFreePattern  pr                  extproc('xmlFreePattern')
     d  comp                               value like(xmlPatternPtr)

     d xmlFreePatternList...
     d                 pr                  extproc('xmlFreePatternList')
     d  comp                               value like(xmlPatternPtr)

     d xmlPatterncompile...
     d                 pr                  extproc('xmlPatterncompile')
     d                                     like(xmlPatternPtr)
     d  pattern                        *   value options(*string)               const xmlChar *
     d  dict                           *   value                                xmlDict *
     d  flags                              value like(xmlCint)
     d  namespaces                     *                                        const xmlChar *(*)

     d xmlPatternMatch...
     d                 pr                  extproc('xmlPatternMatch')
     d                                     like(xmlCint)
     d  comp                               value like(xmlPatternPtr)
     d  node                               value like(xmlNodePtr)

      * streaming interfaces

     d xmlStreamCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlPatternStreamable...
     d                 pr                  extproc('xmlPatternStreamable')
     d                                     like(xmlCint)
     d  comp                               value like(xmlPatternPtr)

     d xmlPatternMaxDepth...
     d                 pr                  extproc('xmlPatternMaxDepth')
     d                                     like(xmlCint)
     d  comp                               value like(xmlPatternPtr)

     d xmlPatternMinDepth...
     d                 pr                  extproc('xmlPatternMinDepth')
     d                                     like(xmlCint)
     d  comp                               value like(xmlPatternPtr)

     d xmlPatternFromRoot...
     d                 pr                  extproc('xmlPatternFromRoot')
     d                                     like(xmlCint)
     d  comp                               value like(xmlPatternPtr)

     d xmlPatternGetStreamCtxt...
     d                 pr                  extproc('xmlPatternGetStreamCtxt')
     d                                     like(xmlStreamCtxtPtr)
     d  comp                               value like(xmlPatternPtr)

     d xmlFreeStreamCtxt...
     d                 pr                  extproc('xmlFreeStreamCtxt')
     d  stream                             value like(xmlStreamCtxtPtr)

     d xmlStreamPushNode...
     d                 pr                  extproc('xmlStreamPushNode')
     d                                     like(xmlCint)
     d  stream                             value like(xmlStreamCtxtPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  ns                             *   value options(*string)               const xmlChar *
     d  nodeType                           value like(xmlCint)

     d xmlStreamPush   pr                  extproc('xmlStreamPush')
     d                                     like(xmlCint)
     d  stream                             value like(xmlStreamCtxtPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  ns                             *   value options(*string)               const xmlChar *

     d xmlStreamPushAttr...
     d                 pr                  extproc('xmlStreamPushAttr')
     d                                     like(xmlCint)
     d  stream                             value like(xmlStreamCtxtPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  ns                             *   value options(*string)               const xmlChar *

     d xmlStreamPop    pr                  extproc('xmlStreamPop')
     d                                     like(xmlCint)
     d  stream                             value like(xmlStreamCtxtPtr)

     d xmlStreamWantsAnyNode...
     d                 pr                  extproc('xmlStreamWantsAnyNode')
     d                                     like(xmlCint)
     d  stream                             value like(xmlStreamCtxtPtr)

      /endif                                                                    LIBXML_PATTERN_ENBLD
      /endif                                                                    XML_PATTERN_H__
