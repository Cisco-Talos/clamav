      * Summary: API to handle XML Pointers
      * Description: API to handle XML Pointers
      * Base implementation was made accordingly to
      * W3C Candidate Recommendation 7 June 2000
      * http://www.w3.org/TR/2000/CR-xptr-20000607
      *
      * Added support for the element() scheme described in:
      * W3C Proposed Recommendation 13 November 2002
      * http://www.w3.org/TR/2002/PR-xptr-element-20021113/
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_XPTR_H__)
      /define XML_XPTR_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_XPTR_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/xpath"

      * A Location Set

     d xmlLocationSetPtr...
     d                 s               *   based(######typedef######)

     d xmlLocationSet  ds                  based(xmlLocationSetPtr)
     d                                     align qualified
     d  locNr                              like(xmlCint)                        # locations in set
     d  locMax                             like(xmlCint)                        Max locations in set
     d  locTab                         *                                        xmlXPathObjectPtr *

      * Handling of location sets.

     d xmlXPtrLocationSetCreate...
     d                 pr                  extproc('xmlXPtrLocationSetCreate')
     d                                     like(xmlLocationSetPtr)
     d val                                 value like(xmlXPathObjectPtr)

     d xmlXPtrFreeLocationSet...
     d                 pr                  extproc('xmlXPtrFreeLocationSet')
     d obj                                 value like(xmlLocationSetPtr)

     d xmlXPtrLocationSetMerge...
     d                 pr                  extproc('xmlXPtrLocationSetMerge')
     d                                     like(xmlLocationSetPtr)
     d val1                                value like(xmlLocationSetPtr)
     d val2                                value like(xmlLocationSetPtr)

     d xmlXPtrNewRange...
     d                 pr                  extproc('xmlXPtrNewRange')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlNodePtr)
     d startindex                          value like(xmlCint)
     d end                                 value like(xmlNodePtr)
     d endindex                            value like(xmlCint)

     d xmlXPtrNewRangePoints...
     d                 pr                  extproc('xmlXPtrNewRangePoints')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlXPathObjectPtr)
     d end                                 value like(xmlXPathObjectPtr)

     d xmlXPtrNewRangeNodePoint...
     d                 pr                  extproc('xmlXPtrNewRangeNodePoint')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlNodePtr)
     d end                                 value like(xmlXPathObjectPtr)

     d xmlXPtrNewRangePointNode...
     d                 pr                  extproc('xmlXPtrNewRangePointNode')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlXPathObjectPtr)
     d end                                 value like(xmlNodePtr)

     d xmlXPtrNewRangeNodes...
     d                 pr                  extproc('xmlXPtrNewRangeNodes')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlNodePtr)
     d end                                 value like(xmlNodePtr)

     d xmlXPtrNewLocationSetNodes...
     d                 pr                  extproc('xmlXPtrNewLocationSetNodes')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlNodePtr)
     d end                                 value like(xmlNodePtr)

     d xmlXPtrNewLocationSetNodeSet...
     d                 pr                  extproc(
     d                                     'xmlXPtrNewLocationSetNodeSet')
     d                                     like(xmlXPathObjectPtr)
     d set                                 value like(xmlNodeSetPtr)

     d xmlXPtrNewRangeNodeObject...
     d                 pr                  extproc('xmlXPtrNewRangeNodeObject')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlNodePtr)
     d end                                 value like(xmlXPathObjectPtr)

     d xmlXPtrNewCollapsedRange...
     d                 pr                  extproc('xmlXPtrNewCollapsedRange')
     d                                     like(xmlXPathObjectPtr)
     d start                               value like(xmlNodePtr)

     d xmlXPtrLocationSetAdd...
     d                 pr                  extproc('xmlXPtrLocationSetAdd')
     d cur                                 value like(xmlLocationSetPtr)
     d val                                 value like(xmlXPathObjectPtr)

     d xmlXPtrWrapLocationSet...
     d                 pr                  extproc('xmlXPtrWrapLocationSet')
     d                                     like(xmlXPathObjectPtr)
     d val                                 value like(xmlLocationSetPtr)

     d xmlXPtrLocationSetDel...
     d                 pr                  extproc('xmlXPtrLocationSetDel')
     d cur                                 value like(xmlLocationSetPtr)
     d val                                 value like(xmlXPathObjectPtr)

     d xmlXPtrLocationSetRemove...
     d                 pr                  extproc('xmlXPtrLocationSetRemove')
     d cur                                 value like(xmlLocationSetPtr)
     d val                                 value like(xmlCint)

      * Functions.

     d xmlXPtrNewContext...
     d                 pr                  extproc('xmlXPtrNewContext')
     d                                     like(xmlXPathContextPtr)
     d doc                                 value like(xmlDocPtr)
     d here                                value like(xmlNodePtr)
     d origin                              value like(xmlNodePtr)

     d xmlXPtrEval     pr                  extproc('xmlXPtrEval')
     d                                     like(xmlXPathObjectPtr)
     d str                             *   value options(*string)               const xmlChar *
     d ctx                                 value like(xmlXPathContextPtr)

     d xmlXPtrRangeToFunction...
     d                 pr                  extproc('xmlXPtrRangeToFunction')
     d ctxt                                value like(xmlXPathParserContextPtr)
     d nargs                               value like(xmlCint)

     d xmlXPtrBuildNodeList...
     d                 pr                  extproc('xmlXPtrBuildNodeList')
     d                                     like(xmlNodePtr)
     d obj                                 value like(xmlXPathObjectPtr)

     d xmlXPtrEvalRangePredicate...
     d                 pr                  extproc('xmlXPtrEvalRangePredicate')
     d ctxt                                value like(xmlXPathParserContextPtr)

      /endif                                                                    LIBXML_XPTR_ENABLED
      /endif                                                                    XML_XPTR_H__
