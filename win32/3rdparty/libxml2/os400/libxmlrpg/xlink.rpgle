      * Summary: unfinished XLink detection module
      * Description: unfinished XLink detection module
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_XLINK_H__)
      /define XML_XLINK_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_XPTR_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"

      * Various defines for the various Link properties.
      *
      * NOTE: the link detection layer will try to resolve QName expansion
      *       of namespaces. If "foo" is the prefix for "http://foo.com/"
      *       then the link detection layer will expand role="foo:myrole"
      *       to "http://foo.com/:myrole".
      * NOTE: the link detection layer will expand URI-Refences found on
      *       href attributes by using the base mechanism if found.

     d xlinkRef        s               *   based(######typedef######)           xmlChar *
     d xlinkRole       s               *   based(######typedef######)           xmlChar *
     d xlinkTitle      s               *   based(######typedef######)           xmlChar *

     d xlinkType       s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XLINK_TYPE_NONE...
     d                 c                   0
     d  XLINK_TYPE_SIMPLE...
     d                 c                   1
     d  XLINK_TYPE_EXTENDED...
     d                 c                   2
     d  XLINK_TYPE_EXTENDED_SET...
     d                 c                   3

     d xlinkShow       s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XLINK_SHOW_NONE...
     d                 c                   0
     d  XLINK_SHOW_NEW...
     d                 c                   1
     d  XLINK_SHOW_EMBED...
     d                 c                   2
     d  XLINK_SHOW_REPLACE...
     d                 c                   3

     d xlinkActuate    s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XLINK_ACTUATE_NONE...
     d                 c                   0
     d  XLINK_ACTUATE_AUTO...
     d                 c                   1
     d  XLINK_ACTUATE_ONREQUEST...
     d                 c                   2

      * xlinkNodeDetectFunc:
      * @ctx:  user data pointer
      * @node:  the node to check
      *
      * This is the prototype for the link detection routine.
      * It calls the default link detection callbacks upon link detection.

     d xlinkNodeDetectFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * The link detection module interact with the upper layers using
      * a set of callback registered at parsing time.

      * xlinkSimpleLinkFunk:
      * @ctx:  user data pointer
      * @node:  the node carrying the link
      * @href:  the target of the link
      * @role:  the role string
      * @title:  the link title
      *
      * This is the prototype for a simple link detection callback.

     d xlinkSimpleLinkFunk...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xlinkExtendedLinkFunk:
      * @ctx:  user data pointer
      * @node:  the node carrying the link
      * @nbLocators: the number of locators detected on the link
      * @hrefs:  pointer to the array of locator hrefs
      * @roles:  pointer to the array of locator roles
      * @nbArcs: the number of arcs detected on the link
      * @from:  pointer to the array of source roles found on the arcs
      * @to:  pointer to the array of target roles found on the arcs
      * @show:  array of values for the show attributes found on the arcs
      * @actuate:  array of values for the actuate attributes found on the arcs
      * @nbTitles: the number of titles detected on the link
      * @title:  array of titles detected on the link
      * @langs:  array of xml:lang values for the titles
      *
      * This is the prototype for a extended link detection callback.

     d xlinkExtendedLinkFunk...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xlinkExtendedLinkSetFunk:
      * @ctx:  user data pointer
      * @node:  the node carrying the link
      * @nbLocators: the number of locators detected on the link
      * @hrefs:  pointer to the array of locator hrefs
      * @roles:  pointer to the array of locator roles
      * @nbTitles: the number of titles detected on the link
      * @title:  array of titles detected on the link
      * @langs:  array of xml:lang values for the titles
      *
      * This is the prototype for a extended link set detection callback.

     d xlinkExtendedLinkSetFunk...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * This is the structure containing a set of Links detection callbacks.
      *
      * There is no default xlink callbacks, if one want to get link
      * recognition activated, those call backs must be provided before parsing.

     d xlinkHandlerPtr...
     d                 s               *   based(######typedef######)           xmlChar *

     d xlinkHandler    ds                  based(xlinkHandlerPtr)
     d                                     align qualified
     d  simple                             like(xlinkSimpleLinkFunk)
     d  extended                           like(xlinkExtendedLinkFunk)
     d  set                                like(xlinkExtendedLinkSetFunk)

      * The default detection routine, can be overridden, they call the default
      * detection callbacks.

     d xlinkGetDefaultDetect...
     d                 pr                  extproc('xlinkGetDefaultDetect')
     d                                     like(xlinkNodeDetectFunc)

     d xlinkSetDefaultDetect...
     d                 pr                  extproc('xlinkSetDefaultDetect')
     d  func                               value like(xlinkNodeDetectFunc)

      * Routines to set/get the default handlers.

     d xlinkGetDefaultHandler...
     d                 pr                  extproc('xlinkGetDefaultHandler')
     d                                     like(xlinkHandlerPtr)

     d xlinkSetDefaultHandler...
     d                 pr                  extproc('xlinkSetDefaultHandler')
     d  handler                            value like(xlinkHandlerPtr)

      * Link detection module itself.

     d xlinkIsLink     pr                  extproc('xlinkIsLink')
     d                                     like(xlinkType)
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)

      /endif                                                                    LIBXML_XPTR_ENABLED
      /endif                                                                    XML_XLINK_H__
