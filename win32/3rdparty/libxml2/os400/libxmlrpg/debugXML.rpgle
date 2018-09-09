      * Summary: Tree debugging APIs
      * Description: Interfaces to a set of routines used for debugging the tree
      *              produced by the XML parser.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(DEBUG_XML__)
      /define DEBUG_XML__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_DEBUG_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/xpath"

      * The standard Dump routines.

     d xmlDebugDumpString...
     d                 pr                  extproc('xmlDebugDumpString')
     d  output                         *   value                                FILE *
     d  str                            *   value options(*string)               const xmlChar *

     d xmlDebugDumpAttr...
     d                 pr                  extproc('xmlDebugDumpAttr')
     d  output                         *   value                                FILE *
     d  attr                               value like(xmlAttrPtr)
     d  depth                              value like(xmlCint)

     d xmlDebugDumpAttrList...
     d                 pr                  extproc('xmlDebugDumpAttrList')
     d  output                         *   value                                FILE *
     d  attr                               value like(xmlAttrPtr)
     d  depth                              value like(xmlCint)

     d xmlDebugDumpOneNode...
     d                 pr                  extproc('xmlDebugDumpOneNode')
     d  output                         *   value                                FILE *
     d  node                               value like(xmlNodePtr)
     d  depth                              value like(xmlCint)

     d xmlDebugDumpNode...
     d                 pr                  extproc('xmlDebugDumpNode')
     d  output                         *   value                                FILE *
     d  node                               value like(xmlNodePtr)
     d  depth                              value like(xmlCint)

     d xmlDebugDumpNodeList...
     d                 pr                  extproc('xmlDebugDumpNodeList')
     d  output                         *   value                                FILE *
     d  node                               value like(xmlNodePtr)
     d  depth                              value like(xmlCint)

     d xmlDebugDumpDocumentHead...
     d                 pr                  extproc('xmlDebugDumpDocumentHead')
     d  output                         *   value                                FILE *
     d  doc                                value like(xmlDocPtr)

     d xmlDebugDumpDocument...
     d                 pr                  extproc('xmlDebugDumpDocument')
     d  output                         *   value                                FILE *
     d  doc                                value like(xmlDocPtr)

     d xmlDebugDumpDTD...
     d                 pr                  extproc('xmlDebugDumpDTD')
     d  output                         *   value                                FILE *
     d  dtd                                value like(xmlDtdPtr)

     d xmlDebugDumpEntities...
     d                 pr                  extproc('xmlDebugDumpEntities')
     d  output                         *   value                                FILE *
     d  doc                                value like(xmlDocPtr)

      ****************************************************************
      *                                                              *
      *                      Checking routines                       *
      *                                                              *
      ****************************************************************

     d xmlDebugCheckDocument...
     d                 pr                  extproc('xmlDebugCheckDocument')
     d                                     like(xmlCint)
     d  output                         *   value                                FILE *
     d  doc                                value like(xmlDocPtr)

      ****************************************************************
      *                                                              *
      *                      XML shell helpers                       *
      *                                                              *
      ****************************************************************

     d xmlLsOneNode    pr                  extproc('xmlLsOneNode')
     d  output                         *   value                                FILE *
     d  node                               value like(xmlNodePtr)

     d xmlLsCountNode  pr                  extproc('xmlLsCountNode')
     d                                     like(xmlCint)
     d  node                               value like(xmlNodePtr)

     d xmlBoolToText   pr              *   extproc('xmlBoolToText')             const char *
     d  boolval                            value like(xmlCint)

      ****************************************************************
      *                                                              *
      *       The XML shell related structures and functions         *
      *                                                              *
      ****************************************************************

      /if defined(LIBXML_XPATH_ENABLED)

      * xmlShellReadlineFunc:
      * @prompt:  a string prompt
      *
      * This is a generic signature for the XML shell input function.
      *
      * Returns a string which will be freed by the Shell.

     d xmlShellReadlineFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlShellCtxt:
      *
      * A debugging shell context.
      * TODO: add the defined function tables.

     d xmlShellCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlSchellCtxt   ds                  based(xmlShellCtxtPtr)
     d                                     align qualified
     d  filename                       *                                        char *
     d  doc                                like(xmlDocPtr)
     d  node                               like(xmlNodePtr)
     d  pctxt                              like(xmlXPathContextPtr)
     d  loaded                             like(xmlCint)
     d  output                         *                                        FILE *
     d  input                              like(xmlShellReadlineFunc)

      * xmlShellCmd:
      * @ctxt:  a shell context
      * @arg:  a string argument
      * @node:  a first node
      * @node2:  a second node
      *
      * This is a generic signature for the XML shell functions.
      *
      * Returns an int, negative returns indicating errors.

     d xmlShellCmd     s               *   based(######typedef######)
     d                                     procptr

     d xmlShellPrintXPathError...
     d                 pr                  extproc('xmlShellPrintXPathError')
     d  errorType                          value like(xmlCint)
     d  arg                            *   value options(*string)               const char *

     d xmlShellPrintXPathResult...
     d                 pr                  extproc('xmlShellPrintXPathResult')
     d  list                               value like(xmlXPathObjectPtr)

     d xmlShellList    pr                  extproc('xmlShellList')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  arg                            *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

     d xmlShellBase    pr                  extproc('xmlShellBase')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  arg                            *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

     d xmlShellDir     pr                  extproc('xmlShellDir')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  arg                            *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

     d xmlShellLoad    pr                  extproc('xmlShellLoad')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  filename                       *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlShellPrintNode...
     d                 pr                  extproc('xmlShellPrintNode')
     d  node                               value like(xmlNodePtr)

     d xmlShellCat     pr                  extproc('xmlShellCat')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  arg                            *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

     d xmlShellWrite   pr                  extproc('xmlShellWrite')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  filename                       *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

     d xmlShellSave    pr                  extproc('xmlShellSave')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  filename                       *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      /if defined(LIBXML_VALID_ENABLED)
     d xmlShellValidate...
     d                 pr                  extproc('xmlShellValidate')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  dtd                            *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)
      /endif                                                                    LIBXML_VALID_ENABLED

     d xmlShellDu      pr                  extproc('xmlShellDu')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  arg                            *   value options(*string)               char *
     d  tree                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

     d xmlShellPwd     pr                  extproc('xmlShellPwd')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlShellCtxtPtr)
     d  buffer                         *   value options(*string)               char *
     d  node                               value like(xmlNodePtr)
     d  node2                              value like(xmlNodePtr)

      * The Shell interface.

     d xmlShell        pr                  extproc('xmlShell')
     d  doc                                value like(xmlDocPtr)
     d  filename                       *   value options(*string)               char *
     d  input                              value like(xmlShellReadlineFunc)
     d  output                         *   value                                FILE *

      /endif                                                                    LIBXML_XPATH_ENABLED
      /endif                                                                    LIBXML_DEBUG_ENABLED
      /endif                                                                    DEBUG_XML__
