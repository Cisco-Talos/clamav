      * Summary: regular expressions handling
      * Description: basic API for libxml regular expressions handling used
      *              for XML Schemas and validation.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_REGEXP_H__)
      /define XML_REGEXP_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_REGEXP_ENABLED)

      /include "libxmlrpg/xmlTypesC"

      * xmlRegexpPtr:
      *
      * A libxml regular expression, they can actually be far more complex
      * thank the POSIX regex expressions.

     d xmlRegexpPtr    s               *   based(######typedef######)

      * xmlRegExecCtxtPtr:
      *
      * A libxml progressive regular expression evaluation context

     d xmlRegExecCtxtPtr...
     d                 s               *   based(######typedef######)

      /include "libxmlrpg/tree"
      /include "libxmlrpg/dict"

      * The POSIX like API

     d xmlRegexpCompile...
     d                 pr                  extproc('xmlRegexpCompile')
     d                                     like(xmlRegexpPtr)
     d  regexp                         *   value options(*string)               const xmlChar *

     d xmlRegFreeRegexp...
     d                 pr                  extproc('xmlRegFreeRegexp')
     d  regexp                             value like(xmlRegexpPtr)

     d xmlRegexpExec   pr                  extproc('xmlRegexpExec')
     d                                     like(xmlCint)
     d  comp                               value like(xmlRegexpPtr)
     d  value                          *   value options(*string)               const xmlChar *

     d xmlRegexpPrint  pr                  extproc('xmlRegexpPrint')
     d  output                         *   value                                FILE *
     d  regexp                             value like(xmlRegexpPtr)

     d xmlRegexpIsDeterminist...
     d                 pr                  extproc('xmlRegexpIsDeterminist')
     d                                     like(xmlCint)
     d  comp                               value like(xmlRegexpPtr)

      * xmlRegExecCallbacks:
      * @exec: the regular expression context
      * @token: the current token string
      * @transdata: transition data
      * @inputdata: input data
      *
      * Callback function when doing a transition in the automata

     d xmlRegExecCallbacks...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * The progressive API

     d xmlRegNewExecCtxt...
     d                 pr                  extproc('xmlRegNewExecCtxt')
     d                                     like(xmlRegExecCtxtPtr)
     d  comp                               value like(xmlRegexpPtr)
     d  callback                           value like(xmlRegExecCallbacks)
     d  data                           *   value                                void *

     d xmlRegFreeExecCtxt...
     d                 pr                  extproc('xmlRegFreeExecCtxt')
     d  exec                               value like(xmlRegExecCtxtPtr)

     d xmlRegExecPushString...
     d                 pr                  extproc('xmlRegExecPushString')
     d                                     like(xmlCint)
     d  exec                               value like(xmlRegExecCtxtPtr)
     d  value                          *   value options(*string)               const xmlChar *
     d  data                           *   value                                void *

     d xmlRegExecPushString2...
     d                 pr                  extproc('xmlRegExecPushString2')
     d                                     like(xmlCint)
     d  exec                               value like(xmlRegExecCtxtPtr)
     d  value                          *   value options(*string)               const xmlChar *
     d  value2                         *   value options(*string)               const xmlChar *
     d  data                           *   value                                void *

     d xmlRegExecNextValues...
     d                 pr                  extproc('xmlRegExecNextValues')
     d                                     like(xmlCint)
     d  exec                               value like(xmlRegExecCtxtPtr)
     d  nbval                              like(xmlCint)
     d  nbneg                              like(xmlCint)
     d  values                         *                                        xmlChar * (*)
     d  terminal                           like(xmlCint)

     d xmlRegExecErrInfo...
     d                 pr                  extproc('xmlRegExecErrInfo')
     d                                     like(xmlCint)
     d  exec                               value like(xmlRegExecCtxtPtr)
     d  string                         *                                        const xmlChar * (*)
     d  nbval                              like(xmlCint)
     d  nbneg                              like(xmlCint)
     d  values                         *                                        xmlChar * (*)
     d  terminal                           like(xmlCint)

      /if defined(LIBXML_EXPR_ENABLED)

      * Formal regular expression handling
      * Its goal is to do some formal work on content models

      * expressions are used within a context

     d xmlExpCtxtPtr   s               *   based(######typedef######)

     d xmlExpFreeCtxt  pr                  extproc('xmlExpFreeCtxt')
     d  ctxt                               value like(xmlExpCtxtPtr)

     d xmlExpNewCtxt   pr                  extproc('xmlExpNewCtxt')
     d                                     like(xmlExpCtxtPtr)
     d  maxNodes                           value like(xmlCint)
     d  dict                               value like(xmlDictPtr)

     d xmlExpCtxtNbNodes...
     d                 pr                  extproc('xmlExpCtxtNbNodes')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlExpCtxtPtr)

     d xmlExpCtxtNbCons...
     d                 pr                  extproc('xmlExpCtxtNbCons')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlExpCtxtPtr)

      * Expressions are trees but the tree is opaque

     d xmlExpNodePtr   s               *   based(######typedef######)

     d xmlExpNodeType  s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_EXP_EMPTY  c                   0
     d  XML_EXP_FORBID...
     d                 c                   1
     d  XML_EXP_ATOM   c                   2
     d  XML_EXP_SEQ    c                   3
     d  XML_EXP_OR     c                   4
     d  XML_EXP_COUNT  c                   5

      * 2 core expressions shared by all for the empty language set
      * and for the set with just the empty token

     d forbiddenExp    s                   import('forbiddenExp')
     d                                     like(xmlExpNodePtr)

     d emptyExp        s                   import('emptyExp')
     d                                     like(xmlExpNodePtr)


      * Expressions are reference counted internally

     d xmlExpFree      pr                  extproc('xmlExpFree')
     d  expr                               value like(xmlExpNodePtr)

     d xmlExpRef       pr                  extproc('xmlExpRef')
     d  expr                               value like(xmlExpNodePtr)

      * constructors can be either manual or from a string

     d xmlExpParse     pr                  extproc('xmlExpParse')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  expr                           *   value options(*string)               const char *

     d xmlExpNewAtom   pr                  extproc('xmlExpNewAtom')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlExpNewOr     pr                  extproc('xmlExpNewOr')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  left                               value like(xmlExpNodePtr)
     d  right                              value like(xmlExpNodePtr)

     d xmlExpNewSeq    pr                  extproc('xmlExpNewSeq')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  left                               value like(xmlExpNodePtr)
     d  right                              value like(xmlExpNodePtr)

     d xmlExpNewRange  pr                  extproc('xmlExpNewRange')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  subset                             value like(xmlExpNodePtr)
     d  min                                value like(xmlCint)
     d  max                                value like(xmlCint)

      * The really interesting APIs

     d xmlExpIsNillable...
     d                 pr                  extproc('xmlExpIsNillable')
     d                                     like(xmlCint)
     d  expr                               value like(xmlExpNodePtr)

     d xmlExpMaxToken  pr                  extproc('xmlExpMaxToken')
     d                                     like(xmlCint)
     d  expr                               value like(xmlExpNodePtr)

     d xmlExpGetLanguage...
     d                 pr                  extproc('xmlExpGetLanguage')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  expr                               value like(xmlExpNodePtr)
     d  langList                       *                                        const xmlChar *(*)
     d  len                                value like(xmlCint)

     d xmlExpGetStart  pr                  extproc('xmlExpGetStart')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  expr                               value like(xmlExpNodePtr)
     d  tokList                        *                                        const xmlChar *(*)
     d  len                                value like(xmlCint)

     d xmlExpStringDerive...
     d                 pr                  extproc('xmlExpStringDerive')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  expr                               value like(xmlExpNodePtr)
     d  str                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlExpExpDerive...
     d                 pr                  extproc('xmlExpExpDerive')
     d                                     like(xmlExpNodePtr)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  expr                               value like(xmlExpNodePtr)
     d  sub                                value like(xmlExpNodePtr)

     d xmlExpSubsume   pr                  extproc('xmlExpSubsume')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlExpCtxtPtr)
     d  expr                               value like(xmlExpNodePtr)
     d  sub                                value like(xmlExpNodePtr)

     d xmlExpDump      pr                  extproc('xmlExpDump')
     d  buf                                value like(xmlBufferPtr)
     d  expr                               value like(xmlExpNodePtr)
      /endif                                                                    LIBXML_EXPR_ENABLED
      /endif                                                                    LIBXML_REGEXP_ENABLD
      /endif                                                                    XML_REGEXP_H__
