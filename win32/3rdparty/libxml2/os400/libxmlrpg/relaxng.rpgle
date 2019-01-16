      * Summary: implementation of the Relax-NG validation
      * Description: implementation of the Relax-NG validation
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_RELAX_NG__)
      /define XML_RELAX_NG__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_SCHEMAS_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/hash"
      /include "libxmlrpg/xmlstring"

     d xmlRelaxNGPtr   s               *   based(######typedef######)

      * xmlRelaxNGValidityErrorFunc:
      * @ctx: the validation context
      * @msg: the message
      * @...: extra arguments
      *
      * Signature of an error callback from a Relax-NG validation

     d xmlRelaxNGValidityErrorFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlRelaxNGValidityWarningFunc:
      * @ctx: the validation context
      * @msg: the message
      * @...: extra arguments
      *
      * Signature of a warning callback from a Relax-NG validation

     d xmlRelaxNGValidityWarningFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * A schemas validation context

     d xmlRelaxNGParserCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlRelaxNGValidCtxtPtr...
     d                 s               *   based(######typedef######)

      * xmlRelaxNGValidErr:
      *
      * List of possible Relax NG validation errors

     d xmlRelaxNGValidErr...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_RELAXNG_OK...
     d                 c                   0
     d  XML_RELAXNG_ERR_MEMORY...
     d                 c                   1
     d  XML_RELAXNG_ERR_TYPE...
     d                 c                   2
     d  XML_RELAXNG_ERR_TYPEVAL...
     d                 c                   3
     d  XML_RELAXNG_ERR_DUPID...
     d                 c                   4
     d  XML_RELAXNG_ERR_TYPECMP...
     d                 c                   5
     d  XML_RELAXNG_ERR_NOSTATE...
     d                 c                   6
     d  XML_RELAXNG_ERR_NODEFINE...
     d                 c                   7
     d  XML_RELAXNG_ERR_LISTEXTRA...
     d                 c                   8
     d  XML_RELAXNG_ERR_LISTEMPTY...
     d                 c                   9
     d  XML_RELAXNG_ERR_INTERNODATA...
     d                 c                   10
     d  XML_RELAXNG_ERR_INTERSEQ...
     d                 c                   11
     d  XML_RELAXNG_ERR_INTEREXTRA...
     d                 c                   12
     d  XML_RELAXNG_ERR_ELEMNAME...
     d                 c                   13
     d  XML_RELAXNG_ERR_ATTRNAME...
     d                 c                   14
     d  XML_RELAXNG_ERR_ELEMNONS...
     d                 c                   15
     d  XML_RELAXNG_ERR_ATTRNONS...
     d                 c                   16
     d  XML_RELAXNG_ERR_ELEMWRONGNS...
     d                 c                   17
     d  XML_RELAXNG_ERR_ATTRWRONGNS...
     d                 c                   18
     d  XML_RELAXNG_ERR_ELEMEXTRANS...
     d                 c                   19
     d  XML_RELAXNG_ERR_ATTREXTRANS...
     d                 c                   20
     d  XML_RELAXNG_ERR_ELEMNOTEMPTY...
     d                 c                   21
     d  XML_RELAXNG_ERR_NOELEM...
     d                 c                   22
     d  XML_RELAXNG_ERR_NOTELEM...
     d                 c                   23
     d  XML_RELAXNG_ERR_ATTRVALID...
     d                 c                   24
     d  XML_RELAXNG_ERR_CONTENTVALID...
     d                 c                   25
     d  XML_RELAXNG_ERR_EXTRACONTENT...
     d                 c                   26
     d  XML_RELAXNG_ERR_INVALIDATTR...
     d                 c                   27
     d  XML_RELAXNG_ERR_DATAELEM...
     d                 c                   28
     d  XML_RELAXNG_ERR_VALELEM...
     d                 c                   29
     d  XML_RELAXNG_ERR_LISTELEM...
     d                 c                   30
     d  XML_RELAXNG_ERR_DATATYPE...
     d                 c                   31
     d  XML_RELAXNG_ERR_VALUE...
     d                 c                   32
     d  XML_RELAXNG_ERR_LIST...
     d                 c                   33
     d  XML_RELAXNG_ERR_NOGRAMMAR...
     d                 c                   34
     d  XML_RELAXNG_ERR_EXTRADATA...
     d                 c                   35
     d  XML_RELAXNG_ERR_LACKDATA...
     d                 c                   36
     d  XML_RELAXNG_ERR_INTERNAL...
     d                 c                   37
     d  XML_RELAXNG_ERR_ELEMWRONG...
     d                 c                   38
     d  XML_RELAXNG_ERR_TEXTWRONG...
     d                 c                   39

      * xmlRelaxNGParserFlags:
      *
      * List of possible Relax NG Parser flags

     d xmlRelaxNGParserFlag...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_RELAXNGP_NONE...
     d                 c                   0
     d  XML_RELAXNGP_FREE_DOC...
     d                 c                   1
     d  XML_RELAXNGP_CRNG...
     d                 c                   2

     d xmlRelaxNGInitTypes...
     d                 pr                  extproc('xmlRelaxNGInitTypes')
     d                                     like(xmlCint)

     d xmlRelaxNGCleanupTypes...
     d                 pr                  extproc('xmlRelaxNGCleanupTypes')


      * Interfaces for parsing.

     d xmlRelaxNGNewParserCtxt...
     d                 pr                  extproc('xmlRelaxNGNewParserCtxt')
     d                                     like(xmlRelaxNGParserCtxtPtr)
     d  URL                            *   value options(*string)               const char *

     d xmlRelaxNGNewMemParserCtxt...
     d                 pr                  extproc('xmlRelaxNGNewMemParserCtxt')
     d                                     like(xmlRelaxNGParserCtxtPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)

     d xmlRelaxNGNewDocParserCtxt...
     d                 pr                  extproc('xmlRelaxNGNewDocParserCtxt')
     d                                     like(xmlRelaxNGParserCtxtPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlRelaxParserSetFlag...
     d                 pr                  extproc('xmlRelaxParserSetFlag')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGParserCtxtPtr)
     d  flag                               value like(xmlCint)

     d xmlRelaxNGFreeParserCtxt...
     d                 pr                  extproc('xmlRelaxNGFreeParserCtxt')
     d  ctxt                               value like(xmlRelaxNGParserCtxtPtr)

     d xmlRelaxNGSetParserErrors...
     d                 pr                  extproc('xmlRelaxNGSetParserErrors')
     d  ctxt                               value like(xmlRelaxNGParserCtxtPtr)
     d  err                                value
     d                                     like(xmlRelaxNGValidityErrorFunc)
     d  warn                               value
     d                                     like(xmlRelaxNGValidityWarningFunc)
     d  ctx                            *   value                                void *

     d xmlRelaxNGGetParserErrors...
     d                 pr                  extproc('xmlRelaxNGGetParserErrors')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGParserCtxtPtr)
     d  err                                like(xmlRelaxNGValidityErrorFunc)
     d  warn                               like(xmlRelaxNGValidityWarningFunc)
     d  ctx                            *                                        void *(*)

     d xmlRelaxNGSetParserStructuredErrors...
     d                 pr                  extproc(
     d                                     'xmlRelaxNGSetParserStructuredErrors'
     d                                     )
     d  ctxt                               value like(xmlRelaxNGParserCtxtPtr)
     d  serror                             value like(xmlStructuredErrorFunc)
     d  ctx                            *   value                                void *

     d xmlRelaxNGParse...
     d                 pr                  extproc('xmlRelaxNGParse')
     d                                     like(xmlRelaxNGPtr)
     d  ctxt                               value like(xmlRelaxNGParserCtxtPtr)

     d xmlRelaxNGFree  pr                  extproc('xmlRelaxNGFree')
     d  schema                             value like(xmlRelaxNGPtr)


      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlRelaxNGDump  pr                  extproc('xmlRelaxNGDump')
     d  output                         *   value                                FILE *
     d  schema                             value like(xmlRelaxNGPtr)

     d xmlRelaxNGDumpTree...
     d                 pr                  extproc('xmlRelaxNGDumpTree')
     d  output                         *   value                                FILE *
     d  schema                             value like(xmlRelaxNGPtr)
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      * Interfaces for validating

     d xmlRelaxNGSetValidErrors...
     d                 pr                  extproc('xmlRelaxNGSetValidErrors')
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  err                                value
     d                                     like(xmlRelaxNGValidityErrorFunc)
     d  warn                               value
     d                                     like(xmlRelaxNGValidityWarningFunc)
     d  ctx                            *   value                                void *

     d xmlRelaxNGGetValidErrors...
     d                 pr                  extproc('xmlRelaxNGGetValidErrors')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  err                                like(xmlRelaxNGValidityErrorFunc)
     d  warn                               like(xmlRelaxNGValidityWarningFunc)
     d  ctx                            *   value                                void * *

     d xmlRelaxNGSetValidStructuredErrors...
     d                 pr                  extproc(
     d                                     'xmlRelaxNGSetValidStructuredErrors')
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  serror                             value like(xmlStructuredErrorFunc)
     d  ctx                            *   value                                void *

     d xmlRelaxNGNewValidCtxt...
     d                 pr                  extproc('xmlRelaxNGNewValidCtxt')
     d                                     like(xmlRelaxNGValidCtxtPtr)
     d  schema                             value like(xmlRelaxNGPtr)

     d xmlRelaxNGFreeValidCtxt...
     d                 pr                  extproc('xmlRelaxNGFreeValidCtxt')
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)

     d xmlRelaxNGValidateDoc...
     d                 pr                  extproc('xmlRelaxNGValidateDoc')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  doc                                value like(xmlDocPtr)

      * Interfaces for progressive validation when possible

     d xmlRelaxNGValidatePushElement...
     d                 pr                  extproc(
     d                                     'xmlRelaxNGValidatePushElement')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  doc                                value like(xmlDocPtr)
     d  elem                               value like(xmlNodePtr)

     d xmlRelaxNGValidatePushCData...
     d                 pr                  extproc(
     d                                     'xmlRelaxNGValidatePushCData')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  data                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlRelaxNGValidatePopElement...
     d                 pr                  extproc(
     d                                     'xmlRelaxNGValidatePopElement')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  doc                                value like(xmlDocPtr)
     d  elem                               value like(xmlNodePtr)

     d xmlRelaxNGValidateFullElement...
     d                 pr                  extproc(
     d                                     'xmlRelaxNGValidateFullElement')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlRelaxNGValidCtxtPtr)
     d  doc                                value like(xmlDocPtr)
     d  elem                               value like(xmlNodePtr)

      /endif                                                                    LIBXML_SCHEMAS_ENBLD
      /endif                                                                    XML_RELAX_NG__
