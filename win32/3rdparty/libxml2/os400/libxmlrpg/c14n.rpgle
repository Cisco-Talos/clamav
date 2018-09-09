      * Summary: Provide Canonical XML and Exclusive XML Canonicalization
      * Description: the c14n modules provides a
      *
      * "Canonical XML" implementation
      * http://www.w3.org/TR/xml-c14n
      *
      * and an
      *
      * "Exclusive XML Canonicalization" implementation
      * http://www.w3.org/TR/xml-exc-c14n
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_C14N_H__)
      /define XML_C14N_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_C14N_ENABLED)
      /if defined(LIBXML_OUTPUT_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/xpath"

      * XML Canonicazation
      * http://www.w3.org/TR/xml-c14n
      *
      * Exclusive XML Canonicazation
      * http://www.w3.org/TR/xml-exc-c14n
      *
      * Canonical form of an XML document could be created if and only if
      *  a) default attributes (if any) are added to all nodes
      *  b) all character and parsed entity references are resolved
      * In order to achive this in libxml2 the document MUST be loaded with
      * following global setings:
      *
      *    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS ã XML_COMPLETE_ATTRS;
      *    xmlSubstituteEntitiesDefault(1);
      *
      * or corresponding parser context setting:
      *    xmlParserCtxtPtr ctxt;
      *
      *    ...
      *    ctxt->loadsubset = XML_DETECT_IDS ã XML_COMPLETE_ATTRS;
      *    ctxt->replaceEntities = 1;
      *    ...

      * xmlC14NMode:
      *
      * Predefined values for C14N modes

     d xmlBufferAllocationScheme...
     d xmlC14NMode     s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_C14N_1_0   c                   0                                    Original C14N 1.0
     d  XML_C14N_EXCLUSIVE_1_0...                                               Exclusive C14N 1.0
     d                 c                   1
     d  XML_C14N_1_1   c                   2                                    C14N 1.1 spec

     d xmlC14NDocSaveTo...
     d                 pr                  extproc('xmlC14NDocSaveTo')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  nodes                              value like(xmlNodeSetPtr)
     d  mode                               value like(xmlCint)
     d  inclusive_ns_prefixes...
     d                                 *   options(*omit)                       xmlChar *(*)
     d  with_comments                      value like(xmlCint)
     d  buf                                value like(xmlOutputBufferPtr)

     d xmlC14NDocDumpMemory...
     d                 pr                  extproc('xmlC14NDocDumpMemory')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  nodes                              value like(xmlNodeSetPtr)
     d  mode                               value like(xmlCint)
     d  inclusive_ns_prefixes...
     d                                 *   options(*omit)                       xmlChar *(*)
     d  with_comments                      value like(xmlCint)
     d  doc_txt_ptr                    *                                        xmlChar *(*)

     d xmlC14NDocSave  pr                  extproc('xmlC14NDocSave')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  nodes                              value like(xmlNodeSetPtr)
     d  mode                               value like(xmlCint)
     d  inclusive_ns_prefixes...
     d                                 *   options(*omit)                       xmlChar *(*)
     d  with_comments                      value like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  compression                        value like(xmlCint)

      * This is the core C14N function

      * xmlC14NIsVisibleCallback:
      * @user_data: user data
      * @node: the curent node
      * @parent: the parent node
      *
      * Signature for a C14N callback on visible nodes
      *
      * Returns 1 if the node should be included

     d xmlC14NIsVisibleCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

     d xmlC14NExecute  pr                  extproc('xmlC14NExecute')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  is_visible_callback...
     d                                     value like(xmlC14NIsVisibleCallback)
     d  user_data                      *   value                                void *
     d  mode                               value like(xmlCint)
     d  inclusive_ns_prefixes...
     d                                 *   options(*omit)                       xmlChar *(*)
     d  with_comments                      value like(xmlCint)
     d  buf                                value like(xmlOutputBufferPtr)

      /endif                                                                    LIBXML_OUTPUT_ENABLD
      /endif                                                                    LIBXML_C14N_ENABLED
      /endif                                                                    XML_C14N_H__
