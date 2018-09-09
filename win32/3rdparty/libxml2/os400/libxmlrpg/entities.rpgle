      * Summary: interface for the XML entities handling
      * Description: this module provides some of the entity API needed
      *              for the parser and applications.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_ENTITIES_H__)
      /define XML_ENTITIES_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"

      * The different valid entity types.

     d xmlEntityType   s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_INTERNAL_GENERAL_ENTITY...
     d                 c                   1
     d  XML_EXTERNAL_GENERAL_PARSED_ENTITY...
     d                 c                   2
     d  XML_EXTERNAL_GENERAL_UNPARSED_ENTITY...
     d                 c                   3
     d  XML_INTERNAL_PARAMETER_ENTITY...
     d                 c                   4
     d  XML_EXTERNAL_PARAMETER_ENTITY...
     d                 c                   5
     d  XML_INTERNAL_PREDEFINED_ENTITY...
     d                 c                   6

      * An unit of storage for an entity, contains the string, the value
      * and the linkind data needed for the linking in the hash table.

     d xmlEntity       ds                  based(xmlEntityPtr)
     d                                     align qualified
     d  #private                       *                                        void *
     d  type                               like(xmlElementType)                 XML_ENTITY_DECL
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     First child link
     d  last                               like(xmlNodePtr)                     Last child link
     d  parent                             like(xmlDtdPtr)                      -> DTD
     d  next                               like(xmlNodePtr)                     next sibling link
     d  prev                               like(xmlNodePtr)                     prev sibling link
     d  doc                                like(xmlDocPtr)                      containing document
     d  orig                           *                                        xmlChar *
     d  content                        *                                        xmlChar *
     d  length                             like(xmlCint)                        content length
     d  etype                              like(xmlEntityType)                  The entity type
     d  ExternalID                     *                                        const xmlChar *
     d  SystemlID                      *                                        const xmlChar *
     d  nexte                              like(xmlEntityPtr)                   unused
     d  URI                            *                                        const xmlChar *
     d  owner                              like(xmlCint)                        Owns children ?
     d  checked                            like(xmlCint)                        Content checked ?

      * All entities are stored in an hash table.
      * There is 2 separate hash tables for global and parameter entities.

     d xmlEntitiesTablePtr...
     d                 s               *   based(######typedef######)

      * External functions:

      /if defined(LIBXML_LEGACY_ENABLED)
     d xmlInitializePredefinedEntities...
     d                 pr                  extproc(
     d                                      'xmlInitializePredefinedEntities')
      /endif                                                                    LIBXML_LEGACY_ENABLD

     d xmlNewEntity    pr                  extproc('xmlNewEntity')
     d                                     like(xmlEntityPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  type                               value like(xmlCint)
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemID                       *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlAddDocEntity...
     d                 pr                  extproc('xmlAddDocEntity')
     d                                     like(xmlEntityPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  type                               value like(xmlCint)
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemID                       *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlAddDtdEntity...
     d                 pr                  extproc('xmlAddDtdEntity')
     d                                     like(xmlEntityPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  type                               value like(xmlCint)
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemID                       *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlGetPredefinedEntity...
     d                 pr                  extproc('xmlGetPredefinedEntity')
     d                                     like(xmlEntityPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlGetDocEntity...
     d                 pr                  extproc('xmlGetDocEntity')
     d                                     like(xmlEntityPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlGetDtdEntity...
     d                 pr                  extproc('xmlGetDtdEntity')
     d                                     like(xmlEntityPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlGetParameterEntity...
     d                 pr                  extproc('xmlGetParameterEntity')
     d                                     like(xmlEntityPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *


      /if defined(LIBXML_LEGACY_ENABLED)
     d xmlEncodeEntities...
     d                 pr              *   extproc('xmlEncodeEntities')         xmlChar *
     d  doc                                value like(xmlDocPtr)
     d  input                          *   value options(*string)               const xmlChar *
      /endif                                                                    LIBXML_LEGACY_ENABLD

     d xmlEncodeEntitiesReentrant...
     d                 pr              *   extproc(                             xmlChar *
     d                                      'xmlEncodeEntitiesReentrant')
     d  doc                                value like(xmlDocPtr)
     d  input                          *   value options(*string)               const xmlChar *
XMLPU
     d xmlEncodeSpecialChars...
     d                 pr              *   extproc('xmlSpecialChars')           xmlChar *
     d  doc                                value like(xmlDocPtr)
     d  input                          *   value options(*string)               const xmlChar *
XMLPU
     d xmlCreateEntitiesTable...
     d                 pr                  extproc('xmlCreateEntitiesTable')
     d                                     like(xmlEntitiesTablePtr)

      /if defined(LIBXML_TREE_ENABLED)
     d xmlCopyEntitiesTable...
     d                 pr                  extproc('xmlCopyEntitiesTable')
     d                                     like(xmlEntitiesTablePtr)
     d  table                              value like(xmlEntitiesTablePtr)
      /endif                                                                    LIBXML_TREE_ENABLED

     d xmlFreeEntitiesTable...
     d                 pr                  extproc('xmlFreeEntitiesTable')
     d  table                              value like(xmlEntitiesTablePtr)
XMLPU
      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlDumpEntitiesTable...
     d                 pr                  extproc('xmlDumpEntitiesTable')
     d  buf                                value like(xmlBufferPtr)
     d  table                              value like(xmlEntitiesTablePtr)
XMLPU
     d xmlDumpEntityDecl...
     d                 pr                  extproc('xmlDumpEntityDecl')
     d  buf                                value like(xmlBufferPtr)
     d  ent                                value like(xmlEntityPtr)
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      /if defined(LIBXML_LEGACY_ENABLED)
     d xmlCleanupPredefinedEntities...
     d                 pr                  extproc(
XMLPUd                                      'xmlCleanupPredefinedEntities')
      /endif                                                                    LIBXML_LEGACY_ENABLD

      /endif                                                                    XML_ENTITIES_H__
