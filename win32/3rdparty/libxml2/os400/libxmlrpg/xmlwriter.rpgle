      * Summary: text writing API for XML
      * Description: text writing API for XML
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_XMLWRITER_H__)
      /define XML_XMLWRITER_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_WRITER_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/xmlstdarg"
      /include "libxmlrpg/xmlIO"
      /include "libxmlrpg/list"
      /include "libxmlrpg/xmlstring"

     d xmlTextWriterPtr...
     d                 s               *   based(######typedef######)

      * Constructors & Destructor

     d xmlNewTextWriter...
     d                 pr                  extproc('xmlNewTextWriter')
     d                                     like(xmlTextWriterPtr)
     d  out                                value like(xmlOutputBufferPtr)

     d xmlNewTextWriterFilename...
     d                 pr                  extproc('xmlNewTextWriterFilename')
     d                                     like(xmlTextWriterPtr)
     d  uri                            *   value options(*string)               const char *
     d  compression                        value like(xmlCint)

     d xmlNewTextWriterMemory...
     d                 pr                  extproc('xmlNewTextWriterMemory')
     d                                     like(xmlTextWriterPtr)
     d  buf                                value like(xmlBufferPtr)
     d  compression                        value like(xmlCint)

     d xmlNewTextWriterPushParser...
     d                 pr                  extproc('xmlNewTextWriterPushParser')
     d                                     like(xmlTextWriterPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  compression                        value like(xmlCint)

     d xmlNewTextWriterDoc...
     d                 pr                  extproc('xmlNewTextWriterDoc')
     d                                     like(xmlTextWriterPtr)
     d  doc                                like(xmlDocPtr)
     d  compression                        value like(xmlCint)

     d xmlNewTextWriterTree...
     d                 pr                  extproc('xmlNewTextWriterTree')
     d                                     like(xmlTextWriterPtr)
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)
     d  compression                        value like(xmlCint)

     d xmlFreeTextWriter...
     d                 pr                  extproc('xmlFreeTextWriter')
     d  writer                             value like(xmlTextWriterPtr)

      * Functions

      * Document

     d xmlTextWriterStartDocument...
     d                 pr                  extproc('xmlTextWriterStartDocument')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  version                        *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  standalone                     *   value options(*string)               const char *

     d xmlTextWriterEndDocument...
     d                 pr                  extproc('xmlTextWriterEndDocument')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * Comments

     d xmlTextWriterStartComment...
     d                 pr                  extproc('xmlTextWriterStartComment')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

     d xmlTextWriterEndComment...
     d                 pr                  extproc('xmlTextWriterEndComment')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

     d xmlTextWriterWriteFormatComment...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatComment')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string: *nopass)      const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatComment...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatComment')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteComment...
     d                 pr                  extproc('xmlTextWriterWriteComment')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  content                        *   value options(*string)               const xmlChar *

      * Elements

     d xmlTextWriterStartElement...
     d                 pr                  extproc('xmlTextWriterStartElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextWriterStartElementNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterStartElementNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *

     d xmlTextWriterEndElement...
     d                 pr                  extproc('xmlTextWriterEndElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

     d xmlTextWriterFullEndElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterFullEndElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * Elements conveniency functions

     d xmlTextWriterWriteFormatElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteElement...
     d                 pr                  extproc('xmlTextWriterWriteElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteFormatElementNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatElementNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatElementNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatElementNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteElementNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteElementNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * Text

     d xmlTextWriterWriteFormatRaw...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatRaw')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatRaw...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatRaw')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteRawLen...
     d                 pr                  extproc('xmlTextWriterWriteRawLen')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlTextWriterWriteRaw...
     d                 pr                  extproc('xmlTextWriterWriteRaw')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteFormatString...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatString')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatString...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatString')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteString...
     d                 pr                  extproc('xmlTextWriterWriteString')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteBase64...
     d                 pr                  extproc('xmlTextWriterWriteBase64')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  data                           *   value options(*string)               const char *
     d  start                              value like(xmlCint)
     d  len                                value like(xmlCint)

     d xmlTextWriterWriteBinHex...
     d                 pr                  extproc('xmlTextWriterWriteBinHex')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  data                           *   value options(*string)               const char *
     d  start                              value like(xmlCint)
     d  len                                value like(xmlCint)

      * Attributes

     d xmlTextWriterStartAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextWriterStartAttribute')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextWriterStartAttributeNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterStartAttributeNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *

     d xmlTextWriterEndAttribute...
     d                 pr                  extproc('xmlTextWriterEndAttribute')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * Attributes conveniency functions

     d xmlTextWriterWriteFormatAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatAttribute')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatAttribute')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteAttribute...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteAttribute')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteFormatAttributeNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatAttributeNS'
     d                                     )
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatAttributeNS...
     d                 pr                  extproc('xmlTextWriterWriteVFormatAt-
     d                                     tributeNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteAttributeNS...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteAttributeNS')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  namespaceURI                   *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * PI's

     d xmlTextWriterStartPI...
     d                 pr                  extproc('xmlTextWriterStartPI')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  target                         *   value options(*string)               const xmlChar *

     d xmlTextWriterEndPI...
     d                 pr                  extproc('xmlTextWriterEndPI')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * PI conveniency functions

     d xmlTextWriterWriteFormatPI...
     d                 pr                  extproc('xmlTextWriterWriteFormatPI')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  target                         *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatPI...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatPI')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  target                         *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWritePI...
     d                 pr                  extproc('xmlTextWriterWritePI')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  target                         *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * xmlTextWriterWriteProcessingInstruction:
      *
      * This macro maps to xmlTextWriterWritePI

     d xmlTextWriterWriteProcessingInstruction...
     d                 pr                  extproc('xmlTextWriterWritePI')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  target                         *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * CDATA

     d xmlTextWriterStartCDATA...
     d                 pr                  extproc('xmlTextWriterStartCDATA')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

     d xmlTextWriterEndCDATA...
     d                 pr                  extproc('xmlTextWriterEndCDATA')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * CDATA conveniency functions

     d xmlTextWriterWriteFormatCDATA...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatCDATA')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatCDATA...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatCDATA')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteCDATA...
     d                 pr                  extproc('xmlTextWriterWriteCDATA')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  content                        *   value options(*string)               const xmlChar *

      * DTD

     d xmlTextWriterStartDTD...
     d                 pr                  extproc('xmlTextWriterStartDTD')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *

     d xmlTextWriterEndDTD...
     d                 pr                  extproc('xmlTextWriterEndDTD')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * DTD conveniency functions

     d xmlTextWriterWriteFormatDTD...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatDTD')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatDTD...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatDTD')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteDTD...
     d                 pr                  extproc('xmlTextWriterWriteDTD')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  subset                         *   value options(*string)               const xmlChar *

      * xmlTextWriterWriteDocType:
      *
      * this macro maps to xmlTextWriterWriteDTD

     d xmlTextWriterWriteDocType...
     d                 pr                  extproc('xmlTextWriterWriteDTD')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  subset                         *   value options(*string)               const xmlChar *

      * DTD element definition

     d xmlTextWriterStartDTDElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterStartDTDElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextWriterEndDTDElement...
     d                 pr                  extproc('xmlTextWriterEndDTDElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * DTD element definition conveniency functions

     d xmlTextWriterWriteFormatDTDElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatDTDElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatDTDElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatDTDElement'
     d                                     )
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteDTDElement...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteDTDElement')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * DTD attribute list definition

     d xmlTextWriterStartDTDAttlist...
     d                 pr                  extproc(
     d                                     'xmlTextWriterStartDTDAttlist')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextWriterEndDTDAttlist...
     d                 pr                  extproc('xmlTextWriterEndDTDAttlist')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * DTD attribute list definition conveniency functions

     d xmlTextWriterWriteFormatDTDAttlist...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteFormatDTDAttlist')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatDTDAttlist...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteVFormatDTDAttlist'
     d                                     )
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteDTDAttlist...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteDTDAttlist')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * DTD entity definition

     d xmlTextWriterStartDTDEntity...
     d                 pr                  extproc(
     d                                     'xmlTextWriterStartDTDEntity')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pe                                 value like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlTextWriterEndDTDEntity...
     d                 pr                  extproc('xmlTextWriterEndDTDEntity')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      * DTD entity definition conveniency functions

     d xmlTextWriterWriteFormatDTDInternalEntity...
     d                 pr                  extproc('xmlTextWriterWriteFormatDTD-
     d                                     InternalEntity')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pe                                 value like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  #vararg1                       *   value options(*string: *nopass)      void *
     d  #vararg2                       *   value options(*string: *nopass)      void *
     d  #vararg3                       *   value options(*string: *nopass)      void *
     d  #vararg4                       *   value options(*string: *nopass)      void *
     d  #vararg5                       *   value options(*string: *nopass)      void *
     d  #vararg6                       *   value options(*string: *nopass)      void *
     d  #vararg7                       *   value options(*string: *nopass)      void *
     d  #vararg8                       *   value options(*string: *nopass)      void *

     d xmlTextWriterWriteVFormatDTDInternalEntity...
     d                 pr                  extproc('xmlTextWriterWriteVFormatDT-
     d                                     DInternalEntity')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pe                                 value like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *
     d  format                         *   value options(*string)               const char *
     d  argptr                             likeds(xmlVaList)

     d xmlTextWriterWriteDTDInternalEntity...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteDTDInternalEntity'
     d                                     )
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pe                                 value like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteDTDExternalEntity...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteDTDExternalEntity'
     d                                     )
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pe                                 value like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  ndataid                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteDTDExternalEntityContents...
     d                 pr                  extproc('xmlTextWriterWriteDTDExtern-
     d                                     alEntityContents')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  ndataid                        *   value options(*string)               const xmlChar *

     d xmlTextWriterWriteDTDEntity...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteDTDEntity')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  pe                                 value like(xmlCint)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *
     d  ndataid                        *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      * DTD notation definition

     d xmlTextWriterWriteDTDNotation...
     d                 pr                  extproc(
     d                                     'xmlTextWriterWriteDTDNotation')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  pubid                          *   value options(*string)               const xmlChar *
     d  sysid                          *   value options(*string)               const xmlChar *

      * Indentation

     d xmlTextWriterSetIndent...
     d                 pr                  extproc('xmlTextWriterSetIndent')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  indent                             value like(xmlCint)

     d xmlTextWriterSetIndentString...
     d                 pr                  extproc(
     d                                     'xmlTextWriterSetIndentString')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  str                            *   value options(*string)               const xmlChar *

     d xmlTextWriterSetQuoteChar...
     d                 pr                  extproc('xmlTextWriterSetQuoteChar')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)
     d  quotechar                          value like(xmlChar)

      * misc

     d xmlTextWriterFlush...
     d                 pr                  extproc('xmlTextWriterFlush')
     d                                     like(xmlCint)
     d  writer                             value like(xmlTextWriterPtr)

      /endif                                                                    LIBXML_WRITER_ENABLD
      /endif                                                                    XML_XMLWRITER_H__
