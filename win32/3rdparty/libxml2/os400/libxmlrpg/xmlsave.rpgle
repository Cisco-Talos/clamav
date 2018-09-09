      * Summary: the XML document serializer
      * Description: API to save document or subtree of document
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_XMLSAVE_H__)
      /define XML_XMLSAVE_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_OUTPUT_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/encoding"
      /include "libxmlrpg/xmlIO"

      * xmlSaveOption:
      *
      * This is the set of XML save options that can be passed down
      * to the xmlSaveToFd() and similar calls.

     d xmlSaveOption   s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_SAVE_FORMAT...                                                      Format save output
     d                 c                   X'0001'
     d  XML_SAVE_NO_DECL...                                                     Drop xml declaration
     d                 c                   X'0002'
     d  XML_SAVE_NO_EMPTY...                                                    No empty tags
     d                 c                   X'0004'
     d  XML_SAVE_NO_XHTML...                                                    No XHTML1 specific
     d                 c                   X'0008'
     d  XML_SAVE_XHTML...                                                       Frce XHTML1 specific
     d                 c                   X'0010'
     d  XML_SAVE_AS_XML...                                                      Frce XML on HTML doc
     d                 c                   X'0020'
     d  XML_SAVE_AS_HTML...                                                     Frce HTML on XML doc
     d                 c                   X'0040'
     d  XML_SAVE_WSNONSIG...                                                    Fmt w/ non-sig space
     d                 c                   X'0080'

     d xmlSaveCtxtPtr  s               *   based(######typedef######)

     d xmlSaveToFd     pr                  extproc('xmlSaveToFd')
     d                                     like(xmlSaveCtxtPtr)
     d  fd                                 value like(xmlCint)
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlSaveToFilename...
     d                 pr                  extproc('xmlSaveToFilename')
     d                                     like(xmlSaveCtxtPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlSaveToBuffer...
     d                 pr                  extproc('xmlSaveToBuffer')
     d                                     like(xmlSaveCtxtPtr)
     d  buffer                             value like(xmlBufferPtr)
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlSaveToIO     pr                  extproc('xmlSaveToIO')
     d                                     like(xmlSaveCtxtPtr)
     d  iowrite                            value like(xmlOutputWriteCallback)
     d  ioclose                            value like(xmlOutputCloseCallback)
     d  ioctx                          *   value                                void *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlSaveDoc      pr                  extproc('xmlSaveDoc')
     d                                     like(xmlClong)
     d  ctxt                               value like(xmlSaveCtxtPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlSaveTree     pr                  extproc('xmlSaveTree')
     d                                     like(xmlClong)
     d  ctxt                               value like(xmlSaveCtxtPtr)
     d  node                               value like(xmlNodePtr)

     d xmlSaveFlush    pr                  extproc('xmlSaveFlush')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSaveCtxtPtr)

     d xmlSaveClose    pr                  extproc('xmlSaveClose')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSaveCtxtPtr)

     d xmlSaveSetEscape...
     d                 pr                  extproc('xmlSaveSetEscape')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSaveCtxtPtr)
     d  escape                             value like(xmlCharEncodingOutputFunc)

     d xmlSaveSetAttrEscape...
     d                 pr                  extproc('xmlSaveSetAttrEscape')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlSaveCtxtPtr)
     d  escape                             value like(xmlCharEncodingOutputFunc)

      /endif                                                                    LIBXML_OUTPUT_ENABLD
      /endif                                                                    XML_XMLSAVE_H__
