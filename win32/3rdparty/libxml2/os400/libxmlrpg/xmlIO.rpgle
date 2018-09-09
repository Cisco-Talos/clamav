      * Summary: interface for the I/O interfaces used by the parser
      * Description: interface for the I/O interfaces used by the parser
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_IO_H__)
      /define XML_IO_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"

      * Those are the functions and datatypes for the parser input
      * I/O structures.

      * xmlInputMatchCallback:
      * @filename: the filename or URI
      *
      * Callback used in the I/O Input API to detect if the current handler
      * can provide input fonctionnalities for this resource.
      *
      * Returns 1 if yes and 0 if another Input module should be used

     d xmlInputMatchCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlInputOpenCallback:
      * @filename: the filename or URI
      *
      * Callback used in the I/O Input API to open the resource
      *
      * Returns an Input context or NULL in case or error

     d xmlInputOpenCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlInputReadCallback:
      * @context:  an Input context
      * @buffer:  the buffer to store data read
      * @len:  the length of the buffer in bytes
      *
      * Callback used in the I/O Input API to read the resource
      *
      * Returns the number of bytes read or -1 in case of error

     d xmlInputReadCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlInputCloseCallback:
      * @context:  an Input context
      *
      * Callback used in the I/O Input API to close the resource
      *
      * Returns 0 or -1 in case of error

     d xmlInputCloseCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      /if defined(LIBXML_OUTPUT_ENABLED)

      * Those are the functions and datatypes for the library output
      * I/O structures.

      * xmlOutputMatchCallback:
      * @filename: the filename or URI
      *
      * Callback used in the I/O Output API to detect if the current handler
      * can provide output fonctionnalities for this resource.
      *
      * Returns 1 if yes and 0 if another Output module should be used

     d xmlOutputMatchCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlOutputOpenCallback:
      * @filename: the filename or URI
      *
      * Callback used in the I/O Output API to open the resource
      *
      * Returns an Output context or NULL in case or error

     d xmlOutputOpenCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlOutputWriteCallback:
      * @context:  an Output context
      * @buffer:  the buffer of data to write
      * @len:  the length of the buffer in bytes
      *
      * Callback used in the I/O Output API to write to the resource
      *
      * Returns the number of bytes written or -1 in case of error

     d xmlOutputWriteCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlOutputCloseCallback:
      * @context:  an Output context
      *
      * Callback used in the I/O Output API to close the resource
      *
      * Returns 0 or -1 in case of error

     d xmlOutputCloseCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      /include "libxmlrpg/globals"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/parser"
      /include "libxmlrpg/encoding"

     d xmlParserInputBuffer...
     d                 ds                  based(xmlParserInputBufferPtr)
     d                                     align qualified
     d  context                        *                                        void *
     d  readcallback                       like(xmlInputReadCallback)
     d  closecallback                      like(xmlInputCloseCallback)
      *
     d  encoder                            like(xmlCharEncodingHandlerPtr)      Conversions --> UTF8
      *
     d  buffer                             like(xmlBufPtr)                      UTF-8 local buffer
     d  raw                                like(xmlBufPtr)                      Raw input buffer
     d  compressed                         like(xmlCint)
     d  error                              like(xmlCint)
     d  rawconsumed                        like(xmlCulong)

      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlOutputBuffer...
     d                 ds                  based(xmlOutputBufferPtr)
     d                                     align qualified
     d  context                        *                                        void *
     d  writecallback                      like(xmlOutputWriteCallback)
     d  closecallback                      like(xmlOutputCloseCallback)
      *
     d  encoder                            like(xmlCharEncodingHandlerPtr)      Conversions --> UTF8
      *
     d  buffer                             like(xmlBufPtr)                      UTF-8/ISOLatin local
     d  conv                               like(xmlBufPtr)                      Buffer for output
     d  written                            like(xmlCint)                        Total # byte written
     d  error                              like(xmlCint)
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      * Interfaces for input

     d xmlCleanupInputCallbacks...
     d                 pr                  extproc('xmlCleanupInputCallbacks')

     d xmlPopInputCallbacks...
     d                 pr                  extproc('xmlPopInputCallbacks')
     d                                     like(xmlCint)

     d xmlRegisterDefaultInputCallbacks...
     d                 pr                  extproc(
     d                                      'xmlRegisterDefaultInputCallbacks')

     d xmlAllocParserInputBuffer...
     d                 pr                  extproc('xmlAllocParserInputBuffer')
     d                                     like(xmlParserInputBufferPtr)
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferCreateFilename...
     d                 pr                  extproc(
     d                                     'xmlParserInputBufferCreateFilename')
     d                                     like(xmlParserInputBufferPtr)
     d  URI                            *   value options(*string)               const char *
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferCreateFile...
     d                 pr                  extproc(
     d                                      'xmlParserInputBufferCreateFile')
     d                                     like(xmlParserInputBufferPtr)
     d  file                           *   value                                FILE *
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferCreateFd...
     d                 pr                  extproc(
     d                                      'xmlParserInputBufferCreateFd')
     d                                     like(xmlParserInputBufferPtr)
     d  fd                                 value like(xmlCint)
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferCreateMem...
     d                 pr                  extproc(
     d                                      'xmlParserInputBufferCreateMem')
     d                                     like(xmlParserInputBufferPtr)
     d  mem                            *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferCreateStatic...
     d                 pr                  extproc(
     d                                      'xmlParserInputBufferCreateStatic')
     d                                     like(xmlParserInputBufferPtr)
     d  mem                            *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferCreateIO...
     d                 pr                  extproc(
     d                                      'xmlParserInputBufferCreateIO')
     d                                     like(xmlParserInputBufferPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  enc                                value like(xmlCharEncoding)

     d xmlParserInputBufferRead...
     d                 pr                  extproc('xmlParserInputBufferRead')
     d                                     like(xmlCint)
     d  in                                 value like(xmlParserInputBufferPtr)
     d  len                                value like(xmlCint)

     d xmlParserInputBufferGrow...
     d                 pr                  extproc('xmlParserInputBufferGrow')
     d                                     like(xmlCint)
     d  in                                 value like(xmlParserInputBufferPtr)
     d  len                                value like(xmlCint)

     d xmlParserInputBufferPush...
     d                 pr                  extproc('xmlParserInputBufferPush')
     d                                     like(xmlCint)
     d  in                                 value like(xmlParserInputBufferPtr)
     d  len                                value like(xmlCint)
     d  buf                            *   value options(*string)               const char *

     d xmlFreeParserInputBuffer...
     d                 pr                  extproc('xmlFreeParserInputBuffer')
     d  in                                 value like(xmlParserInputBufferPtr)

     d xmlParserGetDirectory...
     d                 pr              *   extproc('xmlParserGetDirectory')     char *
     d  filename                       *   value options(*string)               const char *

     d xmlRegisterInputCallbacks...
     d                 pr                  extproc('xmlRegisterInputCallbacks')
     d                                     like(xmlCint)
     d  matchFunc                          value like(xmlInputMatchCallback)
     d  openFunc                           value like(xmlInputOpenCallback)
     d  readFunc                           value like(xmlInputReadCallback)
     d  closeFunc                          value like(xmlInputCloseCallback)

      /if defined(LIBXML_OUTPUT_ENABLED)

      * Interfaces for output

     d xmlCleanupOutputCallbacks...
     d                 pr                  extproc('xmlCleanupOutputCallbacks')

     d xmlRegisterDefaultOutputCallbacks...
     d                 pr                  extproc(
     d                                      'xmlRegisterDefaultOuputCallbacks')

     d xmlAllocOutputBuffer...
     d                 pr                  extproc('xmlAllocOutputBuffer')
     d                                     like(xmlOutputBufferPtr)
     d  encoder                            value
     d                                     like(xmlCharEncodingHandlerPtr)

     d xmlOutputBufferCreateFilename...
     d                 pr                  extproc(
     d                                      'xmlOutputBufferCreateFilename')
     d                                     like(xmlOutputBufferPtr)
     d  URI                            *   value options(*string)               const char *
     d  encoder                            value
     d                                     like(xmlCharEncodingHandlerPtr)
     d  compression                        value like(xmlCint)

     d xmlOutputBufferCreateFile...
     d                 pr                  extproc('xmlOutputBufferCreateFile')
     d                                     like(xmlOutputBufferPtr)
     d  file                           *   value                                FILE *
     d  encoder                            value
     d                                     like(xmlCharEncodingHandlerPtr)

     d xmlOutputBufferCreateBuffer...
     d                 pr                  extproc(
     d                                      'xmlOutputBufferCreateBuffer')
     d                                     like(xmlOutputBufferPtr)
     d  buffer                             value like(xmlBufferPtr)
     d  encoder                            value
     d                                     like(xmlCharEncodingHandlerPtr)

     d xmlOutputBufferCreateFd...
     d                 pr                  extproc('xmlOutputBufferCreateFd')
     d                                     like(xmlOutputBufferPtr)
     d  fd                                 value like(xmlCint)
     d  encoder                            value
     d                                     like(xmlCharEncodingHandlerPtr)

     d xmlOutputBufferCreateIO...
     d                 pr                  extproc('xmlOutputBufferCreateIO')
     d                                     like(xmlOutputBufferPtr)
     d  iowrite                            value like(xmlOutputWriteCallback)
     d  ioclose                            value like(xmlOutputCloseCallback)
     d  ioctx                          *   value                                void *
     d  encoder                            value
     d                                     like(xmlCharEncodingHandlerPtr)

      * Couple of APIs to get the output without digging into the buffers

     d xmlOutputBufferGetContent...
     d                 pr              *   extproc('xmlOutputBufferGetContent') const xmlChar *
     d  out                                value like(xmlOutputBufferPtr)

     d xmlOutputBufferGetSize...
     d                 pr                  extproc('xmlOutputBufferGetSize')
     d                                     like(xmlCsize_t)
     d  out                                value like(xmlOutputBufferPtr)

     d xmlOutputBufferWrite...
     d                 pr                  extproc('xmlOutputBufferWrite')
     d                                     like(xmlCint)
     d  out                                value like(xmlOutputBufferPtr)
     d  len                                value like(xmlCint)
     d  buf                            *   value options(*string)               const char *

     d xmlOutputBufferWriteString...
     d                 pr                  extproc('xmlOutputBufferWriteString')
     d                                     like(xmlCint)
     d  out                                value like(xmlOutputBufferPtr)
     d  str                            *   value options(*string)               const char *

     d xmlOutputBufferWriteEscape...
     d                 pr                  extproc('xmlOutputBufferWriteEscape')
     d                                     like(xmlCint)
     d  out                                value like(xmlOutputBufferPtr)
     d  str                            *   value options(*string)               const xmlChar *
     d  escaping                           value like(xmlCharEncodingOutputFunc)

     d xmlOutputBufferFlush...
     d                 pr                  extproc('xmlOutputBufferFlush')
     d                                     like(xmlCint)
     d  out                                value like(xmlOutputBufferPtr)

     d xmlOutputBufferClose...
     d                 pr                  extproc('xmlOutputBufferClose')
     d                                     like(xmlCint)
     d  out                                value like(xmlOutputBufferPtr)

     d xmlRegisterOutputCallbacks...
     d                 pr                  extproc('xmlRegisterOutputCallbacks')
     d                                     like(xmlCint)
     d  matchFunc                          value like(xmlOutputMatchCallback)
     d  openFunc                           value like(xmlOutputOpenCallback)
     d  writeFunc                          value like(xmlOutputWriteCallback)
     d  closeFunc                          value like(xmlOutputCloseCallback)

      /if defined(LIBXML_HTTP_ENABLED)

      *  This function only exists if HTTP support built into the library

     d xmlRegisterHTTPPostCallbacks...
     d                 pr                  extproc(
     d                                      'xmlRegisterHTTPPostCallbacks')

      /endif                                                                    LIBXML_HTTP_ENABLED
      /endif                                                                    LIBXML_OUTPUT_ENABLD

     d xmlCheckHTTPInput...
     d                 pr                  extproc('xmlCheckHTTPInput')
     d                                     like(xmlParserInputPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  ret                                value like(xmlParserInputPtr)

      * A predefined entity loader disabling network accesses

     d xmlNoNetExternalEntityLoader...
     d                 pr                  extproc(
     d                                      'xmlNoNetExternalEntityLoader')
     d                                     like(xmlParserInputPtr)
     d  URL                            *   value options(*string)               const char *
     d  ID                             *   value options(*string)               const char *
     d  ctxt                               value like(xmlParserCtxtPtr)

      * xmlNormalizeWindowsPath is obsolete, don't use it.
      * Check xmlCanonicPath in uri.h for a better alternative.

     d xmlNormalizeWindowsPath...
     d                 pr              *   extproc('xmlNormalizeWindowsPath')   xmlChar *
     d  path                           *   value options(*string)               const xmlChar *

     d xmlCheckFilename...
     d                 pr                  extproc('xmlCheckFilename')
     d                                     like(xmlCint)
     d  path                           *   value options(*string)               const char *

      * Default 'file://' protocol callbacks

     d xmlFileMatch    pr                  extproc('xmlFileMatch')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *

     d xmlFileOpen     pr              *   extproc('xmlFileOpen')               void *
     d  filename                       *   value options(*string)               const char *

     d xmlFileRead     pr                  extproc('xmlFileRead')
     d                                     like(xmlCint)
     d  context                        *   value                                void *
     d  buffer                    65535    options(*varsize)
     d  len                                value like(xmlCint)

     d xmlFileClose    pr                  extproc('xmlFileClose')
     d                                     like(xmlCint)
     d  context                        *   value                                void *

      * Default 'http://' protocol callbacks

      /if defined(LIBXML_HTTP_ENABLED)
     d xmlIOHTTPMatch  pr                  extproc('xmlIOHTTPMatch')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *

     d xmlIOHTTPOpen   pr              *   extproc('xmlIOHTTPOpen')             void *
     d  filename                       *   value options(*string)               const char *

      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlIOHTTPOpenW  pr              *   extproc('xmlIOHTTPOpenW')            void *
     d  post_uri                       *   value options(*string)               const char *
     d  compression                        value like(xmlCint)
      /endif                                                                    LIBXML_OUTPUT_ENABLD

     d xmlIOHTTPRead   pr                  extproc('xmlIOHTTPRead')
     d                                     like(xmlCint)
     d  context                        *   value                                void *
     d  buffer                    65535    options(*varsize)
     d  len                                value like(xmlCint)

     d xmlIOHTTPClose  pr                  extproc('xmlIOHTTPClose')
     d                                     like(xmlCint)
     d  context                        *   value                                void *
      /endif                                                                    LIBXML_HTTP_ENABLED

      * Default 'ftp://' protocol callbacks

      /if defined(LIBXML_FTP_ENABLED)
     d xmlIOFTPMatch   pr                  extproc('xmlIOFTPMatch')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *

     d xmlIOFTPOpen    pr              *   extproc('xmlIOFTPOpen')              void *
     d  filename                       *   value options(*string)               const char *

     d xmlIOFTPRead    pr                  extproc('xmlIOFTPRead')
     d                                     like(xmlCint)
     d  context                        *   value                                void *
     d  buffer                    65535    options(*varsize)
     d  len                                value like(xmlCint)

     d xmlIOFTPClose   pr                  extproc('xmlIOFTPClose')
     d                                     like(xmlCint)
     d  context                        *   value                                void *
      /endif                                                                    LIBXML_FTP_ENABLED

      /endif                                                                    XML_IO_H__
