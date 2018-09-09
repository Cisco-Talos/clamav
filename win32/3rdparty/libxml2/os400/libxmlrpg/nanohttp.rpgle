      * Summary: minimal HTTP implementation
      * Description: minimal HTTP implementation allowing to fetch resources
      *              like external subset.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(NANO_HTTP_H__)
      /define NANO_HTTP_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_HTTP_ENABLED)

      /include "libxmlrpg/xmlTypesC"

     d xmlNanoHTTPInit...
     d                 pr                  extproc('xmlNanoHTTPInit')

     d xmlNanoHTTPCleanup...
     d                 pr                  extproc('xmlNanoHTTPCleanup')

     d xmlNanoHTTPScanProxy...
     d                 pr                  extproc('xmlNanoHTTPScanProxy')
     d  URL                            *   value options(*string)               const char *

     d xmlNanoHTTPFetch...
     d                 pr                  extproc('xmlNanoHTTPFetch')
     d                                     like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  filename                       *   value options(*string)               const char *

     d xmlNanoHTTPMethod...
     d                 pr              *   extproc('xmlNanoHTTPMethod')         void *
     d  URL                            *   value options(*string)               const char *
     d  method                         *   value options(*string)               const char *
     d  input                          *   value options(*string)               const char *
     d  contentType                    *   value                                char * *
     d  headers                        *   value options(*string)               const char *
     d  ilen                               value like(xmlCint)

     d xmlNanoHTTPMethodRedir...
     d                 pr              *   extproc('xmlNanoHTTPMethodRedir')    void *
     d  URL                            *   value options(*string)               const char *
     d  method                         *   value options(*string)               const char *
     d  input                          *   value options(*string)               const char *
     d  contentType                    *   value                                char * *
     d  redir                          *   value                                char * *
     d  headers                        *   value options(*string)               const char *
     d  ilen                               value like(xmlCint)

     d xmlNanoHTTPOpen...
     d                 pr              *   extproc('xmlNanoHTTPOpen')           void *
     d  URL                            *   value options(*string)               const char *
     d  contentType                    *                                        char *(*)

     d xmlNanoHTTPOpenRedir...
     d                 pr              *   extproc('xmlNanoHTTPOpenRedir')      void *
     d  URL                            *   value options(*string)               const char *
     d  contentType                    *   value                                char * *
     d  redir                          *   value                                char * *

     d xmlNanoHTTPReturnCode...
     d                 pr                  extproc('xmlNanoHTTPReturnCode')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoHTTPAuthHeader...
     d                 pr              *   extproc('xmlNanoHTTPAuthHeader')     const char *
     d  ctx                            *   value                                void *

     d xmlNanoHTTPRedir...
     d                 pr              *   extproc('xmlNanoHTTPRedir')          const char *
     d  ctx                            *   value                                void *

     d xmlNanoHTTPContentLength...
     d                 pr                  extproc('xmlNanoHTTPContentLength')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoHTTPEncoding...
     d                 pr              *   extproc('xmlNanoHTTPEncoding')       const char *
     d  ctx                            *   value                                void *

     d xmlNanoHTTPMimeType...
     d                 pr              *   extproc('xmlNanoHTTPMimeType')       const char *
     d  ctx                            *   value                                void *

     d xmlNanoHTTPRead...
     d                 pr                  extproc('xmlNanoHTTPRead')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  dest                           *   value                                void *
     d  len                                value like(xmlCint)

      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlNanoHTTPSave...
     d                 pr                  extproc('xmlNanoHTTPSave')
     d                                     like(xmlCint)
     d  ctxt                           *   value                                void *
     d  filename                       *   value options(*string)               const char *
      /endif                                                                    LIBXML_OUTPUT_ENABLD

     d xmlNanoHTTPClose...
     d                 pr                  extproc('xmlNanoHTTPClose')
     d  ctx                            *   value                                void *

      /endif                                                                    LIBXML_HTTP_ENABLED
      /endif                                                                    NANO_HTTP_H__
