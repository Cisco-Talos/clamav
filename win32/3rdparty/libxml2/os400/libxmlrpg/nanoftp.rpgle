      * Summary: minimal FTP implementation
      * Description: minimal FTP implementation allowing to fetch resources
      *              like external subset.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(NANO_FTP_H__)
      /define NANO_FTP_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_FTP_ENABLED)

      /include "libxmlrpg/xmlTypesC"

     d INVALID_SOCKET  c                   -1

      * ftpListCallback:
      * @userData:  user provided data for the callback
      * @filename:  the file name (including "->" when links are shown)
      * @attrib:  the attribute string
      * @owner:  the owner string
      * @group:  the group string
      * @size:  the file size
      * @links:  the link count
      * @year:  the year
      * @month:  the month
      * @day:  the day
      * @hour:  the hour
      * @minute:  the minute
      *
      * A callback for the xmlNanoFTPList command.
      * Note that only one of year and day:minute are specified.

     d ftpListCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * ftpDataCallback:
      * @userData: the user provided context
      * @data: the data received
      * @len: its size in bytes
      *
      * A callback for the xmlNanoFTPGet command.

     d ftpDataCallback...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * Init

     d xmlNanoFTPInit  pr                  extproc('xmlNanoFTPInit')

     d xmlNanoFTPCleanup...
     d                 pr                  extproc('xmlNanoFTPCleanup')

      * Creating/freeing contexts.

     d xmlNanoFTPNewCtxt...
     d                 pr              *   extproc('xmlNanoFTPNewCtxt')         void *
     d  URL                            *   value options(*string)               const char *

     d xmlNanoFTPFreeCtxt...
     d                 pr                  extproc('xmlNanoFTPFreeCtxt')
     d  ctx                            *   value                                void *

     d xmlNanoFTPConnectTo...
     d                 pr              *   extproc('xmlNanoFTPConnectTo')       void *
     d  server                         *   value options(*string)               const char *
     d  port                               value like(xmlCint)

      * Opening/closing session connections.

     d xmlNanoFTPOpen  pr              *   extproc('xmlNanoFTPOpen')            void *
     d  URL                            *   value options(*string)               const char *

     d xmlNanoFTPConnect...
     d                 pr                  extproc('xmlNanoFTPConnect')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoFTPClose...
     d                 pr                  extproc('xmlNanoFTPClose')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoFTPQuit  pr                  extproc('xmlNanoFTPQuit')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoFTPScanProxy...
     d                 pr                  extproc('xmlNanoFTPScanProxy')
     d  URL                            *   value options(*string)               const char *

     d xmlNanoFTPProxy...
     d                 pr                  extproc('xmlNanoFTPProxy')
     d  host                           *   value options(*string)               const char *
     d  port                               value like(xmlCint)
     d  user                           *   value options(*string)               const char *
     d  passwd                         *   value options(*string)               const char *
     d  type                               value like(xmlCint)

     d xmlNanoFTPUpdateURL...
     d                 pr                  extproc('xmlNanoFTPUpdateURL')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  URL                            *   value options(*string)               const char *

      * Rather internal commands.

     d xmlNanoFTPGetResponse...
     d                 pr                  extproc('xmlNanoFTPGetResponse')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoFTPCheckResponse...
     d                 pr                  extproc('xmlNanoFTPCheckResponse')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

      * CD/DIR/GET handlers.

     d xmlNanoFTPCwd   pr                  extproc('xmlNanoFTPCwd')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  directory                      *   value options(*string)               const char *

     d xmlNanoFTPDele  pr                  extproc('xmlNanoFTPDele')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  file                           *   value options(*string)               const char *

     d xmlNanoFTPGetConnection...
     d                 pr                  extproc('xmlNanoFTPGetConnection')   Socket descriptor
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoFTPCloseConnection...
     d                 pr                  extproc('xmlNanoFTPCloseConnection')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *

     d xmlNanoFTPList  pr                  extproc('xmlNanoFTPList')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  callback                           value like(ftpListCallback)
     d  userData                       *   value                                void *
     d  filename                       *   value options(*string)               const char *

     d xmlNanoFTPGetSocket...
     d                 pr                  extproc('xmlNanoFTPGetSocket')       Socket descriptor
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  filename                       *   value options(*string)               const char *

     d xmlNanoFTPGet   pr                  extproc('xmlNanoFTPGet')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  callback                           value like(ftpDataCallback)
     d  userData                       *   value                                void *
     d  filename                       *   value options(*string)               const char *

     d xmlNanoFTPRead  pr                  extproc('xmlNanoFTPRead')
     d                                     like(xmlCint)
     d  ctx                            *   value                                void *
     d  dest                           *   value                                void *
     d  len                                value like(xmlCint)

      /endif                                                                    LIBXML_FTP_ENABLED
      /endif                                                                    NANO_FTP_H__
