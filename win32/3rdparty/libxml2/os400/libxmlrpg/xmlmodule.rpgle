      * Summary: dynamic module loading
      * Description: basic API for dynamic module loading, used by
      *              libexslt added in 2.6.17
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_MODULE_H__)
      /define XML_MODULE_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_MODULES_ENABLED)

      /include "libxmlrpg/xmlTypesC"

      * xmlModulePtr:
      *
      * A handle to a dynamically loaded module

     d xmlModulePtr    s               *   based(######typedef######)

      * xmlModuleOption:
      *
      * enumeration of options that can be passed down to xmlModuleOpen()

     d xmlModuleOption...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_MODULE_LAZY...                                                      Lazy binding
     d                 c                   1
     d  XML_MODULE_LOCAL...                                                     Local binding
     d                 c                   2

     d xmlModuleOpen   pr                  extproc('xmlModuleOpen')
     d                                     like(xmlModulePtr)
     d  filename                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlModuleSymbol...
     d                 pr                  extproc('xmlModuleSymbol')
     d                                     like(xmlCint)
     d  module                             value like(xmlModulePtr)
     d  name                           *   value options(*string)               const char *
     d  result                         *                                        void *(*)

     d xmlModuleClose  pr                  extproc('xmlModuleClose')
     d                                     like(xmlCint)
     d  module                             value like(xmlModulePtr)

     d xmlModuleFree   pr                  extproc('xmlModuleFree')
     d                                     like(xmlCint)
     d  module                             value like(xmlModulePtr)

      /endif                                                                    LIBXML_MODULES_ENBLD
      /endif                                                                    XML_MODULE_H__
