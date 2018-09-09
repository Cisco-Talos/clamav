      * Summary: string dictionary
      * Description: dictionary of reusable strings, just used to avoid
      *         allocation and freeing operations.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_DICT_H__)
      /define XML_DICT_H__

      * The dictionary.

     d xmlDictPtr      s               *   based(######typedef######)

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"

      * Initializer

     d xmlInitializeDict...
     d                 pr                  extproc('xmlInitializeDict')
     d                                     like(xmlCint)

      * Constructor and destructor.

     d xmlDictCreate   pr                  extproc('xmlDictCreate')
     d                                     like(xmlDictPtr)

     d xmlDictSetLimit...
     d                 pr                  extproc('xmlDictSetLimit')
     d                                     like(xmlCsize_t)
     d  dict                               value like(xmlDictPtr)
     d  limit                              value like(xmlCsize_t)

     d xmlDictGetUsage...
     d                 pr                  extproc('xmlDictGetUsage')
     d                                     like(xmlCsize_t)
     d  dict                               value like(xmlDictPtr)

     d xmlDictCreateSub...
     d                 pr                  extproc('xmlDictCreateSub')
     d                                     like(xmlDictPtr)
     d  sub                                value like(xmlDictPtr)

     d xmlDictReference...
     d                 pr                  extproc('xmlDictGetReference')
     d                                     like(xmlCint)
     d  dict                               value like(xmlDictPtr)

     d xmlDictFree     pr                  extproc('xmlDictFree')
     d  dict                               value like(xmlDictPtr)

      * Lookup of entry in the dictionary.

     d xmlDictLookup   pr              *   extproc('xmlDictLookup')             const xmlChar *
     d  dict                               value like(xmlDictPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlDictExists   pr              *   extproc('xmlDictExists')             const xmlChar *
     d  dict                               value like(xmlDictPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlDictQLookup  pr              *   extproc('xmlDictQLookup')            const xmlChar *
     d  dict                               value like(xmlDictPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *

     d xmlDictOwns     pr                  extproc('xmlDictOwns')
     d                                     like(xmlCint)
     d  dict                               value like(xmlDictPtr)
     d  str                            *   value options(*string)               const xmlChar *

     d xmlDictSize     pr                  extproc('xmlDictSize')
     d                                     like(xmlCint)
     d  dict                               value like(xmlDictPtr)

      * Cleanup function

     d xmlDictCleanup  pr                  extproc('xmlDictCleanup')

      /endif                                                                    ! XML_DICT_H__
