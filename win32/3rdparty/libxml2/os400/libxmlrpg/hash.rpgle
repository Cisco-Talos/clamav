      * Summary: Chained hash tables
      * Description: This module implements the hash table support used in
      *              various places in the library.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_HASH_H__)
      /define XML_HASH_H__

      /include "libxmlrpg/xmlTypesC"

      * The hash table.

     d xmlHashTablePtr...
     d                 s               *   based(######typedef######)

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/parser"
      /include "libxmlrpg/dict"

      * function types:

      * xmlHashDeallocator:
      * @payload:  the data in the hash
      * @name:  the name associated
      *
      * Callback to free data from a hash.

     d xmlHashDeallocator...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlHashCopier:
      * @payload:  the data in the hash
      * @name:  the name associated
      *
      * Callback to copy data from a hash.
      *
      * Returns a copy of the data or NULL in case of error.

     d xmlHashCopier   s               *   based(######typedef######)
     d                                     procptr

      * xmlHashScanner:
      * @payload:  the data in the hash
      * @data:  extra scannner data
      * @name:  the name associated
      *
      * Callback when scanning data in a hash with the simple scanner.

     d xmlHashScanner  s               *   based(######typedef######)
     d                                     procptr

      * xmlHashScannerFull:
      * @payload:  the data in the hash
      * @data:  extra scannner data
      * @name:  the name associated
      * @name2:  the second name associated
      * @name3:  the third name associated
      *
      * Callback when scanning data in a hash with the full scanner.

     d xmlHashScannerFull...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * Constructor and destructor.

     d xmlHashCreate   pr                  extproc('xmlHashCreate')
     d                                     like(xmlHashTablePtr)
     d  size                               value like(xmlCint)

     d xmlHashCreateDict...
     d                 pr                  extproc('xmlHashCreateDict')
     d                                     like(xmlHashTablePtr)
     d  size                               value like(xmlCint)
     d  dict                               value like(xmlDictPtr)

     d xmlHashFree     pr                  extproc('xmlHashFree')
     d  table                              value like(xmlHashTablePtr)
     d  f                                  value like(xmlHashDeallocator)

      * Add a new entry to the hash table.

     d xmlHashAddEntry...
     d                 pr                  extproc('xmlHashAddEntry')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  userdata                       *   value options(*string)               void *

     d xmlHashUpdateEntry...
     d                 pr                  extproc('xmlHashUpdateEntry')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  userdata                       *   value options(*string)               void *
     d  f                                  value like(xmlHashDeallocator)

     d xmlHashAddEntry2...
     d                 pr                  extproc('xmlHashAddEntry2')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  userdata                       *   value options(*string)               void *

     d xmlHashUpdateEntry2...
     d                 pr                  extproc('xmlHashUpdateEntry2')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  userdata                       *   value options(*string)               void *
     d  f                                  value like(xmlHashDeallocator)

     d xmlHashAddEntry3...
     d                 pr                  extproc('xmlHashAddEntry3')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *
     d  userdata                       *   value options(*string)               void *

     d xmlHashUpdateEntry3...
     d                 pr                  extproc('xmlHashUpdateEntry3')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *
     d  userdata                       *   value options(*string)               void *
     d  f                                  value like(xmlHashDeallocator)

      * Remove an entry from the hash table.

     d xmlHashRemoveEntry...
     d                 pr                  extproc('xmlHashRemoveEntry')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  f                                  value like(xmlHashDeallocator)

     d xmlHashRemoveEntry2...
     d                 pr                  extproc('xmlHashRemoveEntry2')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  f                                  value like(xmlHashDeallocator)

     d xmlHashRemoveEntry3...
     d                 pr                  extproc('xmlHashRemoveEntry3')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *
     d  f                                  value like(xmlHashDeallocator)

      * Retrieve the userdata.

     d xmlHashLookup   pr              *   extproc('xmlHashLookup')             void *
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlHashLookup2  pr              *   extproc('xmlHashLookup2')            void *
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *

     d xmlHashLookup3  pr              *   extproc('xmlHashLookup3')            void *
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *

     d xmlHashQLookup  pr              *   extproc('xmlHashQLookup')            void *
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  prefix                         *   value options(*string)               const xmlChar *

     d xmlHashQLookup2...
     d                 pr              *   extproc('xmlHashQLookup2')           void *
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  prefix2                        *   value options(*string)               const xmlChar *

     d xmlHashQLookup3...
     d                 pr              *   extproc('xmlHashQLookup3')           void *
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  prefix                         *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  prefix2                        *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *
     d  prefix3                        *   value options(*string)               const xmlChar *

      * Helpers.

     d xmlHashCopy     pr                  extproc('xmlHashCopy')
     d                                     like(xmlHashTablePtr)
     d  table                              value like(xmlHashTablePtr)
     d  f                                  value like(xmlHashCopier)

     d xmlHashSize     pr                  extproc('xmlHashSize')
     d                                     like(xmlCint)
     d  table                              value like(xmlHashTablePtr)

     d xmlHashScan     pr                  extproc('xmlHashScan')
     d  table                              value like(xmlHashTablePtr)
     d  f                                  value like(xmlHashScanner)
     d  data                           *   value options(*string)               void *

     d xmlHashScan3    pr                  extproc('xmlHashScan3')
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *
     d  f                                  value like(xmlHashScanner)
     d  data                           *   value options(*string)               void *

     d xmlHashScanFull...
     d                 pr                  extproc('xmlHashScanFull')
     d  table                              value like(xmlHashTablePtr)
     d  f                                  value like(xmlHashScannerFull)
     d  data                           *   value options(*string)               void *

     d xmlHashScanFull3...
     d                 pr                  extproc('xmlHashScanFull3')
     d  table                              value like(xmlHashTablePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  name2                          *   value options(*string)               const xmlChar *
     d  name3                          *   value options(*string)               const xmlChar *
     d  f                                  value like(xmlHashScannerFull)
     d  data                           *   value options(*string)               void *

      /endif                                                                    XML_HASH_H__
