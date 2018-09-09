      * Summary: Unicode character range checking
      * Description: this module exports interfaces for the character
      *               range validation APIs
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_CHVALID_H__)
      /define XML_CHVALID_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/xmlstring"

      * Define our typedefs and structures

     d xmlChSRangePtr  s               *   based(######typedef######)

     d xmlChSRange     ds                  based(xmlChSRangePtr)
     d                                     align qualified
     d  low                                like(xmlCushort)
     d  high                               like(xmlCushort)

     d xmlChLRangePtr  s               *   based(######typedef######)

     d xmlChLRange     ds                  based(xmlChLRangePtr)
     d                                     align qualified
     d  low                                like(xmlCuint)
     d  high                               like(xmlCuint)

     d xmlChRangeGroupPtr...
     d                 s               *   based(######typedef######)

     d xmlChRangeGroup...
     d                 ds                  based(xmlChRangeGroupPtr)
     d                                     align qualified
     d  nbShortRange                       like(xmlCint)
     d  nbLongRange                        like(xmlCint)
     d  shortRange                         like(xmlChSRangePtr)
     d  longRange                          like(xmlChLRangePtr)

      * Range checking routine

     d xmlCharInRange  pr                  extproc('xmlCharInRange')
     d                                     like(xmlCint)
     d val                                 value like(xmlCuint)
     d group                               like(xmlChRangeGroupPtr)             const

     d xmlIsBaseCharGroup...
     d                 ds                  import('xmlIsBaseCharGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsCharGroup...
     d                 ds                  import('xmlIsCharGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsCombiningGroup...
     d                 ds                  import('xmlIsCombiningGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsDigitGroup...
     d                 ds                  import('xmlIsDigitGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsExtenderGroup...
     d                 ds                  import('xmlIsExtenderGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsIdeographicGroup...
     d                 ds                  import('xmlIsIdeographicGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsBaseChar   pr                  extproc('xmlIsBaseChar')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsBlank      pr                  extproc('xmlIsBlank')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsChar       pr                  extproc('xmlIsChar')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsCombining  pr                  extproc('xmlIsCombining')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsDigit      pr                  extproc('xmlIsDigit')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsExtender   pr                  extproc('xmlIsExtender')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsIdeographic...
     d                 pr                  extproc('xmlIsIdeographic')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

     d xmlIsPubidChar  pr                  extproc('xmlIsPubidChar')
     d                                     like(xmlCint)
     d ch                                  value like(xmlCuint)

      /endif                                                                    XML_CHVALID_H__
