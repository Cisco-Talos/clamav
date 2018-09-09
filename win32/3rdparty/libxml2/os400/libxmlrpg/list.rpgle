      * Summary: lists interfaces
      * Description: this module implement the list support used in
      * various place in the library.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_LINK_INCLUDE__)
      /define XML_LINK_INCLUDE__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"

     d xmlLinkPtr      s               *   based(######typedef######)

     d xmlListPtr      s               *   based(######typedef######)

      * xmlListDeallocator:
      * @lk:  the data to deallocate
      *
      * Callback function used to free data from a list.

     d xmlListDeallocator...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlListDataCompare:
      * @data0: the first data
      * @data1: the second data
      *
      * Callback function used to compare 2 data.
      *
      * Returns 0 is equality, -1 or 1 otherwise depending on the ordering.

     d xmlListDataCompare...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlListWalker:
      * @data: the data found in the list
      * @user: extra user provided data to the walker
      *
      * Callback function used when walking a list with xmlListWalk().
      *
      * Returns 0 to stop walking the list, 1 otherwise.

     d xmlListWalker   s               *   based(######typedef######)
     d                                     procptr

      * Creation/Deletion

     d xmlListCreate   pr                  extproc('xmlListCreate')
     d                                     like(xmlListPtr)
     d  deallocator                        value like(xmlListDeallocator)
     d  compare                            value like(xmlListDataCompare)

     d xmlListDelete   pr                  extproc('xmlListDelete')
     d  l                                  value like(xmlListPtr)

      * Basic Operators

     d xmlListSearch   pr              *   extproc('xmlListSearch')             void *
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListReverseSearch...
     d                 pr              *   extproc('xmlListReverseSearch')      void *
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListInsert   pr                  extproc('xmlListInsert')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListAppend   pr                  extproc('xmlListAppend')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListRemoveFirst...
     d                 pr                  extproc('xmlListRemoveFirst')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListRemoveLast...
     d                 pr                  extproc('xmlListRemoveLast')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListRemoveAll...
     d                 pr                  extproc('xmlListRemoveAll')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListClear    pr                  extproc('xmlListClear')
     d  l                                  value like(xmlListPtr)

     d xmlListEmpty    pr                  extproc('xmlListEmpty')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)

     d xmlListFront    pr                  extproc('xmlListFront')
     d                                     like(xmlLinkPtr)
     d  l                                  value like(xmlListPtr)

     d xmlListEnd      pr                  extproc('xmlListEnd')
     d                                     like(xmlLinkPtr)
     d  l                                  value like(xmlListPtr)

     d xmlListSize     pr                  extproc('xmlListSize')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)

     d xmlListPopFront...
     d                 pr                  extproc('xmlListPopFront')
     d  l                                  value like(xmlListPtr)

     d xmlListPopBack...
     d                 pr                  extproc('xmlListPopBack')
     d  l                                  value like(xmlListPtr)

     d xmlListPushFront...
     d                 pr                  extproc('xmlListPushFront')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

     d xmlListPushBack...
     d                 pr                  extproc('xmlListPushBack')
     d                                     like(xmlCint)
     d  l                                  value like(xmlListPtr)
     d  data                           *   value                                void *

      * Advanced Operators

     d xmlListReverse  pr                  extproc('xmlListReverse')
     d  l                                  value like(xmlListPtr)

     d xmlListSort     pr                  extproc('xmlListSort')
     d  l                                  value like(xmlListPtr)

     d xmlListWalk     pr                  extproc('xmlListWalk')
     d  l                                  value like(xmlListPtr)
     d  walker                             value like(xmlListWalker)
     d  user                           *   value                                const void *

     d xmlListReverseWalk...
     d                 pr                  extproc('xmlListReverseWalk')
     d  l                                  value like(xmlListPtr)
     d  walker                             value like(xmlListWalker)
     d  user                           *   value                                const void *

     d xmlListMerge    pr                  extproc('xmlListMerge')
     d  l1                                 value like(xmlListPtr)
     d  l2                                 value like(xmlListPtr)

     d xmlListDup      pr                  extproc('xmlListDup')
     d                                     like(xmlListPtr)
     d  old                                value like(xmlListPtr)

     d xmlListCopy     pr                  extproc('xmlListCopy')
     d                                     like(xmlCint)
     d  cur                                value like(xmlListPtr)
     d  old                                value like(xmlListPtr)               const

      * Link operators

     d xmlListGetData  pr              *   extproc('xmlListGetData')            void *
     d  lk                                 value like(xmlLinkPtr)

      * xmlListUnique()
      * xmlListSwap

      /endif                                                                    XML_LINK_INCLUDE__
