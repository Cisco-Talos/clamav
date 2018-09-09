      * Summary: interfaces for thread handling
      * Description: set of generic threading related routines
      *              should work with pthreads, Windows native or TLS threads
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_THREADS_H__)
      /define XML_THREADS_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"

      * xmlMutex are a simple mutual exception locks.

     d xmlMutexPtr     s               *   based(######typedef######)

      * xmlRMutex are reentrant mutual exception locks.

     d xmlRMutexPtr    s               *   based(######typedef######)

      /include "libxmlrpg/globals"

     d xmlNewMutex     pr                  extproc('xmlNewMutex')
     d                                     like(xmlMutexPtr)

     d xmlMutexLock    pr                  extproc('xmlMutexLock')
     d  tok                                value like(xmlMutexPtr)

     d xmlMutexUnlock  pr                  extproc('xmlMutexUnlock')
     d  tok                                value like(xmlMutexPtr)

     d xmlFreeMutex    pr                  extproc('xmlFreeMutex')
     d  tok                                value like(xmlMutexPtr)

     d xmlNewRMutex    pr                  extproc('xmlNewRMutex')
     d                                     like(xmlRMutexPtr)

     d xmlRMutexLock   pr                  extproc('xmlRMutexLock')
     d  tok                                value like(xmlRMutexPtr)

     d xmlRMutexUnlock...
     d                 pr                  extproc('xmlRMutexUnlock')
     d  tok                                value like(xmlRMutexPtr)

     d xmlFreeRMutex   pr                  extproc('xmlFreeRMutex')
     d  tok                                value like(xmlRMutexPtr)

      * Library wide APIs.

     d xmlInitThreads  pr                  extproc('xmlInitThreads')

     d xmlLockLibrary  pr                  extproc('xmlLockLibrary')

     d xmlUnlockLibrary...
     d                 pr                  extproc('xmlUnlockLibrary')

     d xmlGetThreadId  pr                  extproc('xmlGetThreadId')
     d                                     like(xmlCint)

     d xmlIsMainThread...
     d                 pr                  extproc('xmlIsMainThread')
     d                                     like(xmlCint)

     d xmlCleanupThreads...
     d                 pr                  extproc('xmlCleanupThreads')

     d xmlGetGlobalState...
     d                 pr                  extproc('xmlGetGlobalState')
     d                                     like(xmlGlobalStatePtr)

      /endif                                                                    XML_THREADS_H__
