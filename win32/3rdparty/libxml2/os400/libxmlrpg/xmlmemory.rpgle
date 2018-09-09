      * Summary: interface for the memory allocator
      * Description: provides interfaces for the memory allocator,
      *              including debugging capabilities.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(DEBUG_MEMORY_ALLOC__)
      /define DEBUG_MEMORY_ALLOC__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"

      * DEBUG_MEMORY:
      *
      * DEBUG_MEMORY replaces the allocator with a collect and debug
      * shell to the libc allocator.
      * DEBUG_MEMORY should only be activated when debugging
      * libxml i.e. if libxml has been configured with --with-debug-mem too.

      * /define DEBUG_MEMORY_FREED
      * /define DEBUG_MEMORY_LOCATION

      /if defined(DEBUG)
      /if not defined(DEBUG_MEMORY)
      /define DEBUG_MEMORY
      /endif
      /endif

      * DEBUG_MEMORY_LOCATION:
      *
      * DEBUG_MEMORY_LOCATION should be activated only when debugging
      * libxml i.e. if libxml has been configured with --with-debug-mem too.

      /if defined(DEBUG_MEMORY_LOCATION)
      /endif

      * The XML memory wrapper support 4 basic overloadable functions.

      * xmlFreeFunc:
      * @mem: an already allocated block of memory
      *
      * Signature for a free() implementation.

     d xmlFreeFunc     s               *   based(######typedef######)
     d                                     procptr

      * xmlMallocFunc:
      * @size:  the size requested in bytes
      *
      * Signature for a malloc() implementation.
      *
      * Returns a pointer to the newly allocated block or NULL in case of error.

     d xmlMallocFunc   s               *   based(######typedef######)
     d                                     procptr

      * xmlReallocFunc:
      * @mem: an already allocated block of memory
      * @size:  the new size requested in bytes
      *
      * Signature for a realloc() implementation.
      *
      * Returns a pointer to the newly reallocated block or NULL in case of error.

     d xmlReallocFunc  s               *   based(######typedef######)
     d                                     procptr

      * xmlStrdupFunc:
      * @str: a zero terminated string
      *
      * Signature for an strdup() implementation.
      *
      * Returns the copy of the string or NULL in case of error.

     d xmlStrdupFunc   s               *   based(######typedef######)
     d                                     procptr

      * The 5 interfaces used for all memory handling within libxml.
      * Since indirect calls are only supported via a based prototype,
      *   storage is accessed via functions.

     d get_xmlFree     pr                  extproc('__get_xmlFree')
     d                                     like(xmlFreeFunc)

     d set_xmlFree     pr                  extproc('__set_xmlFree')
     d  func                               value like(xmlFreeFunc)

     d xmlFree         pr                  extproc('__call_xmlFree')
     d  mem                            *   value                                void *

     d get_xmlMalloc   pr                  extproc('__get_xmlMalloc')
     d                                     like(xmlMallocFunc)

     d set_xmlMalloc   pr                  extproc('__set_xmlMalloc')
     d  func                               value like(xmlMallocFunc)

     d xmlMalloc       pr              *   extproc('__call_xmlMalloc')          void *
     d  size                               value like(xmlCsize_t)

     d get_xmlMallocAtomic...
     d                 pr                  extproc('__get_xmlMallocAtomic')
     d                                     like(xmlMallocFunc)

     d set_xmlMallocAtomic...
     d                 pr                  extproc('__set_xmlMallocAtomic')
     d  func                               value like(xmlMallocFunc)

     d xmlMallocAtomic...
     d                 pr              *   extproc('__call_xmlMallocAtomic')    void *
     d  size                               value like(xmlCsize_t)

     d get_xmlRealloc  pr                  extproc('__get_xmlRealloc')
     d                                     like(xmlReallocFunc)

     d set_xmlRealloc  pr                  extproc('__set_xmlRealloc')
     d  func                               value like(xmlReallocFunc)

     d xmlRealloc      pr              *   extproc('__call_xmlRealloc')         void *
     d  mem                            *   value                                void *
     d  size                               value like(xmlCsize_t)

     d get_xmlMemStrdup...
     d                 pr                  extproc('__get_xmlMemStrdup')
     d                                     like(xmlStrdupFunc)

     d set_xmlMemStrdup...
     d                 pr                  extproc('__set_xmlMemstrdup')
     d  func                               value like(xmlStrdupFunc)

     d xmlMemStrdup    pr              *   extproc('__call_xmlMemStrdup')          void *
     d  str                            *   value options(*string)               const char *

      * The way to overload the existing functions.
      * The xmlGc function have an extra entry for atomic block
      * allocations useful for garbage collected memory allocators

     d xmlMemSetup     pr                  extproc('xmlMemSetup')
     d                                     like(xmlCint)
     d  freeFunc                           value like(xmlFreeFunc)
     d  mallocFunc                         value like(xmlMallocFunc)
     d  reallocFunc                        value like(xmlReallocFunc)
     d  strdupFunc                         value like(xmlStrdupFunc)

     d xmlMemGet       pr                  extproc('xmlMemGet')
     d                                     like(xmlCint)
     d  freeFunc                           like(xmlFreeFunc)
     d  mallocFunc                         like(xmlMallocFunc)
     d  reallocFunc                        like(xmlReallocFunc)
     d  strdupFunc                         like(xmlStrdupFunc)

     d xmlGcMemSetup   pr                  extproc('xmlGcMemSetup')
     d                                     like(xmlCint)
     d  freeFunc                           value like(xmlFreeFunc)
     d  mallocFunc                         value like(xmlMallocFunc)
     d  mallocAtomicFunc...
     d                                     value like(xmlMallocFunc)
     d  reallocFunc                        value like(xmlReallocFunc)
     d  strdupFunc                         value like(xmlStrdupFunc)

     d xmlGcMemGet     pr                  extproc('xmlGcMemGet')
     d                                     like(xmlCint)
     d  freeFunc                           like(xmlFreeFunc)
     d  mallocFunc                         like(xmlMallocFunc)
     d  mallocAtomicFunc...
     d                                     like(xmlMallocFunc)
     d  reallocFunc                        like(xmlReallocFunc)
     d  strdupFunc                         like(xmlStrdupFunc)

      * Initialization of the memory layer.

     d xmlInitMemory   pr                  extproc('xmlInitMemory')
     d                                     like(xmlCint)

      * Cleanup of the memory layer.

     d xmlCleanupMemory...
     d                 pr                  extproc('xmlCleanupMemory')

      * These are specific to the XML debug memory wrapper.

     d xmlMemUsed      pr                  extproc('xmlMemUsed')
     d                                     like(xmlCint)

     d xmlMemBlocks    pr                  extproc('xmlMemBlocks')
     d                                     like(xmlCint)

     d xmlMemDisplay   pr                  extproc('xmlMemDisplay')
     d  fp                             *   value                                FILE *

     d xmlMmDisplayLast...
     d                 pr                  extproc('xmlMemDisplayLast')
     d  fp                             *   value                                FILE *
     d  nbBytes                            value like(xmlClong)

     d xmlMemShow      pr                  extproc('xmlMemShow')
     d  fp                             *   value                                FILE *
     d  nr                                 value like(xmlCint)

     d xmlMemoryDump   pr                  extproc('xmlMemoryDump')

     d xmlMemMalloc    pr              *   extproc('xmlMemMalloc')              void *
     d  size                               value like(xmlCsize_t)

     d xmlMemRealloc   pr              *   extproc('xmlMemRealloc')             void *
     d  ptr                            *   value                                void *
     d  size                               value like(xmlCsize_t)

     d xmlMemFree      pr                  extproc('xmlMemFree')
     d  ptr                            *   value                                void *

     d xmlMemoryStrdup...
     d                 pr              *   extproc('xmlMemoryStrdup')           char *
     d  str                            *   value options(*string)               const char *

     d xmlMallocLoc    pr              *   extproc('xmlMallocLoc')              void *
     d  size                               value like(xmlCsize_t)
     d  file                           *   value options(*string)               const char *
     d  line                               value like(xmlCint)

     d xmlReallocLoc   pr              *   extproc('xmlReallocLoc')              void *
     d  ptr                            *   value                                void *
     d  size                               value like(xmlCsize_t)
     d  file                           *   value options(*string)               const char *
     d  line                               value like(xmlCint)

     d xmlMallocAtomicLoc...
     d                 pr              *   extproc('xmlMallocAtomicLoc')        void *
     d  size                               value like(xmlCsize_t)
     d  file                           *   value options(*string)               const char *
     d  line                               value like(xmlCint)

     d xmlMemStrdupLoc...
     d                 pr              *   extproc('xmlMemStrdupLoc')           char *
     d  str                            *   value options(*string)               const char *
     d  file                           *   value options(*string)               const char *
     d  line                               value like(xmlCint)

      /if not defined(XML_GLOBALS_H)
      /if not defined(XML_THREADS_H__)
      /include "libxmlrpg/threads"
      /include "libxmlrpg/globals"
      /endif
      /endif

      /endif                                                                    DEBUG_MEMORY_ALLOC__
