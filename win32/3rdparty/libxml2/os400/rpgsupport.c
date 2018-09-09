/**
***     Additional procedures for ILE/RPG support.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#include <sys/types.h>

#include <stdarg.h>

#include "libxml/xmlmemory.h"
#include "libxml/xpath.h"
#include "libxml/parser.h"
#include "libxml/HTMLparser.h"

#include "rpgsupport.h"


/**
***     ILE/RPG cannot directly derefence a pointer and has no macros.
***     The following additional procedures supply these functions.
***     In addition, the following code is adjusted for threads control at
***             compile time via the C macros.
**/

#define THREADED_VAR(name, type)                                        \
                type __get_##name(void) { return name; }                \
                void __set_##name(type arg) { name = arg; }


THREADED_VAR(xmlFree, xmlFreeFunc)

void
__call_xmlFree(void * mem)

{
        xmlFree(mem);
}


THREADED_VAR(xmlMalloc, xmlMallocFunc)

void *
__call_xmlMalloc(size_t size)

{
        return xmlMalloc(size);
}


THREADED_VAR(xmlMallocAtomic, xmlMallocFunc)

void *
__call_xmlMallocAtomic(size_t size)

{
        return xmlMallocAtomic(size);
}


THREADED_VAR(xmlRealloc, xmlReallocFunc)

void *
__call_xmlRealloc(void * mem, size_t size)

{
        return xmlRealloc(mem, size);
}


THREADED_VAR(xmlMemStrdup, xmlStrdupFunc)

char *
__call_xmlMemStrdup(const char * str)

{
        return xmlMemStrdup(str);
}


#ifdef LIBXML_DOCB_ENABLED
THREADED_VAR(docbDefaultSAXHandler, xmlSAXHandlerV1)
#endif


#ifdef LIBXML_HTML_ENABLED
THREADED_VAR(htmlDefaultSAXHandler, xmlSAXHandlerV1)
#endif


THREADED_VAR(xmlLastError, xmlError)

THREADED_VAR(oldXMLWDcompatibility, int)
THREADED_VAR(xmlBufferAllocScheme, xmlBufferAllocationScheme)
THREADED_VAR(xmlDefaultBufferSize, int)
THREADED_VAR(xmlDefaultSAXHandler, xmlSAXHandlerV1)
THREADED_VAR(xmlDefaultSAXLocator, xmlSAXLocator)
THREADED_VAR(xmlDoValidityCheckingDefaultValue, int)

/* No caller to xmlGenericError() because the argument list is unknown. */
THREADED_VAR(xmlGenericError, xmlGenericErrorFunc)


THREADED_VAR(xmlStructuredError, xmlStructuredErrorFunc)

void
__call_xmlStructuredError(void * userData, xmlErrorPtr error)

{
        xmlStructuredError(userData, error);
}

THREADED_VAR(xmlGenericErrorContext, void *)
THREADED_VAR(xmlStructuredErrorContext, void *)
THREADED_VAR(xmlGetWarningsDefaultValue, int)
THREADED_VAR(xmlIndentTreeOutput, int)
THREADED_VAR(xmlTreeIndentString, const char *)
THREADED_VAR(xmlKeepBlanksDefaultValue, int)
THREADED_VAR(xmlLineNumbersDefaultValue, int)
THREADED_VAR(xmlLoadExtDtdDefaultValue, int)
THREADED_VAR(xmlParserDebugEntities, int)
THREADED_VAR(xmlParserVersion, const char *)
THREADED_VAR(xmlPedanticParserDefaultValue, int)
THREADED_VAR(xmlSaveNoEmptyTags, int)
THREADED_VAR(xmlSubstituteEntitiesDefaultValue, int)


THREADED_VAR(xmlRegisterNodeDefaultValue, xmlRegisterNodeFunc)

void
__call_xmlRegisterNodeDefaultValue(xmlNodePtr node)

{
        xmlRegisterNodeDefaultValue(node);
}


THREADED_VAR(xmlDeregisterNodeDefaultValue, xmlDeregisterNodeFunc)

void
__call_xmlDeregisterNodeDefaultValue(xmlNodePtr node)

{
        xmlDeregisterNodeDefaultValue(node);
}


THREADED_VAR(xmlParserInputBufferCreateFilenameValue, xmlParserInputBufferCreateFilenameFunc)

xmlParserInputBufferPtr
__call_xmlParserInputBufferCreateFilenameValue(const char *URI,
                                                        xmlCharEncoding enc)

{
        return xmlParserInputBufferCreateFilenameValue(URI, enc);
}


THREADED_VAR(xmlOutputBufferCreateFilenameValue, xmlOutputBufferCreateFilenameFunc)

xmlOutputBufferPtr
__call_xmlOutputBufferCreateFilenameValue(const char *URI,
                        xmlCharEncodingHandlerPtr encoder, int compression)

{
        return xmlOutputBufferCreateFilenameValue(URI, encoder, compression);
}



/**
***     va_list support.
**/

void
__xmlVaStart(char * * list, char * lastargaddr, size_t lastargsize)

{
        list[1] = lastargaddr + lastargsize;
}


void *
__xmlVaArg(char * * list, void * dest, size_t argsize)

{
        size_t align;

        if (!argsize)
                return (void *) NULL;

        for (align = 16; align > argsize; align >>= 1)
                ;

        align--;
        list[0] = list[1] + (align - (((size_t) list[0] - 1) & align));
        list[1] = list[0] + argsize;

        if (dest)
                memcpy(dest, list[0], argsize);

        return (void *) list[0];
}


void
__xmlVaEnd(char * * list)

{
        /* Nothing to do. */
}


#ifdef LIBXML_XPATH_ENABLED

int
__xmlXPathNodeSetGetLength(const xmlNodeSet * ns)

{
        return xmlXPathNodeSetGetLength(ns);
}


xmlNodePtr
__xmlXPathNodeSetItem(const xmlNodeSet * ns, int index)

{
        return xmlXPathNodeSetItem(ns, index);
}


int
__xmlXPathNodeSetIsEmpty(const xmlNodeSet * ns)

{
        return xmlXPathNodeSetIsEmpty(ns);
}

#endif


#ifdef LIBXML_HTML_ENABLED

const char *
__htmlDefaultSubelement(const htmlElemDesc * elt)

{
        return htmlDefaultSubelement(elt);
}


int
__htmlElementAllowedHereDesc(const htmlElemDesc * parent,
                                                const htmlElemDesc * elt)

{
        return htmlElementAllowedHereDesc(parent, elt);
}


const char * *
__htmlRequiredAttrs(const htmlElemDesc * elt)

{
        return htmlRequiredAttrs(elt);
}

#endif
