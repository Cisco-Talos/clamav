/**
***     Additional delarations for ILE/RPG support.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#ifndef __RPGSUPPORT_H__
#define __RPGSUPPORT_H__

#include <sys/types.h>

#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include "libxml/HTMLparser.h"


XMLPUBFUN xmlFreeFunc   __get_xmlFree(void);
XMLPUBFUN void          __set_xmlFree(xmlFreeFunc freefunc);
XMLPUBFUN void          __call_xmlFree(void * mem);
XMLPUBFUN xmlMallocFunc __get_xmlMalloc(void);
XMLPUBFUN void          __set_xmlMalloc(xmlMallocFunc allocfunc);
XMLPUBFUN void *        __call_xmlMalloc(size_t size);
XMLPUBFUN xmlMallocFunc __get_xmlMallocAtomic(void);
XMLPUBFUN void          __set_xmlMallocAtomic(xmlMallocFunc allocfunc);
XMLPUBFUN void *        __call_xmlMallocAtomic(size_t size);
XMLPUBFUN xmlReallocFunc __get_xmlRealloc(void);
XMLPUBFUN void          __set_xmlRealloc(xmlReallocFunc reallocfunc);
XMLPUBFUN void *        __call_xmlRealloc(void * mem, size_t size);
XMLPUBFUN xmlStrdupFunc __get_xmlMemStrdup(void);
XMLPUBFUN void          __set_xmlMemStrdup(xmlStrdupFunc strdupfunc);
XMLPUBFUN char *        __call_xmlMemStrdup(const char * str);

#ifdef LIBXML_DOCB_ENABLED
XMLPUBFUN xmlSAXHandlerV1 __get_docbDefaultSAXHandler(void);
XMLPUBFUN void          __set_docbDefaultSAXHandler(xmlSAXHandlerV1 hdlr);
#endif

#ifdef LIBXML_HTML_ENABLED
XMLPUBFUN xmlSAXHandlerV1 __get_htmlDefaultSAXHandler(void);
XMLPUBFUN void          __set_htmlDefaultSAXHandler(xmlSAXHandlerV1 hdlr);
#endif

XMLPUBFUN xmlError      __get_xmlLastError(void);
XMLPUBFUN void          __set_xmlLastError(xmlError err);

XMLPUBFUN int           __get_oldXMLWDcompatibility(void);
XMLPUBFUN void          __set_oldXMLWDcompatibility(int val);

XMLPUBFUN xmlBufferAllocationScheme __get_xmlBufferAllocScheme(void);
XMLPUBFUN void          __set_xmlBufferAllocScheme(xmlBufferAllocationScheme val);

XMLPUBFUN int           __get_xmlDefaultBufferSize(void);
XMLPUBFUN void          __set_xmlDefaultBufferSize(int val);

XMLPUBFUN xmlSAXHandlerV1 __get_xmlDefaultSAXHandler(void);
XMLPUBFUN void          __set_xmlDefaultSAXHandler(xmlSAXHandlerV1 val);

XMLPUBFUN xmlSAXLocator __get_xmlDefaultSAXLocator(void);
XMLPUBFUN void          __set_xmlDefaultSAXLocator(xmlSAXLocator val);

XMLPUBFUN int           __get_xmlDoValidityCheckingDefaultValue(void);
XMLPUBFUN void          __set_xmlDoValidityCheckingDefaultValue(int val);

XMLPUBFUN xmlGenericErrorFunc __get_xmlGenericError(void);
XMLPUBFUN void          __set_xmlGenericError(xmlGenericErrorFunc val);

XMLPUBFUN xmlStructuredErrorFunc __get_xmlStructuredError(void);
XMLPUBFUN void          __set_xmlStructuredError(xmlStructuredErrorFunc val);
XMLPUBFUN void          __call_xmlStructuredError(void *userData, xmlErrorPtr error);

XMLPUBFUN void *        __get_xmlGenericErrorContext(void);
XMLPUBFUN void          __set_xmlGenericErrorContext(void * val);

XMLPUBFUN void *        __get_xmlStructuredErrorContext(void);
XMLPUBFUN void          __set_xmlStructuredErrorContext(void * val);

XMLPUBFUN int           __get_xmlGetWarningsDefaultValue(void);
XMLPUBFUN void          __set_xmlGetWarningsDefaultValue(int val);

XMLPUBFUN int           __get_xmlIndentTreeOutput(void);
XMLPUBFUN void          __set_xmlIndentTreeOutput(int val);

XMLPUBFUN const char *  __get_xmlTreeIndentString(void);
XMLPUBFUN void          __set_xmlTreeIndentString(const char * val);

XMLPUBFUN int           __get_xmlKeepBlanksDefaultValue(void);
XMLPUBFUN void          __set_xmlKeepBlanksDefaultValue(int val);

XMLPUBFUN int           __get_xmlLineNumbersDefaultValue(void);
XMLPUBFUN void          __set_xmlLineNumbersDefaultValue(int val);

XMLPUBFUN int           __get_xmlLoadExtDtdDefaultValue(void);
XMLPUBFUN void          __set_xmlLoadExtDtdDefaultValue(int val);

XMLPUBFUN int           __get_xmlParserDebugEntities(void);
XMLPUBFUN void          __set_xmlParserDebugEntities(int val);

XMLPUBFUN const char *  __get_xmlParserVersion(void);
XMLPUBFUN void          __set_xmlParserVersion(const char * val);

XMLPUBFUN int           __get_xmlPedanticParserDefaultValue(void);
XMLPUBFUN void          __set_xmlPedanticParserDefaultValue(int val);

XMLPUBFUN int           __get_xmlSaveNoEmptyTags(void);
XMLPUBFUN void          __set_xmlSaveNoEmptyTags(int val);

XMLPUBFUN int           __get_xmlSubstituteEntitiesDefaultValue(void);
XMLPUBFUN void          __set_xmlSubstituteEntitiesDefaultValue(int val);

XMLPUBFUN xmlRegisterNodeFunc __get_xmlRegisterNodeDefaultValue(void);
XMLPUBFUN void          __set_xmlRegisterNodeDefaultValue(xmlRegisterNodeFunc val);
XMLPUBFUN void          __call_xmlRegisterNodeDefaultValue(xmlNodePtr node);

XMLPUBFUN xmlDeregisterNodeFunc __get_xmlDeregisterNodeDefaultValue(void);
XMLPUBFUN void          __set_xmlDeregisterNodeDefaultValue(xmlDeregisterNodeFunc val);
XMLPUBFUN void          __call_xmlDeregisterNodeDefaultValue(xmlNodePtr node);

XMLPUBFUN xmlParserInputBufferCreateFilenameFunc
                        __get_xmlParserInputBufferCreateFilenameValue(void);
XMLPUBFUN void          __set_xmlParserInputBufferCreateFilenameValue(
                                xmlParserInputBufferCreateFilenameFunc val);
XMLPUBFUN xmlParserInputBufferPtr
                __call_xmlParserInputBufferCreateFilenameValue(const char *URI,
                                                        xmlCharEncoding enc);

XMLPUBFUN xmlOutputBufferCreateFilenameFunc
                        __get_xmlOutputBufferCreateFilenameValue(void);
XMLPUBFUN void          __set_xmlOutputBufferCreateFilenameValue(
                                xmlOutputBufferCreateFilenameFunc val);
XMLPUBFUN xmlOutputBufferPtr
                        __call_xmlOutputBufferCreateFilenameValue(const char *URI,
                                xmlCharEncodingHandlerPtr encoder,
                                int compression);


XMLPUBFUN void          __xmlVaStart(char * * list,
                                char * lastargaddr, size_t lastargsize);
XMLPUBFUN void *        __xmlVaArg(char * * list, void * dest, size_t argsize);
XMLPUBFUN void          __xmlVaEnd(char * * list);

#ifdef LIBXML_XPATH_ENABLED
XMLPUBFUN int           __xmlXPathNodeSetGetLength(xmlNodeSetPtr ns);
XMLPUBFUN xmlNodePtr    __xmlXPathNodeSetItem(xmlNodeSetPtr ns, int index);
XMLPUBFUN int           __xmlXPathNodeSetIsEmpty(xmlNodeSetPtr ns);
#endif

#ifdef LIBXML_HTML_ENABLED
XMLPUBFUN const char *  __htmlDefaultSubelement(const htmlElemDesc * elt);
XMLPUBFUN int   __htmlElementAllowedHereDesc(const htmlElemDesc * parent,
                        const htmlElemDesc * elt);
XMLPUBFUN const char * *
                        __htmlRequiredAttrs(const htmlElemDesc * elt);
#endif

#endif
