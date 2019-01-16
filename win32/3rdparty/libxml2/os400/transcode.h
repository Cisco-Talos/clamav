/**
***     Transcoding support declarations.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#ifndef _TRANSCODE_H_
#define _TRANSCODE_H_

#include <stdarg.h>
#include <libxml/dict.h>


XMLPUBFUN void          xmlZapDict(xmlDictPtr * dict);
XMLPUBFUN const char *  xmlTranscodeResult(const xmlChar * s,
        const char * encoding, xmlDictPtr * dict,
        void (*freeproc)(const void *));
XMLPUBFUN const xmlChar * xmlTranscodeString(const char * s,
        const char * encoding, xmlDictPtr * dict);
XMLPUBFUN const xmlChar * xmlTranscodeWString(const char * s,
        const char * encoding, xmlDictPtr * dict);
XMLPUBFUN const xmlChar * xmlTranscodeHString(const char * s,
        const char * encoding, xmlDictPtr * dict);

#ifndef XML_NO_SHORT_NAMES
/**
***     Since the above functions are generally called "inline" (i.e.: several
***             times nested in a single expression), define shorthand names
***             to minimize calling statement length.
**/

#define xmlTR   xmlTranscodeResult
#define xmlTS   xmlTranscodeString
#define xmlTW   xmlTranscodeWString
#define xmlTH   xmlTranscodeHstring
#endif

XMLPUBFUN const char *  xmlVasprintf(xmlDictPtr * dict, const char * encoding,
        const xmlChar * fmt, va_list args);

#endif
