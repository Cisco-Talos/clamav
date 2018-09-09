/**
***     Transcoding support and wrappers.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#define IN_LIBXML
#include "libxml.h"

#include <sys/types.h>
#include <iconv.h>
#include "libxml/xmlmemory.h"
#include "libxml/dict.h"
#include "transcode.h"


/**
***     Destroy a dictionary and mark as destroyed.
**/

void
xmlZapDict(xmlDictPtr * dict)

{
        if (dict && *dict) {
                xmlDictFree(*dict);
                *dict = (xmlDictPtr) NULL;
                }
}


/**
***     Support for inline conversion from/to UTF-8.
***     This is targetted to function parameter encoding conversion.
***     Method is:
***     -       Convert string from/to UTF-8.
***     -       Keep it in a dictionary.
***     -       Free original string if a release procedure is provided.
***     Can also be called without dictionary to convert a string from/to UTF-8
***             into xmlMalloc'ed dynamic storage.
**/

const char *
xmlTranscodeResult(const xmlChar * s, const char * encoding,
                        xmlDictPtr * dict, void (*freeproc)(const void *))

{
        size_t l;
        iconv_t cd;
        char * srcp;
        char * dstp;
        size_t srcc;
        size_t dstc;
        char * ts;
        const char * ret;
        int err;
        static const int nullstring[] = { 0 };

        /* Convert from UTF-8. */

        if (!s)
                return (const char *) NULL;

        ret = (const char *) NULL;
        ts = (char *) NULL;
        err = 0;
        l = xmlStrlen(s);

        if (!l && dict)
                ret = (const char *) nullstring;
        else {
                if (dict && !*dict)
                        err = !(*dict = xmlDictCreate());

                if (!err)
                        err = !(ts = xmlMalloc(4 * l + 4));

                dstp = ts;
                dstc = 4 * l;

                if (!err && l) {
                        if (!encoding)
                                encoding = "ibm-0";     /* Job's encoding. */

                        cd = iconv_open(encoding, "UTF-8");

                        if (cd == (iconv_t) -1)
                                err = 1;
                        else {
                                srcp = (char *) s;
                                srcc = l;
                                srcc = iconv(cd, &srcp, &srcc, &dstp, &dstc);
                                iconv_close(cd);
                                err = srcc == (size_t) -1;
                                }
                        }

                if (!err) {
                        dstp[0] = dstp[1] = dstp[2] = dstp[3] = '\0';

                        if (!dict) {
                                if (dstc)
                                        ts = xmlRealloc(ts, (dstp - ts) + 4);

                                ret = (const char *) ts;
                                ts = (char *) NULL;
                                }
                        else
                                ret = (char *) xmlDictLookup(*dict,
                                    (xmlChar *) ts, dstp - ts + 1);
                        }
                }

        if (ts)
                xmlFree(ts);

        if (freeproc)
                (*freeproc)(s);

        return ret;
}


/**
***     Support for inline conversion to UTF-8.
***     Method is:
***     -       Convert string to UTF-8.
***     -       Keep it in a dictionary.
***     Can also be called without dictionary to convert a string to UTF-8 into
***             xmlMalloc'ed dynamic storage.
**/

static const xmlChar *
inTranscode(const char * s, size_t l, const char * encoding, xmlDictPtr * dict)

{
        iconv_t cd;
        char * srcp;
        char * dstp;
        size_t srcc;
        size_t dstc;
        xmlChar * ts;
        const xmlChar * ret;
        static const xmlChar nullstring[] = { 0 };

        if (!l && dict)
                return nullstring;

        if (dict && !*dict)
                if (!(*dict = xmlDictCreate()))
                        return (const xmlChar *) NULL;

        ts = (xmlChar *) xmlMalloc(6 * l + 1);

        if (!ts)
                return (const xmlChar *) NULL;

        dstp = (char *) ts;
        dstc = 6 * l;

        if (l) {
                if (!encoding)
                        encoding = "ibm-0";     /* Use job's encoding. */

                cd = iconv_open("UTF-8", encoding);

                if (cd == (iconv_t) -1) {
                        xmlFree((char *) ts);
                        return (const xmlChar *) NULL;
                        }

                srcp = (char *) s;
                srcc = l;
                srcc = iconv(cd, &srcp, &srcc, &dstp, &dstc);
                iconv_close(cd);

                if (srcc == (size_t) -1) {
                        xmlFree((char *) ts);
                        return (const xmlChar *) NULL;
                        }
                }

        *dstp = '\0';

        if (!dict) {
                if (dstc)
                        ts = xmlRealloc(ts, (dstp - ts) + 1);

                return ts;
                }

        ret = xmlDictLookup(*dict, ts, dstp - ts + 1);
        xmlFree((char *) ts);
        return ret;
}


/**
***     Input 8-bit character string parameter.
**/

const xmlChar *
xmlTranscodeString(const char * s, const char * encoding, xmlDictPtr * dict)

{
        if (!s)
                return (const xmlChar *) NULL;

        return inTranscode(s, xmlStrlen(s), encoding, dict);
}


/**
***     Input 16-bit character string parameter.
**/

const xmlChar *
xmlTranscodeWString(const char * s, const char * encoding, xmlDictPtr * dict)

{
        size_t i;

        if (!s)
                return (const xmlChar *) NULL;

        for (i = 0; s[i] && s[i + 1]; i += 2)
                ;

        return inTranscode(s, i, encoding, dict);
}


/**
***     Input 32-bit character string parameter.
**/

const xmlChar *
xmlTranscodeHString(const char * s, const char * encoding, xmlDictPtr * dict)

{
        size_t i;

        if (!s)
                return (const xmlChar *) NULL;

        for (i = 0; s[i] && s[i + 1] && s[i + 2] && s[i + 3]; i += 4)
                ;

        return inTranscode(s, i, encoding, dict);
}


/**
***     vasprintf() implementation with result transcoding.
**/

const char *
xmlVasprintf(xmlDictPtr * dict, const char * encoding,
                                        const xmlChar * fmt, va_list args)

{
        char * s = NULL;

        vasprintf(&s, fmt, args);
        return xmlTranscodeResult((const xmlChar *) s, encoding, dict, free);
}
