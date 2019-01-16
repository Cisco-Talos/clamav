      * Summary: interface for the encoding conversion functions
      * Description: interface for the encoding conversion functions needed for
      *              XML basic encoding and iconv() support.
      *
      * Related specs are
      * rfc2044        (UTF-8 and UTF-16) F. Yergeau Alis Technologies
      * [ISO-10646]    UTF-8 and UTF-16 in Annexes
      * [ISO-8859-1]   ISO Latin-1 characters codes.
      * [UNICODE]      The Unicode Consortium, "The Unicode Standard --
      *                Worldwide Character Encoding -- Version 1.0", Addison-
      *                Wesley, Volume 1, 1991, Volume 2, 1992.  UTF-8 is
      *                described in Unicode Technical Report #4.
      * [US-ASCII]     Coded Character Set--7-bit American Standard Code for
      *                Information Interchange, ANSI X3.4-1986.
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_CHAR_ENCODING_H__)
      /define XML_CHAR_ENCODING_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"

      * xmlCharEncoding:
      *
      * Predefined values for some standard encodings.
      * Libxml does not do beforehand translation on UTF8 and ISOLatinX.
      * It also supports ASCII, ISO-8859-1, and UTF16 (LE and BE) by default.
      *
      * Anything else would have to be translated to UTF8 before being
      * given to the parser itself. The BOM for UTF16 and the encoding
      * declaration are looked at and a converter is looked for at that
      * point. If not found the parser stops here as asked by the XML REC. A
      * converter can be registered by the user
      * xmlRegisterCharEncodingHandler but the current form doesn't allow
      * stateful transcoding (a serious problem agreed !). If iconv has been
      * found it will be used automatically and allow stateful transcoding,
      * the simplest is then to be sure to enable iconv and to provide iconv
      * libs for the encoding support needed.
      *
      * Note that the generic "UTF-16" is not a predefined value.  Instead, only
      * the specific UTF-16LE and UTF-16BE are present.

     d xmlCharEncoding...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_CHAR_ENCODING_ERROR...                                              No encoding detected
     d                 c                   -1
     d  XML_CHAR_ENCODING_NONE...                                               No encoding detected
     d                 c                   0
     d  XML_CHAR_ENCODING_UTF8...                                               UTF-8
     d                 c                   1
     d  XML_CHAR_ENCODING_UTF16LE...                                            UTF-16 little endian
     d                 c                   2
     d  XML_CHAR_ENCODING_UTF16BE...                                            UTF-16 big endian
     d                 c                   3
     d  XML_CHAR_ENCODING_UCS4LE...                                             UCS-4 little endian
     d                 c                   4
     d  XML_CHAR_ENCODING_UCS4BE...                                             UCS-4 big endian
     d                 c                   5
     d  XML_CHAR_ENCODING_EBCDIC...                                             EBCDIC uh!
     d                 c                   6
     d  XML_CHAR_ENCODING_UCS4_2143...                                          UCS-4 unusual order
     d                 c                   7
     d  XML_CHAR_ENCODING_UCS4_3412...                                          UCS-4 unusual order
     d                 c                   8
     d  XML_CHAR_ENCODING_UCS2...                                               UCS-2
     d                 c                   9
     d  XML_CHAR_ENCODING_8859_1...                                             ISO-8859-1 ISOLatin1
     d                 c                   10
     d  XML_CHAR_ENCODING_8859_2...                                             ISO-8859-2 ISOLatin2
     d                 c                   11
     d  XML_CHAR_ENCODING_8859_3...                                             ISO-8859-3
     d                 c                   12
     d  XML_CHAR_ENCODING_8859_4...                                             ISO-8859-4
     d                 c                   13
     d  XML_CHAR_ENCODING_8859_5...                                             ISO-8859-5
     d                 c                   14
     d  XML_CHAR_ENCODING_8859_6...                                             ISO-8859-6
     d                 c                   15
     d  XML_CHAR_ENCODING_8859_7...                                             ISO-8859-7
     d                 c                   16
     d  XML_CHAR_ENCODING_8859_8...                                             ISO-8859-8
     d                 c                   17
     d  XML_CHAR_ENCODING_8859_9...                                             ISO-8859-9
     d                 c                   18
     d  XML_CHAR_ENCODING_2022_JP...                                            ISO-2022-JP
     d                 c                   19
     d  XML_CHAR_ENCODING_SHIFT_JIS...                                          Shift_JIS
     d                 c                   20
     d  XML_CHAR_ENCODING_EUC_JP...                                             EUC-JP
     d                 c                   21
     d  XML_CHAR_ENCODING_ASCII...                                              Pure ASCII
     d                 c                   22

      * xmlCharEncodingInputFunc:
      * @out:  a pointer to an array of bytes to store the UTF-8 result
      * @outlen:  the length of @out
      * @in:  a pointer to an array of chars in the original encoding
      * @inlen:  the length of @in
      *
      * Take a block of chars in the original encoding and try to convert
      * it to an UTF-8 block of chars out.
      *
      * Returns the number of bytes written, -1 if lack of space, or -2
      *     if the transcoding failed.
      * The value of @inlen after return is the number of octets consumed
      *     if the return value is positive, else unpredictiable.
      * The value of @outlen after return is the number of octets consumed.

     d xmlCharEncodingInputFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlCharEncodingOutputFunc:
      * @out:  a pointer to an array of bytes to store the result
      * @outlen:  the length of @out
      * @in:  a pointer to an array of UTF-8 chars
      * @inlen:  the length of @in
      *
      * Take a block of UTF-8 chars in and try to convert it to another
      * encoding.
      * Note: a first call designed to produce heading info is called with
      * in = NULL. If stateful this should also initialize the encoder state.
      *
      * Returns the number of bytes written, -1 if lack of space, or -2
      *     if the transcoding failed.
      * The value of @inlen after return is the number of octets consumed
      *     if the return value is positive, else unpredictiable.
      * The value of @outlen after return is the number of octets produced.

     d xmlCharEncodingOutputFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * Block defining the handlers for non UTF-8 encodings.
      * If iconv is supported, there are two extra fields.

      /if defined(LIBXML_ICU_ENABLED)
     d uconv_t         ds                  based(######typedef######)
     d                                     align qualified
     d  uconv                          *                                        UConverter *
     d  utf8                           *                                        UConverter *
      /endif

     d xmlCharEncodingHandlerPtr...
     d                 s               *   based(######typedef######)

     d xmlCharEncodingHandler...
     d                 ds                  based(xmlCharEncodingHandlerPtr)
     d                                     align qualified
     d  name                           *                                        char *
     d  input                              like(xmlCharEncodingInputFunc)
     d  output                             like(xmlCharEncodingOutputFunc)
      *
      /if defined(LIBXML_ICONV_ENABLED)
     d  iconv_in                       *                                        iconv_t
     d  iconv_out                      *                                        iconv_t
      /endif                                                                    LIBXML_ICONV_ENABLED
      *
      /if defined(LIBXML_ICU_ENABLED)
     d  uconv_in                       *                                        uconv_t *
     d  uconv_out                      *                                        uconv_t *
      /endif                                                                    LIBXML_ICU_ENABLED

      /include "libxmlrpg/tree"

      * Interfaces for encoding handlers.

     d xmlInitCharEncodingHandlers...
     d                 pr                  extproc(
     d                                      'xmlInitCharEncodingHandlers')

     d xmlCleanupCharEncodingHandlers...
     d                 pr                  extproc(
     d                                      'xmlCleanupCharEncodingHandlers')

     d xmlRegisterCharEncodingHandler...
     d                 pr                  extproc(
     d                                      'xmlRegisterCharEncodingHandler')
     d  handler                            value like(xmlCharEncodingHandlerPtr)

     d xmlGetCharEncodingHandler...
     d                 pr                  extproc('xmlGetCharEncodingHandler')
     d                                     like(xmlCharEncodingHandlerPtr)
     d  enc                                value like(xmlCharEncoding)

     d xmlFindCharEncodingHandler...
     d                 pr                  extproc('xmlFindCharEncodingHandler')
     d                                     like(xmlCharEncodingHandlerPtr)
     d  name                           *   value options(*string)               const char *

     d xmlNewCharEncodingHandler...
     d                 pr                  extproc('xmlNewCharEncodingHandler')
     d                                     like(xmlCharEncodingHandlerPtr)
     d  name                           *   value options(*string)               const char *
     d  input                              value like(xmlCharEncodingInputFunc)
     d  output                             value like(xmlCharEncodingOutputFunc)

      * Interfaces for encoding names and aliases.

     d xmlAddEncodingAlias...
     d                 pr                  extproc('xmlAddEncodingAlias')
     d                                     like(xmlCint)
     d  name                           *   value options(*string)               const char *
     d  alias                          *   value options(*string)               const char *

     d xmlDelEncodingAlias...
     d                 pr                  extproc('xmlDelEncodingAlias')
     d                                     like(xmlCint)
     d  alias                          *   value options(*string)               const char *

     d xmlGetEncodingAlias...
     d                 pr              *   extproc('xmlGetEncodingAlias')       const char *
     d  alias                          *   value options(*string)               const char *

     d xmlCleanupEncodingAliases...
     d                 pr                  extproc('xmlCleanupEncodingAliases')

     d xmlParseCharEncoding...
     d                 pr                  extproc('xmlParseCharEncoding')
     d                                     like(xmlCharEncoding)
     d  name                           *   value options(*string)               const char *

     d xmlGetCharEncodingName...
     d                 pr              *   extproc('xmlGetCharEncodingName')    const char *
     d  enc                                value like(xmlCharEncoding)

      * Interfaces directly used by the parsers.

     d xmlDetectCharEncoding...
     d                 pr                  extproc('xmlDetectCharEncoding')
     d                                     like(xmlCharEncoding)
     d  in                             *   value options(*string)               const unsigned char*
     d  len                                value like(xmlCint)

     d xmlCharEncOutFunc...
     d                 pr                  extproc('xmlCharEncOutFunc')
     d                                     like(xmlCint)
     d  handler                            likeds(xmlCharEncodingHandler)
     d  out                                value like(xmlBufferPtr)
     d  in                                 value like(xmlBufferPtr)

     d xmlCharEncInFunc...
     d                 pr                  extproc('xmlCharEncInFunc')
     d                                     like(xmlCint)
     d  handler                            likeds(xmlCharEncodingHandler)
     d  out                                value like(xmlBufferPtr)
     d  in                                 value like(xmlBufferPtr)

     d xmlCharEncFirstLine...
     d                 pr                  extproc('xmlCharEncFirstLine')
     d                                     like(xmlCint)
     d  handler                            likeds(xmlCharEncodingHandler)
     d  out                                value like(xmlBufferPtr)
     d  in                                 value like(xmlBufferPtr)

     d xmlCharEncCloseFunc...
     d                 pr                  extproc('xmlCharEncCloseFunc')
     d                                     like(xmlCint)
     d  handler                            likeds(xmlCharEncodingHandler)

      * Export a few useful functions

      /if defined(LIBXML_OUTPUT_ENABLED)
     d UTF8Toisolat1   pr                  extproc('UTF8Toisolat1')
     d                                     like(xmlCint)
     d  out                       65535    options(*varsize)                    unsigned char (*)
     d  outlen                             like(xmlCint)
     d  in                             *   value options(*string)               const unsigned char*
     d  inlen                              like(xmlCint)

      /endif                                                                    LIBXML_OUTPUT_ENABLD

     d isolat1ToUTF8   pr                  extproc('isolat1ToUTF8')
     d                                     like(xmlCint)
     d  out                       65535    options(*varsize)                    unsigned char (*)
     d  outlen                             like(xmlCint)
     d  in                             *   value options(*string)               const unsigned char*
     d  inlen                              like(xmlCint)

      /endif                                                                    XML_CHAR_ENCODING_H
