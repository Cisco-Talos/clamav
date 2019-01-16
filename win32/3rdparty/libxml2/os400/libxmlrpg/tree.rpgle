      * Summary: interfaces for tree manipulation
      * Description: this module describes the structures found in an tree
      *              resulting from an XML or HTML parsing, as well as the API
      *              provided for various processing on that tree
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_TREE_H__)
      /define XML_TREE_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/xmlstring"


      * Some of the basic types pointer to structures:

      * xmlIO.h

     d xmlParserInputBufferPtr...
     d                 s               *   based(######typedef######)

     d xmlOutputBufferPtr...
     d                 s               *   based(######typedef######)

      * parser.h

     d xmlParserInputPtr...
     d                 s               *   based(######typedef######)

     d xmlParserCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlSAXLocatorPtr...
     d                 s               *   based(######typedef######)

     d xmlSAXHandlerPtr...
     d                 s               *   based(######typedef######)

      * entities.h

     d xmlEntityPtr    s               *   based(######typedef######)


      * BASE_BUFFER_SIZE:
      *
      * default buffer size 4000.

     d BASE_BUFFER_SIZE...
     d                 c                   4096

      * LIBXML_NAMESPACE_DICT:
      *
      * Defines experimental behaviour:
      * 1) xmlNs gets an additional field @context (a xmlDoc)
      * 2) when creating a tree, xmlNs->href is stored in the dict of xmlDoc.

      /if defined(DO_NOT_COMPILE)
      /define LIBXML_NAMESPACE_DICT
      /endif

      * xmlBufferAllocationScheme:
      *
      * A buffer allocation scheme can be defined to either match exactly the
      * need or double it's allocated size each time it is found too small.

     d xmlBufferAllocationScheme...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_BUFFER_ALLOC_DOUBLEIT...
     d                 c                   0
     d  XML_BUFFER_ALLOC_EXACT...
     d                 c                   1
     d  XML_BUFFER_ALLOC_IMMUTABLE...
     d                 c                   2
     d  XML_BUFFER_ALLOC_IO...
     d                 c                   3
     d  XML_BUFFER_ALLOC_HYBRID...
     d                 c                   4

      * xmlBuffer:
      *
      * A buffer structure, this old construct is limited to 2GB and
      * is being deprecated, use API with xmlBuf instead

     d xmlBufferPtr    s               *   based(######typedef######)

     d xmlBuffer       ds                  based(xmlBufferPtr)
     d                                     align qualified
     d  content                        *                                        xmlChar *
     d  use                                like(xmlCuint)
     d  size                               like(xmlCuint)
     d  alloc                              like(xmlBufferAllocationScheme)      The realloc method
     d  contentIO                      *                                        xmlChar *

      * xmlBufPtr:
      *
      * A pointer to a buffer structure, the actual structure internals are not
      * public

     d xmlBufPtr       s               *   based(######typedef######)

      * A few public routines for xmlBuf. As those are expected to be used
      * mostly internally the bulk of the routines are internal in buf.h

     d xmlBufContent   pr              *   extproc('xmlBufContent')             xmlChar *
     d  buf                                value like(xmlBufPtr)                const

     d xmlBufEnd       pr              *   extproc('xmlBufEnd')                 xmlChar *
     d  buf                                value like(xmlBufPtr)                const

     d xmlBufUse       pr                  extproc('xmlBufUse')
     d                                     like(xmlCsize_t)
     d  buf                                value like(xmlBufPtr)                const

     d xmlBufShrink    pr                  extproc('xmlBufShrink')
     d                                     like(xmlCsize_t)
     d  buf                                value like(xmlBufPtr)
     d  len                                value like(xmlCsize_t)

      * LIBXML2_NEW_BUFFER:
      *
      * Macro used to express that the API use the new buffers for
      * xmlParserInputBuffer and xmlOutputBuffer. The change was
      * introduced in 2.9.0.

      /define LIBXML2_NEW_BUFFER

      * XML_XML_NAMESPACE:
      *
      * This is the namespace for the special xml: prefix predefined in the
      * XML Namespace specification.

     d XML_XML_NAMESPACE...
     d                 c                   'http://www.w3.org/XML/1998/+
     d                                      namespace'

      * XML_XML_ID:
      *
      * This is the name for the special xml:id attribute

     d XML_XML_ID      c                   'xml:id'

      * The different element types carried by an XML tree.
      *
      * NOTE: This is synchronized with DOM Level1 values
      *       See http://www.w3.org/TR/REC-DOM-Level-1/
      *
      * Actually this had diverged a bit, and now XML_DOCUMENT_TYPE_NODE should
      * be deprecated to use an XML_DTD_NODE.

     d xmlElementType  s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_ELEMENT_NODE...
     d                 c                   1
     d  XML_ATTRIBUTE_NODE...
     d                 c                   2
     d  XML_TEXT_NODE  c                   3
     d  XML_CDATA_SECTION_NODE...
     d                 c                   4
     d  XML_ENTITY_REF_NODE...
     d                 c                   5
     d  XML_ENTITY_NODE...
     d                 c                   6
     d  XML_PI_NODE    c                   7
     d  XML_COMMENT_NODE...
     d                 c                   8
     d  XML_DOCUMENT_NODE...
     d                 c                   9
     d  XML_DOCUMENT_TYPE_NODE...
     d                 c                   10
     d  XML_DOCUMENT_FRAG_NODE...
     d                 c                   11
     d  XML_NOTATION_NODE...
     d                 c                   12
     d  XML_HTML_DOCUMENT_NODE...
     d                 c                   13
     d  XML_DTD_NODE   c                   14
     d  XML_ELEMENT_DECL...
     d                 c                   15
     d  XML_ATTRIBUTE_DECL...
     d                 c                   16
     d  XML_ENTITY_DECL...
     d                 c                   17
     d  XML_NAMESPACE_DECL...
     d                 c                   18
     d  XML_LOCAL_NAMESPACE...
     d                 c                   18                                   Alias
     d  XML_XINCLUDE_START...
     d                 c                   19
     d  XML_XINCLUDE_END...
     d                 c                   20
      /if defined(LIBXML_DOCB_ENABLED)
     d  XML_DOCB_DOCUMENT_NODE...
     d                 c                   21
      /endif

      * xmlNotation:
      *
      * A DTD Notation definition.

     d xmlNotationPtr  s               *   based(######typedef######)

     d xmlNotation     ds                  based(xmlNotationPtr)
     d                                     align qualified
     d  name                           *                                        const xmlChar *
     d  PublicID                       *                                        const xmlChar *
     d  SystemID                       *                                        const xmlChar *

      * xmlAttributeType:
      *
      * A DTD Attribute type definition.

     d xmlAttributeType...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_ATTRIBUTE_CDATA...
     d                 c                   1
     d  XML_ATTRIBUTE_ID...
     d                 c                   2
     d  XML_ATTRIBUTE_IDREF...
     d                 c                   3
     d  XML_ATTRIBUTE_IDREFS...
     d                 c                   4
     d  XML_ATTRIBUTE_ENTITY...
     d                 c                   5
     d  XML_ATTRIBUTE_ENTITIES...
     d                 c                   6
     d  XML_ATTRIBUTE_NMTOKEN...
     d                 c                   7
     d  XML_ATTRIBUTE_NMTOKENS...
     d                 c                   8
     d  XML_ATTRIBUTE_ENUMERATION...
     d                 c                   9
     d  XML_ATTRIBUTE_NOTATION...
     d                 c                   10

      * xmlAttributeDefault:
      *
      * A DTD Attribute default definition.

     d xmlAttributeDefault...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_ATTRIBUTE_NONE...
     d                 c                   1
     d  XML_ATTRIBUTE_REQUIRED...
     d                 c                   2
     d  XML_ATTRIBUTE_IMPLIED...
     d                 c                   3
     d  XML_ATTRIBUTE_FIXED...
     d                 c                   4

      * xmlEnumeration:
      *
      * List structure used when there is an enumeration in DTDs.

     d xmlEnumerationPtr...
     d                 s               *   based(######typedef######)

     d xmlEnumeration  ds                  based(xmlEnumerationPtr)
     d                                     align qualified
     d  next                               like(xmlEnumerationPtr)              Next one
     d  name                           *                                        const xmlChar *

      * Forward pointer declarations.

     d xmlNodePtr      s               *   based(######typedef######)
     d xmlDocPtr       s               *   based(######typedef######)
     d xmlDtdPtr       s               *   based(######typedef######)

      * xmlAttribute:
      *
      * An Attribute declaration in a DTD.

     d xmlAttributePtr...
     d                 s               *   based(######typedef######)

     d xmlAttribute    ds                  based(xmlAttributePtr)
     d                                     align qualified
     d  #private                       *                                        Application data
     d  type                               like(xmlElementType)                 XML_ATTRIBUTE_DECL
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     NULL
     d  last                               like(xmlNodePtr)                     NULL
     d  parent                             like(xmlDtdPtr)                      -> DTD
     d  next                               like(xmlNodePtr)                     next sibling link
     d  prev                               like(xmlNodePtr)                     previous sibling lnk
     d  doc                                like(xmlDocPtr)                      The containing doc
     d  nexth                              like(xmlAttributePtr)                Next in hash table
     d  atype                              like(xmlAttributeType)               The attribute type
     d  def                                like(xmlAttributeDefault)            The default
     d  defaultValue                   *                                        or const xmlChar *
     d  tree                               like(xmlEnumerationPtr)              or enum tree
     d  prefix                         *                                        const xmlChar *
     d  elem                           *                                        const xmlChar *

      * xmlElementContentType:
      *
      * Possible definitions of element content types.

     d xmlElementContentType...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_ELEMENT_CONTENT_PCDATA...
     d                 c                   1
     d  XML_ELEMENT_CONTENT_ELEMENT...
     d                 c                   2
     d  XML_ELEMENT_CONTENT_SEQ...
     d                 c                   3
     d  XML_ELEMENT_CONTENT_OR...
     d                 c                   4

      * xmlElementContentOccur:
      *
      * Possible definitions of element content occurrences.

     d xmlElementContentOccur...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_ELEMENT_CONTENT_ONCE...
     d                 c                   1
     d  XML_ELEMENT_CONTENT_OPT...
     d                 c                   2
     d  XML_ELEMENT_CONTENT_MULT...
     d                 c                   3
     d  XML_ELEMENT_CONTENT_PLUS...
     d                 c                   4

      * xmlElementContent:
      *
      * An XML Element content as stored after parsing an element definition
      * in a DTD.

     d xmlElementContentPtr...
     d                 s               *   based(######typedef######)

     d xmlElementContent...
     d                 ds                  based(xmlElementContentPtr)
     d                                     align qualified
     d  type                               like(xmlElementContentType)
     d  ocur                               like(xmlElementContentOccur)
     d  name                           *                                        const xmlChar *
     d  c1                                 like(xmlElementContentPtr)           First child
     d  c2                                 like(xmlElementContentPtr)           Second child
     d  parent                             like(xmlElementContentPtr)           Parent
     d  prefix                         *                                        const xmlChar *

      * xmlElementTypeVal:
      *
      * The different possibilities for an element content type.

     d xmlElementTypeVal...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_ELEMENT_TYPE_UNDEFINED...
     d                 c                   0
     d  XML_ELEMENT_TYPE_EMPTY...
     d                 c                   1
     d  XML_ELEMENT_TYPE_ANY...
     d                 c                   2
     d  XML_ELEMENT_TYPE_MIXED...
     d                 c                   3
     d  XML_ELEMENT_TYPE_ELEMENT...
     d                 c                   4

      /include "libxmlrpg/xmlregexp"

      * xmlElement:
      *
      * An XML Element declaration from a DTD.

     d xmlElementPtr   s               *   based(######typedef######)

     d xmlElement      ds                  based(xmlElementPtr)
     d                                     align qualified
     d  #private                       *                                        Application data
     d  type                               like(xmlElementType)                 XML_ELEMENT_DECL
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     NULL
     d  last                               like(xmlNodePtr)                     NULL
     d  parent                             like(xmlDtdPtr)                      -> DTD
     d  next                               like(xmlNodePtr)                     next sibling link
     d  prev                               like(xmlNodePtr)                     previous sibling lnk
     d  doc                                like(xmlDocPtr)                      The containing doc
     d  etype                              like(xmlElementTypeVal)              The type
     d  content                            like(xmlElementContentPtr)           Allowed elem content
     d  attributes                         like(xmlAttributePtr)                Declared attributes
     d  prefix                         *                                        const xmlChar *
      /if defined(LIBXML_REGEXP_ENABLED)
     d  contModel                          like(xmlRegexpPtr)                   Validating regexp
      /else
     d  contModel                      *
      /endif

      * XML_LOCAL_NAMESPACE:
      *
      * A namespace declaration node.

      * xmlNs:
      *
      * An XML namespace.
      * Note that prefix == NULL is valid, it defines the default namespace
      * within the subtree (until overridden).
      *
      * xmlNsType is unified with xmlElementType.

     d xmlNsType       s                   based(######typedef######)           enum
     d                                     like(xmlElementType)

     d xmlNsPtr        s               *   based(######typedef######)

     d xmlNs           ds                  based(xmlNsPtr)
     d                                     align qualified
     d  next                               like(xmlNsPtr)                       next Ns link
     d  type                               like(xmlNsType)                      Global or local
     d  href                           *                                        const xmlChar *
     d  prefix                         *                                        const xmlChar *
     d  #private                       *                                        Application data
     d  context                            like(xmlDocPtr)                      normally an xmlDoc

      * xmlDtd:
      *
      * An XML DTD, as defined by <!DOCTYPE ... There is actually one for
      * the internal subset and for the external subset.

     d xmlDtd          ds                  based(xmlDtdPtr)
     d                                     align qualified
     d  #private                       *                                        Application data
     d  type                               like(xmlElementType)                 XML_DTD_NODE
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     Property link value
     d  last                               like(xmlNodePtr)                     Last child link
     d  parent                             like(xmlDocPtr)                      Child->parent link
     d  next                               like(xmlNodePtr)                     next sibling link
     d  prev                               like(xmlNodePtr)                     previous sibling lnk
     d  doc                                like(xmlDocPtr)                      The containing doc
     d  notations                      *                                        notations hash table
     d  elements                       *                                        elements hash table
     d  entities                       *                                        entities hash table
     d  ExternalID                     *                                        const xmlChar *
     d  SystemID                       *                                        const xmlChar *
     d  pentities                      *                                        param. ent. h table

      * xmlAttr:
      *
      * An attribute on an XML node.

     d xmlAttrPtr      s               *   based(######typedef######)

     d xmlAttr         ds                  based(xmlAttrPtr)
     d                                     align qualified
     d  #private                       *                                        Application data
     d  type                               like(xmlElementType)                 XML_ATTRIBUTE_NODE
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     Property link value
     d  last                               like(xmlNodePtr)                     NULL
     d  parent                             like(xmlNodePtr)                     Child->parent link
     d  next                               like(xmlAttrPtr)                     next sibling link
     d  prev                               like(xmlAttrPtr)                     previous sibling lnk
     d  doc                                like(xmlDocPtr)                      The containing doc
     d  ns                                 like(xmlNsPtr)                       Associated namespace
     d  atype                              like(xmlAttributeType)               For validation
     d  psvi                           *                                        Type/PSVI info

      * xmlID:
      *
      * An XML ID instance.

     d xmlIdPtr        s               *   based(######typedef######)

     d xmlID           ds                  based(xmlIdPtr)
     d                                     align qualified
     d  next                               like(xmlIdPtr)                       Next ID
     d  attr                               like(xmlAttrPtr)                     Attribute holding it
     d  name                           *                                        const xmlChar *
     d  lineno                             like(xmlCint)                        Line # if not avail
     d  doc                                like(xmlDocPtr)                      Doc holding ID

      * xmlRef:
      *
      * An XML IDREF instance.

     d xmlRefPtr       s               *   based(######typedef######)

     d xmlRef          ds                  based(xmlRefPtr)
     d                                     align qualified
     d  next                               like(xmlRefPtr)                      Next Ref
     d  value                          *                                        const xmlChar *
     d  attr                               like(xmlAttrPtr)                     Attribute holding it
     d  name                           *                                        const xmlChar *
     d  lineno                             like(xmlCint)                        Line # if not avail

      * xmlNode:
      *
      * A node in an XML tree.

     d xmlNode         ds                  based(xmlNodePtr)
     d                                     align qualified
     d  #private                       *                                        Application data
     d  type                               like(xmlElementType)
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     Parent->children lnk
     d  last                               like(xmlNodePtr)                     Last child link
     d  parent                             like(xmlNodePtr)                     Child->parent link
     d  next                               like(xmlNodePtr)                     next sibling link
     d  prev                               like(xmlNodePtr)                     previous sibling lnk
     d  doc                                like(xmlDocPtr)                      The containing doc
     d  ns                                 like(xmlNsPtr)                       Associated namespace
     d  content                        *                                        xmlChar *
     d  properties                         like(xmlAttrPtr)                     Properties list
     d  nsDef                              like(xmlNsPtr)                       Node ns definitions
     d  psvi                           *                                        Type/PSVI info
     d  line                               like(xmlCushort)
     d  extra                              like(xmlCushort)                     Data for XPath/XSLT

      * xmlDocProperty
      *
      * Set of properties of the document as found by the parser
      * Some of them are linked to similary named xmlParserOption

     d xmlDocProperties...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_DOC_WELLFORMED...
     d                 c                   X'00000001'
     d  XML_DOC_NSVALID...
     d                 c                   X'00000002'
     d  XML_DOC_OLD10  c                   X'00000004'
     d  XML_DOC_DTDVALID...
     d                 c                   X'00000008'
     d  XML_DOC_XINCLUDE...
     d                 c                   X'00000010'
     d  XML_DOC_USERBUILT...
     d                 c                   X'00000020'
     d  XML_DOC_INTERNAL...
     d                 c                   X'00000030'
     d  XML_DOC_HTML   c                   X'00000080'

      * xmlDoc:
      *
      * An XML document.

     d xmlDoc          ds                  based(xmlDocPtr)
     d                                     align qualified
     d  #private                       *                                        Application data
     d  type                               like(xmlElementType)                 XML_DOCUMENT_NODE
     d  name                           *                                        const xmlChar *
     d  children                           like(xmlNodePtr)                     The document tree
     d  last                               like(xmlNodePtr)                     Last child link
     d  parent                             like(xmlNodePtr)                     Child->parent link
     d  next                               like(xmlNodePtr)                     next sibling link
     d  prev                               like(xmlNodePtr)                     previous sibling lnk
     d  doc                                like(xmlDocPtr)                      Reference to itself
     d  compression                        like(xmlCint)                        zlib compression lev
     d  standalone                         like(xmlCint)
     d  intSubset                          like(xmlDtdPtr)                      Internal subset
     d  extSubset                          like(xmlDtdPtr)                      External subset
     d  oldns                              like(xmlNsPtr)                       Global namespace
     d  version                        *                                        const xmlChar *
     d  encoding                       *                                        const xmlChar *
     d  ids                            *                                        IDs hash table
     d  refs                           *                                        IDREFs hash table
     d  URL                            *                                        const xmlChar *
     d  charset                            like(xmlCint)                        In-memory encoding
     d  dict                           *                                        xmlDictPtr for names
     d  psvi                           *                                        Type/PSVI ino
     d  parseFlags                         like(xmlCint)                        xmlParserOption's
     d  properties                         like(xmlCint)                        xmlDocProperties

      * xmlDOMWrapAcquireNsFunction:
      * @ctxt:  a DOM wrapper context
      * @node:  the context node (element or attribute)
      * @nsName:  the requested namespace name
      * @nsPrefix:  the requested namespace prefix
      *
      * A function called to acquire namespaces (xmlNs) from the wrapper.
      *
      * Returns an xmlNsPtr or NULL in case of an error.

     d xmlDOMWrapAcquireNsFunction...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * xmlDOMWrapCtxt:
      *
      * Context for DOM wrapper-operations.

     d xmlDOMWrapCtxtPtr...
     d                 s               *   based(######typedef######)

     d xmlDOMWrapCtxt...
     d                 ds                  based(xmlDOMWrapCtxtPtr)
     d                                     align qualified
     d  #private                       *                                        void *
     d  type                               like(xmlCint)
     d  namespaceMap                   *                                        void *
     d  getNsForNodeFunc...
     d                                     like(xmlDOMWrapAcquireNsFunction)


      * Variables.

      * Some helper functions

      /undefine XML_TESTVAL
      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_XPATH_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_DEBUG_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_HTML_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SAX1_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_HTML_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_WRITER_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_DOCB_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlValidateNCName...
     d                 pr                  extproc('xmlValidateNCName')
     d                                     like(xmlCint)
     d  value                          *   value options(*string)               const xmlChar *
     d  space                              value like(xmlCint)

      /undefine XML_TESTVAL
      /endif

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlValidateQName...
     d                 pr                  extproc('xmlValidateQName')
     d                                     like(xmlCint)
     d  value                          *   value options(*string)               const xmlChar *
     d  space                              value like(xmlCint)

     d xmlValidateName...
     d                 pr                  extproc('xmlValidateName')
     d                                     like(xmlCint)
     d  value                          *   value options(*string)               const xmlChar *
     d  space                              value like(xmlCint)

     d xmlValidateNMToken...
     d                 pr                  extproc('xmlValidateNMToken')
     d                                     like(xmlCint)
     d  value                          *   value options(*string)               const xmlChar *
     d  space                              value like(xmlCint)

      /undefine XML_TESTVAL
      /endif

     d xmlBuildQName   pr              *   extproc('xmlBuildQName')             xmlChar *
     d  ncname                         *   value options(*string)               const xmlChar *
     d  prefix                         *   value options(*string)               const xmlChar *
     d  memory                    65535    options(*varsize: *omit)             xmlChar[]
     d  len                                value like(xmlCint)                  memory length

     d xmlSplitQName2  pr              *   extproc('xmlSplitQName2')            xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  prefix                         *                                        xmlChar *

     d xmlSplitQName3  pr              *   extproc('xmlSplitQName3')            const xmlChar *
     d  name                           *   value options(*string)               const xmlChar *
     d  len                                like(xmlCint)

      * Handling Buffers, the old ones see @xmlBuf for the new ones.

     d xmlSetBufferAllocationScheme...
     d                 pr                  extproc(
     d                                      'xmlSetBufferAllocationScheme')
     d  scheme                             value
     d                                     like(xmlBufferAllocationScheme)

     d xmlGetBufferAllocationScheme...
     d                 pr                  extproc(
     d                                      'xmlGetBufferAllocationScheme')
     d                                     like(xmlBufferAllocationScheme)

     d xmlBufferCreate...
     d                 pr                  extproc('xmlBufferCreate')
     d                                     like(xmlBufferPtr)

     d xmlBufferCreateSize...
     d                 pr                  extproc('xmlBufferCreateSize')
     d                                     like(xmlBufferPtr)
     d  size                               value like(xmlCsize_t)

     d xmlBufferCreateStatic...
     d                 pr                  extproc('xmlBufferCreateStatic')
     d                                     like(xmlBufferPtr)
     d  mem                            *   value
     d  size                               value like(xmlCsize_t)

     d xmlBufferResize...
     d                 pr                  extproc('xmlBufferResize')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  size                               value like(xmlCsize_t)

     d xmlBufferFree   pr                  extproc('xmlBufferFree')
     d  buf                                value like(xmlBufferPtr)

     d xmlBufferDump   pr                  extproc('xmlBufferDump')
     d                                     like(xmlCint)
     d  file                           *   value                                FILE *
     d  buf                                value like(xmlBufferPtr)

     d xmlBufferAdd    pr                  extproc('xmlBufferAdd')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  str                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)                  str length

     d xmlBufferAddHead...
     d                 pr                  extproc('xmlBufferAddHead')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  str                            *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)                  str length

     d xmlBufferCat    pr                  extproc('xmlBufferCat')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  str                            *   value options(*string)               const xmlChar *

     d xmlBufferCCat   pr                  extproc('xmlBufferCCat')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  str                            *   value options(*string)               const char *

     d xmlBufferShrink...
     d                 pr                  extproc('xmlBufferShrink')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  len                                value like(xmlCuint)

     d xmlBufferGrow   pr                  extproc('xmlBufferGrow')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  len                                value like(xmlCuint)

     d xmlBufferEmpty  pr                  extproc('xmlBufferEmpty')
     d  buf                                value like(xmlBufferPtr)

     d xmlBufferContent...
     d                 pr              *   extproc('xmlBufferContent')          const xmlChar *
     d  buf                                value like(xmlBufferPtr)

     d xmlBufferDetach...
     d                 pr              *   extproc('xmlBufferDetach')           xmlChar *
     d  buf                                value like(xmlBufferPtr)

     d xmlBufferSetAllocationScheme...
     d                 pr                  extproc(
     d                                      'xmlBufferSetAllocationScheme')
     d  buf                                value like(xmlBufferPtr)
     d  scheme                             value
     d                                     like(xmlBufferAllocationScheme)

     d xmlBufferLength...
     d                 pr                  extproc('xmlBufferLength')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)

      * Creating/freeing new structures.

     d xmlCreateIntSubset...
     d                 pr                  extproc('xmlCreateIntSubset')
     d                                     like(xmlDtdPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemlID                      *   value options(*string)               const xmlChar *

     d xmlNewDtd       pr                  extproc('xmlNewDtd')
     d                                     like(xmlDtdPtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemlID                      *   value options(*string)               const xmlChar *

     d xmlGetIntSubset...
     d                 pr                  extproc('xmlGetIntSubset')
     d                                     like(xmlDtdPtr)
     d  doc                                value like(xmlDocPtr)

     d xmlFreeDtd      pr                  extproc('xmlFreeDtd')
     d  cur                                value like(xmlDtdPtr)

      /if defined(LIBXML_LEGACY_ENABLED)
     d xmlNewGlobalNs  pr                  extproc('xmlNewGlobalNs')
     d                                     like(xmlNsPtr)
     d  doc                                value like(xmlDocPtr)
     d  href                           *   value options(*string)               const xmlChar *
     d  prefix                         *   value options(*string)               const xmlChar *
      /endif                                                                    LIBXML_LEGACY_ENABLD

     d xmlNewNs        pr                  extproc('xmlNewNs')
     d                                     like(xmlNsPtr)
     d  node                               value like(xmlNodePtr)
     d  href                           *   value options(*string)               const xmlChar *
     d  prefix                         *   value options(*string)               const xmlChar *

     d xmlFreeNs       pr                  extproc('xmlFreeNs')
     d  cur                                value like(xmlNsPtr)

     d xmlFreeNsList   pr                  extproc('xmlFreeNsList')
     d  cur                                value like(xmlNsPtr)

     d xmlNewDoc       pr                  extproc('xmlNewDoc')
     d                                     like(xmlDocPtr)
     d  version                        *   value options(*string)               const xmlChar *

     d xmlFreeDoc      pr                  extproc('xmlFreeDoc')
     d  cur                                value like(xmlDocPtr)

     d xmlNewDocProp   pr                  extproc('xmlNewDocProp')
     d                                     like(xmlAttrPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  value                          *   value options(*string)               const xmlChar *

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_HTML_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlNewProp      pr                  extproc('xmlNewProp')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  value                          *   value options(*string)               const xmlChar *

      /undefine XML_TESTVAL
      /endif

     d xmlNewNsProp    pr                  extproc('xmlNewNsProp')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  value                          *   value options(*string)               const xmlChar *

     d xmlNewNsPropEatName...
     d                 pr                  extproc('xmlNewNsPropEatName')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value                                xmlChar *
     d  value                          *   value options(*string)               const xmlChar *

     d xmlFreePropList...
     d                 pr                  extproc('xmlFreePropList')
     d  cur                                value like(xmlAttrPtr)

     d xmlFreeProp     pr                  extproc('xmlFreeProp')
     d  cur                                value like(xmlAttrPtr)

     d xmlCopyProp     pr                  extproc('xmlCopyProp')
     d                                     like(xmlAttrPtr)
     d  target                             value like(xmlNodePtr)
     d  cur                                value like(xmlAttrPtr)

     d xmlCopyPropList...
     d                 pr                  extproc('xmlCopyPropList')
     d                                     like(xmlAttrPtr)
     d  target                             value like(xmlNodePtr)
     d  cur                                value like(xmlAttrPtr)

      /if defined(LIBXML_TREE_ENABLED)
     d xmlCopyDtd      pr                  extproc('xmlCopyDtd')
     d                                     like(xmlDtdPtr)
     d  dtd                                value like(xmlDtdPtr)
      /endif                                                                    LIBXML_TREE_ENABLED

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlCopyDoc      pr                  extproc('xmlCopyDoc')
     d                                     like(xmlDocPtr)
     d  doc                                value like(xmlDocPtr)
     d  recursive                          value like(xmlCint)

      /undefine XML_TESTVAL
      /endif

      * Creating new nodes.

     d xmlNewDocNode   pr                  extproc('xmlNewDocNode')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewDocNodeEatName...
     d                 pr                  extproc('xmlNewDocNodeEatName')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value                                xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewNode      pr                  extproc('xmlNewNode')
     d                                     like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlNewNodeEatName...
     d                 pr                  extproc('xmlNewNodeEatName')
     d                                     like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value                                xmlChar *

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlNewChild     pr                  extproc('xmlNewChild')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

      /undefine XML_TESTVAL
      /endif

     d xmlNewDocText   pr                  extproc('xmlNewDocText')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewText      pr                  extproc('xmlNewText')
     d                                     like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewDocPI     pr                  extproc('xmlNewDocPI')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewPI        pr                  extproc('xmlNewPI')
     d                                     like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewDocTextLen...
     d                 pr                  extproc('xmlNewDocTextLen')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlNewTextLen   pr                  extproc('xmlNewTextLen')
     d                                     like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlNewDocComment...
     d                 pr                  extproc('xmlNewDocComment')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewComment   pr                  extproc('xmlNewComment')
     d                                     like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewCDataBlock...
     d                 pr                  extproc('xmlNewCDataBlock')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlNewCharRef   pr                  extproc('xmlNewCharRef')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlNewReference...
     d                 pr                  extproc('xmlNewReference')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlCopyNode     pr                  extproc('xmlCopyNode')
     d                                     like(xmlNodePtr)
     d  node                               value like(xmlNodePtr)
     d  recursive                          value like(xmlCint)

     d xmlDocCopyNode  pr                  extproc('xmlDocCopyNode')
     d                                     like(xmlNodePtr)
     d  node                               value like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  recursive                          value like(xmlCint)

     d xmlDocCopyNodeList...
     d                 pr                  extproc('xmlDocCopyNodeList')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)

     d xmlCopyNodeList...
     d                 pr                  extproc('xmlCopyNodeList')
     d                                     like(xmlNodePtr)
     d  node                               value like(xmlNodePtr)

      /if defined(LIBXML_TREE_ENABLED)
     d xmlNewTextChild...
     d                 pr                  extproc('xmlNewTextChild')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewDocRawNode...
     d                 pr                  extproc('xmlNewDocRawNode')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNewDocFragment...
     d                 pr                  extproc('xmlNewDocFragment')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
      /endif                                                                    LIBXML_TREE_ENABLED

      * Navigating.

     d xmlNewDocFragment...
     d xmlGetLineNo    pr                  extproc('xmlGetLineNo')
     d                                     like(xmlClong)
     d  node                               value like(xmlNodePtr)

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_DEBUG_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlGetNodePath  pr              *   extproc('xmlGetNodePath')            xmlChar *
     d  node                               value like(xmlNodePtr)

      /undefine XML_TESTVAL
      /endif

     d xmlDocGetRootElement...
     d                 pr                  extproc('xmlDocGetRootElement')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)

     d xmlGetLastChild...
     d                 pr                  extproc('xmlGetLastChild')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)

     d xmlNodeIsText   pr                  extproc('xmlNodeIsText')
     d                                     like(xmlCint)
     d  node                               value like(xmlNodePtr)

     d xmlIsBlankNode  pr                  extproc('xmlIsBlankNode')
     d                                     like(xmlCint)
     d  node                               value like(xmlNodePtr)

      * Changing the structure.

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_WRITER_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlDocSetRootElement...
     d                 pr                  extproc('xmlDocSetRootElement')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  root                               value like(xmlNodePtr)

      /undefine XML_TESTVAL
      /endif

      /if defined(LIBXML_TREE_ENABLED)
     d xmlNodeSetName  pr                  extproc('xmlNodeSetName')
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *
      /endif                                                                    LIBXML_TREE_ENABLED

     d xmlAddChild     pr                  extproc('xmlAddChild')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)
     d  cur                                value like(xmlNodePtr)

     d xmlAddChildList...
     d                 pr                  extproc('xmlAddChildList')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)
     d  cur                                value like(xmlNodePtr)

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_WRITER_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlReplaceNode  pr                  extproc('xmlReplaceNode')
     d                                     like(xmlNodePtr)
     d  old                                value like(xmlNodePtr)
     d  cur                                value like(xmlNodePtr)

      /undefine XML_TESTVAL
      /endif

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_HTML_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlAddPrevSibling...
     d                 pr                  extproc('xmlAddPrevSibling')
     d                                     like(xmlNodePtr)
     d  cur                                value like(xmlNodePtr)
     d  elem                               value like(xmlNodePtr)

      /undefine XML_TESTVAL
      /endif

     d xmlAddSibling   pr                  extproc('xmlAddSibling')
     d                                     like(xmlNodePtr)
     d  cur                                value like(xmlNodePtr)
     d  elem                               value like(xmlNodePtr)

     d xmlAddNextSibling...
     d                 pr                  extproc('xmlAddNextSibling')
     d                                     like(xmlNodePtr)
     d  cur                                value like(xmlNodePtr)
     d  elem                               value like(xmlNodePtr)

     d xmlUnlinkNode   pr                  extproc('xmlUnlinkNode')
     d  cur                                value like(xmlNodePtr)

     d xmlTextMerge    pr                  extproc('xmlTextMerge')
     d                                     like(xmlNodePtr)
     d  first                              value like(xmlNodePtr)
     d  second                             value like(xmlNodePtr)

     d xmlTextConcat   pr                  extproc('xmlTextConcat')
     d                                     like(xmlCint)
     d  node                               value like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlFreeNodeList...
     d                 pr                  extproc('xmlFreeNodeList')
     d  cur                                value like(xmlNodePtr)

     d xmlFreeNode     pr                  extproc('xmlFreeNode')
     d  cur                                value like(xmlNodePtr)

     d xmlSetTreeDoc   pr                  extproc('xmlSetTreeDoc')
     d  tree                               value like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)

     d xmlSetListDoc   pr                  extproc('xmlSetListDoc')
     d  list                               value like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)

      * Namespaces.

     d xmlSearchNs     pr                  extproc('xmlSearchNs')
     d                                     like(xmlNsPtr)
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)
     d  nameSpace                      *   value options(*string)               const xmlChar *

     d xmlSearchNsByHref...
     d                 pr                  extproc('xmlSearchNsByHref')
     d                                     like(xmlNsPtr)
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)
     d  href                           *   value options(*string)               const xmlChar *

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_XPATH_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlGetNsList    pr              *   extproc('xmlGetNsList')              xmlNsPtr *
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)

      /undefine XML_TESTVAL
      /endif

     d xmlSetNs        pr                  extproc('xmlSetNs')
     d  node                               value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)

     d xmlCopyNamespace...
     d                 pr                  extproc('xmlCopyNamespace')
     d                                     like(xmlNsPtr)
     d  cur                                value like(xmlNsPtr)

     d xmlCopyNamespaceList...
     d                 pr                  extproc('xmlCopyNamespaceList')
     d                                     like(xmlNsPtr)
     d  cur                                value like(xmlNsPtr)

      * Changing the content.

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_XINCLUDE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_HTML_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlSetProp      pr                  extproc('xmlSetProp')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  value                          *   value options(*string)               const xmlChar *

     d xmlSetNsProp    pr                  extproc('xmlSetNsProp')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  value                          *   value options(*string)               const xmlChar *

      /undefine XML_TESTVAL
      /endif

     d xmlGetNoNsProp  pr              *   extproc('xmlGetNoNsProp')            xmlChar *
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlGetProp      pr              *   extproc('xmlGetProp')                xmlChar *
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlHasProp      pr                  extproc('xmlHasProp')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlHasNsProp    pr                  extproc('xmlHasNsProp')
     d                                     like(xmlAttrPtr)
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  nameSpace                      *   value options(*string)               const xmlChar *

     d xmlGetNsProp    pr              *   extproc('xmlGetNsProp')              xmlChar *
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *
     d  nameSpace                      *   value options(*string)               const xmlChar *

     d xmlStringGetNodeList...
     d                 pr                  extproc('xmlStringGetNodeList')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  value                          *   value options(*string)               const xmlChar *

     d xmlStringLenGetNodeList...
     d                 pr                  extproc('xmlStringLenGetNodeList')
     d                                     like(xmlNodePtr)
     d  doc                                value like(xmlDocPtr)
     d  value                          *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlNodeListGetString...
     d                 pr              *   extproc('xmlNodeListGetString')      xmlChar *
     d  doc                                value like(xmlDocPtr)
     d  list                               value like(xmlNodePtr)
     d  inLine                             value like(xmlCint)

      /if defined(LIBXML_TREE_ENABLED)
     d xmlNodeListGetRawString...
     d                 pr              *   extproc('xmlNodeListGetRawString')   xmlChar *
     d  doc                                value like(xmlDocPtr)
     d  list                               value like(xmlNodePtr)
     d  inLine                             value like(xmlCint)
      /endif                                                                    LIBXML_TREE_ENABLED

     d xmlNodeSetContent...
     d                 pr                  extproc('xmlNodeSetContent')
     d  cur                                value like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *

      /if defined(LIBXML_TREE_ENABLED)
     d xmlNodeSetContentLen...
     d                 pr                  extproc('xmlNodeSetContentLen')
     d  cur                                value like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)
      /endif                                                                    LIBXML_TREE_ENABLED

     d xmlNodeAddContent...
     d                 pr                  extproc('xmlNodeAddContent')
     d  cur                                value like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *

     d xmlNodeAddContentLen...
     d                 pr                  extproc('xmlNodeAddContentLen')
     d  cur                                value like(xmlNodePtr)
     d  content                        *   value options(*string)               const xmlChar *
     d  len                                value like(xmlCint)

     d xmlNodeGetContent...
     d                 pr              *   extproc('xmlNodeGetContent')         xmlChar *
     d  cur                                value like(xmlNodePtr)

     d xmlNodeBufGetContent...
     d                 pr                  extproc('xmlNodeBufGetContent')
     d                                     like(xmlCint)
     d  buffer                             value like(xmlBufferPtr)
     d  cur                                value like(xmlNodePtr)

     d xmlBufGetNodeContent...
     d                 pr                  extproc('xmlBufGetNodeContent')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufPtr)
     d  cur                                value like(xmlNodePtr)

     d xmlNodeGetLang  pr              *   extproc('xmlNodeGetLang')            xmlChar *
     d  cur                                value like(xmlNodePtr)

     d xmlNodeGetSpacePreserve...
     d                 pr                  extproc('xmlNodeGetSpacePreserve')
     d                                     like(xmlCint)
     d  cur                                value like(xmlNodePtr)

      /if defined(LIBXML_TREE_ENABLED)
     d xmlNodeSetLang  pr                  extproc('xmlNodeSetLang')
     d  cur                                value like(xmlNodePtr)
     d  lang                           *   value options(*string)               const xmlChar *

     d xmlNodeSetSpacePreserve...
     d                 pr                  extproc('xmlNodeSetSpacePreserve')
     d  cur                                value like(xmlNodePtr)
     d  val                                value like(xmlCint)
      /endif                                                                    LIBXML_TREE_ENABLED

     d xmlNodeGetBase  pr              *   extproc('xmlNodeGetBase')            xmlChar *
     d  doc                                value like(xmlDocPtr)
     d  cur                                value like(xmlNodePtr)

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_XINCLUDE_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlNodeSetBase  pr                  extproc('xmlNodeSetBase')
     d  node                               value like(xmlNodePtr)
     d  uri                            *   value options(*string)               const xmlChar *

      /undefine XML_TESTVAL
      /endif

      * Removing content.

     d xmlRemoveProp   pr                  extproc('xmlRemoveProp')
     d                                     like(xmlCint)
     d  cur                                value like(xmlAttrPtr)

      /if defined(LIBXML_TREE_ENABLED)
      /define XML_TESTVAL
      /elseif defined(LIBXML_SCHEMAS_ENABLED)
      /define XML_TESTVAL
      /endif
      /if defined(XML_TESTVAL)
     d xmlUnsetNsProp  pr                  extproc('xmlUnsetNsProp')
     d                                     like(xmlCint)
     d  node                               value like(xmlNodePtr)
     d  ns                                 value like(xmlNsPtr)
     d  name                           *   value options(*string)               const xmlChar *

     d xmlUnsetProp    pr                  extproc('xmlUnsetProp')
     d                                     like(xmlCint)
     d  node                               value like(xmlNodePtr)
     d  name                           *   value options(*string)               const xmlChar *

      /undefine XML_TESTVAL
      /endif

      * Internal, don't use.

     d xmlBufferWriteCharacter...                                               Warning: renamed
     d                 pr                  extproc('xmlBufferWriteCHAR')
     d  buf                                value like(xmlBufferPtr)
     d  string                         *   value options(*string)               const xmlChar *

     d xmlBufferWriteChar...
     d                 pr                  extproc('xmlBufferWriteChar')
     d  buf                                value like(xmlBufferPtr)
     d  string                         *   value options(*string)               const xmlChar *

     d xmlBufferWriteQuotedString...
     d                 pr                  extproc('xmlBufferWriteQuotedString')
     d  buf                                value like(xmlBufferPtr)
     d  string                         *   value options(*string)               const xmlChar *

      /if defined(LIBXML_OUTPUT_ENABLED)
     d xmlAttrSerializeTxtContent...
     d                 pr                  extproc('xmlAttrSerializeTxtContent')
     d  buf                                value like(xmlBufferPtr)
     d  attr                               value like(xmlAttrPtr)
     d  string                         *   value options(*string)               const xmlChar *
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      /if defined(LIBXML_TREE_ENABLED)

      * Namespace handling.

     d xmlReconciliateNs...
     d                 pr                  extproc('xmlReconciliateNs')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  tree                               value like(xmlNodePtr)
      /endif

      /if defined(LIBXML_OUTPUT_ENABLED)

      * Saving.

     d xmlDocDumpFormatMemory...
     d                 pr                  extproc('xmlDocDumpFormatMemory')
     d  cur                                value like(xmlDocPtr)
     d  mem                            *                                        xmlChar * (*)
     d  size                               like(xmlCint)
     d  format                             value like(xmlCint)

     d xmlDocDumpMemory...
     d                 pr                  extproc('xmlDocDumpMemory')
     d  cur                                value like(xmlDocPtr)
     d  mem                            *                                        xmlChar * (*)
     d  size                               like(xmlCint)

     d xmlDocDumpMemoryEnc...
     d                 pr                  extproc('xmlDocDumpMemoryEnc')
     d  out_doc                            value like(xmlDocPtr)
     d  doc_txt_ptr                    *                                        xmlChar * (*)
     d  doc_txt_len                        like(xmlCint)
     d  txt_encoding                   *   value options(*string)               const char *

     d xmlDocDumpFormatMemoryEnc...
     d                 pr                  extproc('xmlDocDumpFormatMemoryEnc')
     d  out_doc                            value like(xmlDocPtr)
     d  doc_txt_ptr                    *                                        xmlChar * (*)
     d  doc_txt_len                        like(xmlCint)
     d  txt_encoding                   *   value options(*string)               const char *
     d  format                             value like(xmlCint)

     d xmlDocFormatDump...
     d                 pr                  extproc('xmlDocFormatDump')
     d                                     like(xmlCint)
     d  f                              *   value                                FILE *
     d  cur                                value like(xmlDocPtr)
     d  format                             value like(xmlCint)

     d xmlDocDump      pr                  extproc('xmlDocDump')
     d                                     like(xmlCint)
     d  f                              *   value                                FILE *
     d  cur                                value like(xmlDocPtr)

     d xmlElemDump     pr                  extproc('xmlElemDump')
     d  f                              *   value                                FILE *
     d  doc                                value like(xmlDocPtr)
     d  cur                                value like(xmlNodePtr)

     d xmlSaveFile     pr                  extproc('xmlSaveFile')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  cur                                value like(xmlDocPtr)

     d xmlSaveFormatFile...
     d                 pr                  extproc('xmlSaveFormatFile')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  cur                                value like(xmlDocPtr)
     d  format                             value like(xmlCint)

     d xmlBufNodeDump  pr                  extproc('xmlBufNodeDump')
     d                                     like(xmlCsize_t)
     d  buf                                value like(xmlBufPtr)
     d  doc                                value like(xmlDocPtr)
     d  cur                                value like(xmlNodePtr)
     d  level                              value like(xmlCint)
     d  format                             value like(xmlCint)

     d xmlNodeDump     pr                  extproc('xmlNodeDump')
     d                                     like(xmlCint)
     d  buf                                value like(xmlBufferPtr)
     d  doc                                value like(xmlDocPtr)
     d  cur                                value like(xmlNodePtr)
     d  level                              value like(xmlCint)
     d  format                             value like(xmlCint)

     d xmlSaveFileTo   pr                  extproc('xmlSaveFileTo')
     d                                     like(xmlCint)
     d  buf                                value like(xmlOutputBufferPtr)
     d  cur                                value like(xmlDocPtr)
     d  encoding                       *   value options(*string)               const char *

     d xmlSaveFormatFileTo...
     d                 pr                  extproc('xmlSaveFormatFileTo')
     d                                     like(xmlCint)
     d  buf                                value like(xmlOutputBufferPtr)
     d  cur                                value like(xmlDocPtr)
     d  encoding                       *   value options(*string)               const char *
     d  format                             value like(xmlCint)

     d xmlNodeDumpOutput...
     d                 pr                  extproc('xmlNodeDumpOutput')
     d  buf                                value like(xmlOutputBufferPtr)
     d  doc                                value like(xmlDocPtr)
     d  cur                                value like(xmlNodePtr)
     d  level                              value like(xmlCint)
     d  format                             value like(xmlCint)
     d  encoding                       *   value options(*string)               const char *

     d xmlSaveFormatFileEnc...
     d                 pr                  extproc('xmlSaveFormatFileEnc')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  cur                                value like(xmlDocPtr)
     d  encoding                       *   value options(*string)               const char *
     d  format                             value like(xmlCint)

     d xmlSaveFileEnc  pr                  extproc('xmlSaveFileEnc')
     d                                     like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  cur                                value like(xmlDocPtr)
     d  encoding                       *   value options(*string)               const char *
      /endif                                                                    LIBXML_OUTPUT_ENABLD

      * XHTML

     d xmlIsXHTML      pr                  extproc('xmlIsXHTML')
     d                                     like(xmlCint)
     d  systemID                       *   value options(*string)               const xmlChar *
     d  publicID                       *   value options(*string)               const xmlChar *

      * Compression.

     d xmlGetDocCompressMode...
     d                 pr                  extproc('xmlGetDocCompressMode')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)

     d xmlSetDocCompressMode...
     d                 pr                  extproc('xmlSetDocCompressMode')
     d  doc                                value like(xmlDocPtr)
     d  mode                               value like(xmlCint)

     d xmlGetCompressMode...
     d                 pr                  extproc('xmlGetCompressMode')
     d                                     like(xmlCint)

     d xmlSetCompressMode...
     d                 pr                  extproc('xmlSetCompressMode')
     d  mode                               value like(xmlCint)

      * DOM-wrapper helper functions.

     d xmlDOMWrapNewCtxt...
     d                 pr                  extproc('xmlDOMWrapNewCtxt')
     d                                     like(xmlDOMWrapCtxtPtr)

     d xmlDOMWrapFreeCtxt...
     d                 pr                  extproc('xmlDOMWrapFreeCtxt')
     d  ctxt                               value like(xmlDOMWrapCtxtPtr)

     d xmlDOMWrapReconcileNamespaces...
     d                 pr                  extproc(
     d                                      'xmlDOMWrapReconcileNamespaces')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlDOMWrapCtxtPtr)
     d  elem                               value like(xmlNodePtr)
     d  options                            value like(xmlCint)

     d xmlDOMWrapAdoptNode...
     d                 pr                  extproc('xmlDOMWrapAdoptNode')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlDOMWrapCtxtPtr)
     d  sourceDoc                          value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)
     d  destDoc                            value like(xmlDocPtr)
     d  destParent                         value like(xmlNodePtr)
     d  options                            value like(xmlCint)

     d xmlDOMWrapRemoveNode...
     d                 pr                  extproc('xmlDOMWrapRemoveNode')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlDOMWrapCtxtPtr)
     d  doc                                value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)
     d  options                            value like(xmlCint)

     d xmlDOMWrapCloneNode...
     d                 pr                  extproc('xmlDOMWrapCloneNode')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlDOMWrapCtxtPtr)
     d  sourceDoc                          value like(xmlDocPtr)
     d  node                               value like(xmlNodePtr)
     d  clonedNode                         like(xmlNodePtr)
     d  destDoc                            value like(xmlDocPtr)
     d  destParent                         value like(xmlNodePtr)
     d  options                            value like(xmlCint)

      /if defined(LIBXML_TREE_ENABLED)

      * 5 interfaces from DOM ElementTraversal, but different in entities
      * traversal.

     d xmlChildElementCount...
     d                 pr                  extproc('xmlChildElementCount')
     d                                     like(xmlClong)
     d  parent                             value like(xmlNodePtr)

     d xmlNextElementSibling...
     d                 pr                  extproc('xmlNextElementSibling')
     d                                     like(xmlNodePtr)
     d  node                               value like(xmlNodePtr)

     d xmlFirstElementChild...
     d                 pr                  extproc('xmlFirstElementChild')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)

     d xmlLastElementChild...
     d                 pr                  extproc('xmlLastElementChild')
     d                                     like(xmlNodePtr)
     d  parent                             value like(xmlNodePtr)

     d xmlPreviousElementSibling...
     d                 pr                  extproc('xmlPreviousElementSibling')
     d                                     like(xmlNodePtr)
     d  node                               value like(xmlNodePtr)
      /endif

      /if not defined(XML_PARSER_H__)
      /include "libxmlrpg/xmlmemory"
      /endif

      /endif                                                                    XML_TREE_H__
