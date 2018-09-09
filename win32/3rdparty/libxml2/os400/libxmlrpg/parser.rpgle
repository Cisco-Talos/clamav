      * Summary: the core parser module
      * Description: Interfaces, constants and types related to the XML parser
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_PARSER_H__)
      /define XML_PARSER_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/tree"
      /include "libxmlrpg/dict"
      /include "libxmlrpg/hash"
      /include "libxmlrpg/valid"
      /include "libxmlrpg/entities"
      /include "libxmlrpg/xmlerror"
      /include "libxmlrpg/xmlstring"

      * XML_DEFAULT_VERSION:
      *
      * The default version of XML used: 1.0

     d XML_DEFAULT_VERSION...
     d                 c                   '1.0'

      * xmlParserInput:
      *
      * An xmlParserInput is an input flow for the XML processor.
      * Each entity parsed is associated an xmlParserInput (except the
      * few predefined ones). This is the case both for internal entities
      * - in which case the flow is already completely in memory - or
      * external entities - in which case we use the buf structure for
      * progressive reading and I18N conversions to the internal UTF-8 format.

      * xmlParserInputDeallocate:
      * @str:  the string to deallocate
      *
      * Callback for freeing some parser input allocations.

     d xmlParserInputDeallocate...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * Input buffer

     d xmlParserInput  ds                  based(xmlParserInputPtr)
     d                                     align qualified
     d  buf                                like(xmlParserInputBufferPtr)        UTF-8 encoded buffer
     d  filename                       *                                        const char *
     d  directory                      *                                        const char *
     d  base                           *                                        const char *
     d  cur                            *                                        const char *
     d  end                            *                                        const char *
     d  length                             like(xmlCint)                        Length if known
     d  line                               like(xmlCint)                        Current line
     d  col                                like(xmlCint)                        Current column
      *
      * NOTE: consumed is only tested for equality in the parser code,
      *       so even if there is an overflow this should not give troubles
      *       for parsing very large instances.
      *
     d  consumed                           like(xmlCulong)                      # consumed xmlChars
     d  free                               like(xmlParserInputDeallocate)       base deallocator
     d  encoding                       *                                        const xmlChar *
     d  version                        *                                        const xmlChar *
     d  standalone                         like(xmlCint)                        Standalone entity ?
     d  id                                 like(xmlCint)                        Entity unique ID

      * xmlParserNodeInfo:
      *
      * The parser can be asked to collect Node informations, i.e. at what
      * place in the file they were detected.
      * NOTE: This is off by default and not very well tested.

     d xmlParserNodeInfoPtr...
     d                 s               *   based(######typedef######)

     d xmlParserNodeInfo...
     d                 ds                  based(xmlParserNodeInfoPtr)
     d                                     align qualified
     d  node                               like(xmlNodePtr)                     const
      * Position & line # that text that created the node begins & ends on
     d  begin_pos                          like(xmlCulong)
     d  begin_line                         like(xmlCulong)
     d  end_pos                            like(xmlCulong)
     d  end_line                           like(xmlCulong)

     d xmlParserNodeInfoSeqPtr...
     d                 s               *   based(######typedef######)

     d xmlParserNodeInfoSeq...
     d                 ds                  based(xmlParserNodeInfoSeqPtr)
     d                                     align qualified
     d  maximum                            like(xmlCulong)
     d  length                             like(xmlCulong)
     d  buffer                             like(xmlParserNodeInfoPtr)

      * xmlParserInputState:
      *
      * The parser is now working also as a state based parser.
      * The recursive one use the state info for entities processing.

     d xmlParserInputState...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_PARSER_EOF...                                                       Nothing to parse
     d                 c                   -1
     d  XML_PARSER_START...                                                     Nothing parsed
     d                 c                   0
     d  XML_PARSER_MISC...                                                      Misc* b4 int subset
     d                 c                   1
     d  XML_PARSER_PI  c                   2                                    In proc instr
     d  XML_PARSER_DTD...                                                       In some DTD content
     d                 c                   3
     d  XML_PARSER_PROLOG...                                                    Misc* after int sbst
     d                 c                   4
     d  XML_PARSER_COMMENT...                                                   Within a comment
     d                 c                   5
     d  XML_PARSER_START_TAG...                                                 Within a start tag
     d                 c                   6
     d  XML_PARSER_CONTENT...                                                   Within the content
     d                 c                   7
     d  XML_PARSER_CDATA_SECTION...                                             Within a CDATA
     d                 c                   8
     d  XML_PARSER_END_TAG...                                                   Within a closing tag
     d                 c                   9
     d  XML_PARSER_ENTITY_DECL...                                               In an entity decl
     d                 c                   10
     d  XML_PARSER_ENTITY_VALUE...                                              In entity decl value
     d                 c                   11
     d  XML_PARSER_ATTRIBUTE_VALUE...                                           In attribute value
     d                 c                   12
     d  XML_PARSER_SYSTEM_LITERAL...                                            In a SYSTEM value
     d                 c                   13
     d  XML_PARSER_EPILOG...                                                    Last end tag Misc*
     d                 c                   14
     d  XML_PARSER_IGNORE...                                                    In IGNORED section
     d                 c                   15
     d  XML_PARSER_PUBLIC_LITERAL...                                            In a PUBLIC value
     d                 c                   16

      * XML_DETECT_IDS:
      *
      * Bit in the loadsubset context field to tell to do ID/REFs lookups.
      * Use it to initialize xmlLoadExtDtdDefaultValue.

     d XML_DETECT_IDS  c                   2

      * XML_COMPLETE_ATTRS:
      *
      * Bit in the loadsubset context field to tell to do complete the
      * elements attributes lists with the ones defaulted from the DTDs.
      * Use it to initialize xmlLoadExtDtdDefaultValue.

     d XML_COMPLETE_ATTRS...
     d                 c                   4

      * XML_SKIP_IDS:
      *
      * Bit in the loadsubset context field to tell to not do ID/REFs
      *   registration.
      * Used to initialize xmlLoadExtDtdDefaultValue in some special cases.

     d XML_SKIP_IDS    c                   8

      * xmlParserMode:
      *
      * A parser can operate in various modes

     d xmlParserMode   s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_PARSE_UNKNOWN...
     d                 c                   0
     d  XML_PARSE_DOM...
     d                 c                   1
     d  XML_PARSE_SAX...
     d                 c                   2
     d  XML_PARSE_PUSH_DOM...
     d                 c                   3
     d  XML_PARSE_PUSH_SAX...
     d                 c                   4
     d  XML_PARSE_READER...
     d                 c                   5

      * xmlParserCtxt:
      *
      * The parser context.
      * NOTE This doesn't completely define the parser state, the (current ?)
      *      design of the parser uses recursive function calls since this allow
      *      and easy mapping from the production rules of the specification
      *      to the actual code. The drawback is that the actual function call
      *      also reflect the parser state. However most of the parsing routines
      *      takes as the only argument the parser context pointer, so migrating
      *      to a state based parser for progressive parsing shouldn't be too
      *      hard.

     d xmlParserCtxt   ds                  based(xmlParserCtxtPtr)
     d                                     align qualified
     d  sax                                like(xmlSAXHandlerPtr)               The SAX handler
     d  userData                       *                                        SAX only-4 DOM build
     d  myDoc                              like(xmlDocPtr)                      Document being built
     d  wellFormed                         like(xmlCint)                        Well formed doc ?
     d  replaceEntities...                                                      Replace entities ?
     d                                     like(xmlCint)
     d  version                        *                                        const xmlChar *
     d  encoding                       *                                        const xmlChar *
     d  standalone                         like(xmlCint)                        Standalone document
     d  html                               like(xmlCint)                        HTML state/type
      *
      * Input stream stack
      *
     d  input                              like(xmlParserInputPtr)              Current input stream
     d  inputNr                            like(xmlCint)                        # current in streams
     d  inputMax                           like(xmlCint)                        Max # of in streams
     d  inputTab                       *                                        xmlParserInputPtr *
      *
      * Node analysis stack only used for DOM building
      *
     d  node                               like(xmlNodePtr)                     Current parsed node
     d  nodeNr                             like(xmlCint)                        Parsing stack depth
     d  nodeMax                            like(xmlCint)                        Max stack depth
     d  nodeTab                        *                                        xmlNodePtr *
      *
     d  record_info                        like(xmlCint)                        Keep node info ?
     d  node_seq                           likeds(xmlParserNodeInfoSeq)         Parsed nodes info
      *
     d  errNo                              like(xmlCint)                        Error code
      *
     d  hasExternalSubset...
     d                                     like(xmlCint)
     d  hasPErefs                          like(xmlCint)
     d  external                           like(xmlCint)                        Parsing ext. entity?
      *
     d  valid                              like(xmlCint)                        Valid document ?
     d  validate                           like(xmlCint)                        Try to validate ?
     d  vctxt                              likeds(xmlValidCtxt)                 Validity context
      *
     d  instate                            like(xmlParserInputState)            Current input type
     d  token                              like(xmlCint)                        Next look-ahead char
      *
     d  directory                      *                                        char *
      *
      * Node name stack
      *
     d  name                           *                                        const xmlChar *
     d  nameNr                             like(xmlCint)                        Parsing stack depth
     d  nameMax                            like(xmlCint)                        Max stack depth
     d  nameTab                        *                                        const xmlChar * *
      *
     d  nbChars                            like(xmlClong)                       # xmlChars processed
     d  checkIndex                         like(xmlClong)                       4 progressive parse
     d  keepBlanks                         like(xmlCint)                        Ugly but ...
     d  disableSAX                         like(xmlCint)                        Disable SAX cllbacks
     d  inSubset                           like(xmlCint)                        In int 1/ext 2 sbset
     d  intSubName                     *                                        const xmlChar *
     d  extSubURI                      *                                        const xmlChar *
     d  extSubSytem                    *                                        const xmlChar *
      *
      * xml:space values
      *
     d  space                          *                                        int *
     d  spaceNr                            like(xmlCint)                        Parsing stack depth
     d  spaceMax                           like(xmlCint)                        Max stack depth
     d  spaceTab                       *                                        int *
      *
     d  depth                              like(xmlCint)                        To detect loops
     d  entity                             like(xmlParserInputPtr)              To check boundaries
     d  charset                            like(xmlCint)                        In-memory content
     d  nodelen                            like(xmlCint)                        Speed up parsing
     d  nodemem                            like(xmlCint)                        Speed up parsing
     d  pedantic                           like(xmlCint)                        Enb. pedantic warng
     d  #private                       *                                        void *
      *
     d  loadsubset                         like(xmlCint)                        Load ext. subset ?
     d  linenumbers                        like(xmlCint)                        Set line numbers ?
     d  catalogs                       *                                        void *
     d  recovery                           like(xmlCint)                        Run in recovery mode
     d  progressive                        like(xmlCint)                        Progressive parsing?
     d  dict                               like(xmlDictPtr)                     Parser dictionary
     d  atts                           *                                        const xmlChar *
     d  maxatts                            like(xmlCint)                        Above array size
     d  docdict                            like(xmlCint)                        Use dictionary ?
      *
      * pre-interned strings
      *
     d  str_xml                        *                                        const xmlChar *
     d  str_xmlns                      *                                        const xmlChar *
     d  str_xml_ms                     *                                        const xmlChar *
      *
      * Everything below is used only by the new SAX mode
      *
     d  sax2                               like(xmlCint)                        New SAX mode ?
     d  nsNr                               like(xmlCint)                        # inherited nmspaces
     d  nsMax                              like(xmlCint)                        Array size
     d  nsTab                          *                                        const xmlChar *
     d  attallocs                      *                                        int *
     d  pushTab                        *                                        void *
     d  attsDefault                        like(xmlHashTablePtr)                Defaulted attrs
     d  attsSpecial                        like(xmlHashTablePtr)                non-CDATA attrs
     d  nsWellFormed                       like(xmlCint)                        Doc namespace OK ?
     d  options                            like(xmlCint)                        Extra options
      *
      * Those fields are needed only for treaming parsing so far
      *
     d  dictNames                          like(xmlCint)                        Dict names in tree ?
     d  freeElemsNr                        like(xmlCint)                        # free element nodes
     d  freeElems                          like(xmlNodePtr)                     Free elem nodes list
     d  freeAttrsNr                        like(xmlCint)                        # free attr. nodes
     d  freeAttrs                          like(xmlAttrPtr)                     Free attr noes list
      *
      * the complete error informations for the last error.
      *
     d  lastError                          likeds(xmlError)
     d  parseMode                          like(xmlParserMode)                  The parser mode
     d  nbentities                         like(xmlCulong)                      # entity references
     d  sizeentities                       like(xmlCulong)                      Parsed entities size
      *
      * for use by HTML non-recursive parser
      *
     d  nodeInfo                           like(xmlParserNodeInfoPtr)           Current NodeInfo
     d  nodeInfoNr                         like(xmlCint)                        Parsing stack depth
     d  nodeInfoMax                        like(xmlCint)                        Max stack depth
     d  nodeInfoTab                    *                                        xmlParserNodeInfo *
      *
     d  input_id                           like(xmlCint)                        Label inputs ?
     d  sizeentcopy                        like(xmlCulong)                      Entity copy volume

      * xmlSAXLocator:
      *
      * A SAX Locator.

     d xmlSAXLocator   ds                  based(xmlSAXLocatorPtr)
     d                                     align qualified
     d  getPublicId                    *   procptr
     d  getSystemId                    *   procptr
     d  getLineNumber                  *   procptr
     d  getColumnNumber...
     d                                 *   procptr

      * xmlSAXHandler:
      *
      * A SAX handler is bunch of callbacks called by the parser when
      * processing of the input generate data or structure informations.

      * resolveEntitySAXFunc:
      * @ctx:  the user data (XML parser context)
      * @publicId: The public ID of the entity
      * @systemId: The system ID of the entity
      *
      * Callback:
      * The entity loader, to control the loading of external entities,
      * the application can either:
      *    - override this resolveEntity() callback in the SAX block
      *    - or better use the xmlSetExternalEntityLoader() function to
      *      set up it's own entity resolution routine
      *
      * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.

     d resolveEntitySAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * internalSubsetSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  the root element name
      * @ExternalID:  the external ID
      * @SystemID:  the SYSTEM ID (e.g. filename or URL)
      *
      * Callback on internal subset declaration.

     d internalSubsetSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * externalSubsetSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  the root element name
      * @ExternalID:  the external ID
      * @SystemID:  the SYSTEM ID (e.g. filename or URL)
      *
      * Callback on external subset declaration.

     d externalSubsetSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * getEntitySAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name: The entity name
      *
      * Get an entity by name.
      *
      * Returns the xmlEntityPtr if found.

     d getEntitySAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * getParameterEntitySAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name: The entity name
      *
      * Get a parameter entity by name.
      *
      * Returns the xmlEntityPtr if found.

     d getParameterEntitySAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * entityDeclSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  the entity name
      * @type:  the entity type
      * @publicId: The public ID of the entity
      * @systemId: The system ID of the entity
      * @content: the entity value (without processing).
      *
      * An entity definition has been parsed.

     d entityDeclSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * notationDeclSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name: The name of the notation
      * @publicId: The public ID of the entity
      * @systemId: The system ID of the entity
      *
      * What to do when a notation declaration has been parsed.

     d notationDeclSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * attributeDeclSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @elem:  the name of the element
      * @fullname:  the attribute name
      * @type:  the attribute type
      * @def:  the type of default value
      * @defaultValue: the attribute default value
      * @tree:  the tree of enumerated value set
      *
      * An attribute definition has been parsed.

     d attributeDeclSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * elementDeclSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  the element name
      * @type:  the element type
      * @content: the element value tree
      *
      * An element definition has been parsed.

     d elementDeclSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * unparsedEntityDeclSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name: The name of the entity
      * @publicId: The public ID of the entity
      * @systemId: The system ID of the entity
      * @notationName: the name of the notation
      *
      * What to do when an unparsed entity declaration is parsed.

     d unparsedEntityDeclSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * setDocumentLocatorSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @loc: A SAX Locator
      *
      * Receive the document locator at startup, actually xmlDefaultSAXLocator.
      * Everything is available on the context, so this is useless in our case.

     d setDocumentLocatorSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * startDocumentSAXFunc:
      * @ctx:  the user data (XML parser context)
      *
      * Called when the document start being processed.

     d startDocumentSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * endDocumentSAXFunc:
      * @ctx:  the user data (XML parser context)
      *
      * Called when the document end has been detected.

     d endDocumentSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * startElementSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  The element name, including namespace prefix
      * @atts:  An array of name/value attributes pairs, NULL terminated
      *
      * Called when an opening tag has been processed.

     d startElementSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * endElementSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  The element name
      *
      * Called when the end of an element has been detected.

     d endElementSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * attributeSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  The attribute name, including namespace prefix
      * @value:  The attribute value
      *
      * Handle an attribute that has been read by the parser.
      * The default handling is to convert the attribute into an
      * DOM subtree and past it in a new xmlAttr element added to
      * the element.

     d attributeSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * referenceSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @name:  The entity name
      *
      * Called when an entity reference is detected.

     d referenceSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * charactersSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @ch:  a xmlChar string
      * @len: the number of xmlChar
      *
      * Receiving some chars from the parser.

     d charactersSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * ignorableWhitespaceSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @ch:  a xmlChar string
      * @len: the number of xmlChar
      *
      * Receiving some ignorable whitespaces from the parser.
      * UNUSED: by default the DOM building will use characters.

     d ignorableWhitespaceSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * processingInstructionSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @target:  the target name
      * @data: the PI data's
      *
      * A processing instruction has been parsed.

     d processingInstructionSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * commentSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @value:  the comment content
      *
      * A comment has been parsed.

     d commentSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * cdataBlockSAXFunc:
      * @ctx:  the user data (XML parser context)
      * @value:  The pcdata content
      * @len:  the block length
      *
      * Called when a pcdata block has been parsed.

     d cdataBlockSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * warningSAXFunc:
      * @ctx:  an XML parser context
      * @msg:  the message to display/transmit
      * @...:  extra parameters for the message display
      *
      * Display and format a warning messages, callback.

     d warningSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * errorSAXFunc:
      * @ctx:  an XML parser context
      * @msg:  the message to display/transmit
      * @...:  extra parameters for the message display
      *
      * Display and format an error messages, callback.

     d errorSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * fatalErrorSAXFunc:
      * @ctx:  an XML parser context
      * @msg:  the message to display/transmit
      * @...:  extra parameters for the message display
      *
      * Display and format fatal error messages, callback.
      * Note: so far fatalError() SAX callbacks are not used, error()
      *       get all the callbacks for errors.

     d fatalErrorSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * isStandaloneSAXFunc:
      * @ctx:  the user data (XML parser context)
      *
      * Is this document tagged standalone?
      *
      * Returns 1 if true

     d isStandaloneSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * hasInternalSubsetSAXFunc:
      * @ctx:  the user data (XML parser context)
      *
      * Does this document has an internal subset.
      *
      * Returns 1 if true

     d hasInternalSubsetSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * hasExternalSubsetSAXFunc:
      * @ctx:  the user data (XML parser context)
      *
      * Does this document has an external subset?
      *
      * Returns 1 if true

     d hasExternalSubsetSAXFunc...
     d                 s               *   based(######typedef######)
     d                                     procptr

      ************************************************************************
      *                                                                      *
      *                      The SAX version 2 API extensions                *
      *                                                                      *
      ************************************************************************

      * XML_SAX2_MAGIC:
      *
      * Special constant found in SAX2 blocks initialized fields

     d XML_SAX2_MAGIC  c                   X'DEEDBEAF'

      * startElementNsSAX2Func:
      * @ctx:           the user data (XML parser context)
      * @localname:     the local name of the element
      * @prefix:        the element namespace prefix if available
      * @URI:           the element namespace name if available
      * @nb_namespaces: number of namespace definitions on that node
      * @namespaces:    pointer to the array of prefix/URI pairs namespace
      *                 definitions
      * @nb_attributes:  the number of attributes on that node
      * @nb_defaulted:   the number of defaulted attributes. The defaulted
      *                  ones are at the end of the array
      * @attributes:     pointer to the array of
      *                  (localname/prefix/URI/value/end) attribute values.
      *
      * SAX2 callback when an element start has been detected by the parser.
      * It provides the namespace informations for the element, as well as
      * the new namespace declarations on the element.

     d startElementNsSAX2Func...
     d                 s               *   based(######typedef######)
     d                                     procptr

      * endElementNsSAX2Func:
      * @ctx:  the user data (XML parser context)
      * @localname:  the local name of the element
      * @prefix:  the element namespace prefix if available
      * @URI:  the element namespace name if available
      *
      * SAX2 callback when an element end has been detected by the parser.
      * It provides the namespace informations for the element.

     d endElementNsSAX2Func...
     d                 s               *   based(######typedef######)
     d                                     procptr

     d xmlSAXHandler   ds                  based(xmlSAXHandlerPtr)
     d                                     align qualified
     d  internalSubset...
     d                                     like(internalSubsetSAXFunc)
     d  isStandalone                       like(isStandaloneSAXFunc)
     d  hasInternalSubset...
     d                                     like(hasInternalSubsetSAXFunc)
     d  hasExternalSubset...
     d                                     like(hasExternalSubsetSAXFunc)
     d  resolveEntity                      like(resolveEntitySAXFunc)
     d  getEntity                          like(getEntitySAXFunc)
     d  entityDecl                         like(entityDeclSAXFunc)
     d  notationDecl                       like(notationDeclSAXFunc)
     d  attributeDecl                      like(attributeDeclSAXFunc)
     d  elementDecl                        like(elementDeclSAXFunc)
     d  unparsedEntityDecl...
     d                                     like(unparsedEntityDeclSAXFunc)
     d  setDocumentLocator...
     d                                     like(setDocumentLocatorSAXFunc)
     d  startDocument                      like(startDocumentSAXFunc)
     d  endDocument                        like(endDocumentSAXFunc)
     d  startElement                       like(startElementSAXFunc)
     d  endElement                         like(endElementSAXFunc)
     d  reference                          like(referenceSAXFunc)
     d  characters                         like(charactersSAXFunc)
     d  ignorableWhitespace...
     d                                     like(ignorableWhitespaceSAXFunc)
     d  processingInstruction...
     d                                     like(processingInstructionSAXFunc)
     d  comment                            like(commentSAXFunc)
     d  warning                            like(warningSAXFunc)
     d  error                              like(errorSAXFunc)
     d  fatalError                         like(fatalErrorSAXFunc)
     d  getParameterEntity...
     d                                     like(getParameterEntitySAXFunc)
     d  cdataBlock                         like(cdataBlockSAXFunc)
     d  externalSubset...
     d                                     like(externalSubsetSAXFunc)
     d  initialized                        like(xmlCuint)
      *
      * The following fields are extensions available only on version 2
      *
     d  #private                       *                                        void *
     d  startElementNs...
     d                                     like(startElementNsSAX2Func)
     d  endELementNs                       like(endElementNsSAX2Func)
     d  serror                             like(xmlStructuredErrorFunc)

      * SAX Version 1

     d xmlSAXHandlerV1Ptr...
     d                 s               *   based(######typedef######)

     d xmlSAXHandlerV1...
     d                 ds                  based(xmlSAXHandlerV1Ptr)
     d                                     align qualified
     d  internalSubset...
     d                                     like(internalSubsetSAXFunc)
     d  isStandalone                       like(isStandaloneSAXFunc)
     d  hasInternalSubset...
     d                                     like(hasInternalSubsetSAXFunc)
     d  hasExternalSubset...
     d                                     like(hasExternalSubsetSAXFunc)
     d  resolveEntity                      like(resolveEntitySAXFunc)
     d  getEntity                          like(getEntitySAXFunc)
     d  entityDecl                         like(entityDeclSAXFunc)
     d  notationDecl                       like(notationDeclSAXFunc)
     d  attributeDecl                      like(attributeDeclSAXFunc)
     d  elementDecl                        like(elementDeclSAXFunc)
     d  unparsedEntityDecl...
     d                                     like(unparsedEntityDeclSAXFunc)
     d  setDocumentLocator...
     d                                     like(setDocumentLocatorSAXFunc)
     d  startDocument                      like(startDocumentSAXFunc)
     d  endDocument                        like(endDocumentSAXFunc)
     d  startElement                       like(startElementSAXFunc)
     d  endElement                         like(endElementSAXFunc)
     d  reference                          like(referenceSAXFunc)
     d  characters                         like(charactersSAXFunc)
     d  ignorableWhitespace...
     d                                     like(ignorableWhitespaceSAXFunc)
     d  processingInstruction...
     d                                     like(processingInstructionSAXFunc)
     d  comment                            like(commentSAXFunc)
     d  warning                            like(warningSAXFunc)
     d  error                              like(errorSAXFunc)
     d  fatalError                         like(fatalErrorSAXFunc)
     d  getParameterEntity...
     d                                     like(getParameterEntitySAXFunc)
     d  cdataBlock                         like(cdataBlockSAXFunc)
     d  externalSubset...
     d                                     like(externalSubsetSAXFunc)
     d  initialized                        like(xmlCuint)

      * xmlExternalEntityLoader:
      * @URL: The System ID of the resource requested
      * @ID: The Public ID of the resource requested
      * @context: the XML parser context
      *
      * External entity loaders types.
      *
      * Returns the entity input parser.

     d xmlExternalEntityLoader...
     d                 s               *   based(######typedef######)
     d                                     procptr

      /include "libxmlrpg/encoding"
      /include "libxmlrpg/xmlIO"
      /include "libxmlrpg/globals"

      * Init/Cleanup

     d xmlInitParser   pr                  extproc('xmlInitParser')

     d xmlCleanupParser...
     d                 pr                  extproc('xmlCleanupParser')

      * Input functions

     d xmlParserInputRead...
     d                 pr                  extproc('xmlParserInputRead')
     d                                     like(xmlCint)
     d  in                                 value like(xmlParserInputPtr)
     d  len                                value like(xmlCint)

     d xmlParserInputGrow...
     d                 pr                  extproc('xmlParserInputGrow')
     d                                     like(xmlCint)
     d  in                                 value like(xmlParserInputPtr)
     d  len                                value like(xmlCint)

      * Basic parsing Interfaces

      /if defined(LIBXML_SAX1_ENABLED)
     d xmlParseDoc     pr                  extproc('xmlParseDoc')
     d                                     like(xmlDocPtr)
     d  cur                            *   value options(*string)               const xmlChar *

     d xmlParseFile    pr                  extproc('xmlParseFile')
     d                                     like(xmlDocPtr)
     d  filename                       *   value options(*string)               const char *

     d xmlParseMemory  pr                  extproc('xmlParseMemory')
     d                                     like(xmlDocPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
      /endif                                                                    LIBXML_SAX1_ENABLED

     d xmlSubstituteEntitiesDefault...
     d                 pr                  extproc(
     d                                      'xmlSubstituteEntitiesDefault')
     d                                     like(xmlCint)
     d  val                                value like(xmlCint)

     d xmlKeepBlanksDefault...
     d                 pr                  extproc('xmlKeepBlanksDefault')
     d                                     like(xmlCint)
     d  val                                value like(xmlCint)

     d xmlStopParser   pr                  extproc('xmlStopParser')
     d  ctxt                               value like(xmlParserCtxtPtr)

     d xmlPedanticParserDefault...
     d                 pr                  extproc('xmlPedanticParserDefault')
     d                                     like(xmlCint)
     d  val                                value like(xmlCint)

     d xmlLineNumbersDefault...
     d                 pr                  extproc('xmlLineNumbersDefault')
     d                                     like(xmlCint)
     d  val                                value like(xmlCint)

      /if defined(LIBXML_SAX1_ENABLED)
      * Recovery mode

     d xmlRecoverDoc   pr                  extproc('xmlRecoverDoc')
     d                                     like(xmlDocPtr)
     d  cur                            *   value options(*string)               const xmlChar *

     d xmlRecoverMemory...
     d                 pr                  extproc('xmlRecoverMemory')
     d                                     like(xmlDocPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)

     d xmlRecoverFile  pr                  extproc('xmlRecoverFile')
     d                                     like(xmlDocPtr)
     d  filename                       *   value options(*string)               const char *
      /endif                                                                    LIBXML_SAX1_ENABLED

      * Less common routines and SAX interfaces

     d xmlParseDocument...
     d                 pr                  extproc('xmlParseDocument')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)

     d xmlParseExtParsedEnt...
     d                 pr                  extproc('xmlParseExtParsedEnt')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)

      /if defined(LIBXML_SAX1_ENABLED)
     d xmlSAXUserParseFile...
     d                 pr                  extproc('xmlSAXUserParseFile')
     d                                     like(xmlCint)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  filename                       *   value options(*string)               const char *

     d xmlSAXUserParseMemory...
     d                 pr                  extproc('xmlSAXUserParseMemory')
     d                                     like(xmlCint)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)

     d xmlSAXParseDoc  pr                  extproc('xmlSAXParseDoc')
     d                                     like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  recovery                           value like(xmlCint)

     d xmlSAXParseMemory...
     d                 pr                  extproc('xmlSAXParseMemory')
     d                                     like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  recovery                           value like(xmlCint)

     d xmlSAXParseMemoryWithData...
     d                 pr                  extproc('xmlSAXParseMemoryWithData')
     d                                     like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  recovery                           value like(xmlCint)
     d  data                           *   value                                void *

     d xmlSAXParseFile...
     d                 pr                  extproc('xmlSAXParseFile')
     d                                     like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  filename                       *   value options(*string)               const char *
     d  recovery                           value like(xmlCint)

     d xmlSAXParseFileWithData...
     d                 pr                  extproc('xmlSAXParseFileWithData')
     d                                     like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  filename                       *   value options(*string)               const char *
     d  recovery                           value like(xmlCint)
     d  data                           *   value                                void *

     d xmlSAXParseEntity...
     d                 pr                  extproc('xmlSAXParseEntity')
     d                                     like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  filename                       *   value options(*string)               const char *

     d xmlParseEntity...
     d                 pr                  extproc('xmlParseEntity')
     d                                     like(xmlDocPtr)
     d  filename                       *   value options(*string)               const char *
      /endif                                                                    LIBXML_SAX1_ENABLED

      /if defined(LIBXML_VALID_ENABLED)
     d xmlSAXParseDTD  pr                  extproc('xmlSAXParseDTD')
     d                                     like(xmlDtdPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemID                       *   value options(*string)               const xmlChar *

     d xmlParseDTD     pr                  extproc('xmlParseDTD')
     d                                     like(xmlDtdPtr)
     d  ExternalID                     *   value options(*string)               const xmlChar *
     d  SystemID                       *   value options(*string)               const xmlChar *

     d xmlIOParseDTD   pr                  extproc('xmlIOParseDTD')
     d                                     like(xmlDtdPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  input                              value like(xmlParserInputBufferPtr)
     d  enc                                value like(xmlCharEncoding)
      /endif                                                                    LIBXML_VALID_ENABLED

      /if defined(LIBXML_SAX1_ENABLED)
     d xmlParseBalancedChunkMemory...
     d                 pr                  extproc(
     d                                      'xmlParseBalancedChunkMemory')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  depth                              value like(xmlCint)
     d  user_data                      *   value                                void *
     d  string                         *   value options(*string)               const xmlChar *
     d  lst                            *   value                                xmlNodePtr *
      /endif                                                                    LIBXML_SAX1_ENABLED

     d xmlParseInNodeContext...
     d                 pr                  extproc('xmlParseInNodeContext')
     d                                     like(xmlParserErrors)
     d  node                               value like(xmlNodePtr)
     d  data                           *   value options(*string)               const char *
     d  datalen                            value like(xmlCint)
     d  options                            value like(xmlCint)
     d  lst                            *   value                                xmlNodePtr *

      /if defined(LIBXML_SAX1_ENABLED)
     d xmlParseBalancedChunkMemoryRecover...
     d                 pr                  extproc(
     d                                     'xmlParseBalancedChunkMemoryRecover')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  depth                              value like(xmlCint)
     d  string                         *   value options(*string)               const xmlChar *
     d  lst                            *   value                                xmlNodePtr *
     d  recover                            value like(xmlCint)

     d xmlParseExternalEntity...
     d                 pr                  extproc('xmlParseExternalEntity')
     d                                     like(xmlCint)
     d  doc                                value like(xmlDocPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  depth                              value like(xmlCint)
     d  URL                            *   value options(*string)               const xmlChar *
     d  ID                             *   value options(*string)               const xmlChar *
     d  lst                            *   value                                xmlNodePtr *
      /endif                                                                    LIBXML_SAX1_ENABLED

     d xmlParseCtxtExternalEntity...
     d                 pr                  extproc('xmlParseCtxtExternalEntity')
     d                                     like(xmlCint)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  URL                            *   value options(*string)               const xmlChar *
     d  ID                             *   value options(*string)               const xmlChar *
     d  lst                            *   value                                xmlNodePtr *

      * Parser contexts handling.

     d xmlNewParserCtxt...
     d                 pr                  extproc('xmlNewParserCtxt')
     d                                     like(xmlParserCtxtPtr)

     d xmlInitParserCtxt...
     d                 pr                  extproc('xmlInitParserCtxt')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)

     d xmlClearParserCtxt...
     d                 pr                  extproc('xmlClearParserCtxt')
     d  ctxt                               value like(xmlParserCtxtPtr)

     d xmlFreeParserCtxt...
     d                 pr                  extproc('xmlFreeParserCtxt')
     d  ctxt                               value like(xmlParserCtxtPtr)

      /if defined(LIBXML_SAX1_ENABLED)
     d xmlSetupParserForBuffer...
     d                 pr                  extproc('xmlSetupParserForBuffer')
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  buffer                         *   value options(*string)               const xmlChar *
     d  filename                       *   value options(*string)               const char *
      /endif                                                                    LIBXML_SAX1_ENABLED

     d xmlCreateDocParserCtxt...
     d                 pr                  extproc('xmlCreateDocParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d  cur                            *   value options(*string)               const xmlChar *

      /if defined(LIBXML_LEGACY_ENABLED)
      * Reading/setting optional parsing features.

     d xmlGetFeaturesList...
     d                 pr                  extproc('xmlGetFeaturesList')
     d                                     like(xmlCint)
     d  len                                like(xmlCint)
     d  result                         *                                        const char *(*)

     d xmlGetFeature   pr                  extproc('xmlGetFeature')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  name                           *   value options(*string)               const char *
     d  result                         *   value                                void *

     d xmlSetFeature   pr                  extproc('xmlSetFeature')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  name                           *   value options(*string)               const char *
     d  result                         *   value                                void *
      /endif                                                                    LIBXML_LEGACY_ENABLD

      /if defined(LIBXML_PUSH_ENABLED)
      * Interfaces for the Push mode.

     d xmlCreatePushParserCtxt...
     d                 pr                  extproc('xmlCreatePushParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  filename                       *   value options(*string)               const char *

     d xmlParseChunk   pr                  extproc('xmlParseChunk')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  terminate                          value like(xmlCint)
      /endif                                                                    LIBXML_PUSH_ENABLED

      * Special I/O mode.

     d xmlCreateIOParserCtxt...
     d                 pr                  extproc('xmlCreateIOParserCtxt')
     d                                     like(xmlParserCtxtPtr)
     d  sax                                value like(xmlSAXHandlerPtr)
     d  user_data                      *   value                                void *
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  enc                                value like(xmlCharEncoding)

     d xmlNewIOInputStream...
     d                 pr                  extproc('xmlNewIOInputStream')
     d                                     like(xmlParserInputPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  input                              value like(xmlParserInputBufferPtr)
     d  enc                                value like(xmlCharEncoding)

      * Node infos.

     d xmlParserFindNodeInfo...
     d                 pr              *   extproc('xmlParserFindNodeInfo')     xmlParserNodeInfo *
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  node                               value like(xmlNodePtr)               const

     d xmlInitNodeInfoSeq...
     d                 pr                  extproc('xmlInitNodeInfoSeq')
     d  seq                                value like(xmlParserNodeInfoSeqPtr)

     d xmlClearNodeInfoSeq...
     d                 pr                  extproc('xmlClearNodeInfoSeq')
     d  seq                                value like(xmlParserNodeInfoSeqPtr)

     d xmlParserFindNodeInfoIndex...
     d                 pr                  extproc('xmlParserFindNodeInfoIndex')
     d                                     like(xmlCulong)
     d  seq                                value like(xmlParserNodeInfoSeqPtr)
     d  node                               value like(xmlNodePtr)               const

     d xmlParserAddNodeInfo...
     d                 pr                  extproc('xmlParserAddNodeInfo')
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  info                               value like(xmlParserNodeInfoPtr)     const

      * External entities handling actually implemented in xmlIO.

     d xmlSetExternalEntityLoader...
     d                 pr                  extproc('xmlSetExternalEntityLoader')
     d  f                                  value like(xmlExternalEntityLoader)

     d xmlGetExternalEntityLoader...
     d                 pr                  extproc('xmlGetExternalEntityLoader')
     d                                     like(xmlExternalEntityLoader)

     d xmlLoadExternalEntity...
     d                 pr                  extproc('xmlLoadExternalEntity')
     d                                     like(xmlParserInputPtr)
     d  URL                            *   value options(*string)               const char *
     d  ID                             *   value options(*string)               const char *
     d  ctxt                               value like(xmlParserCtxtPtr)

      * Index lookup, actually implemented in the encoding module

     d xmlByteConsumed...
     d                 pr                  extproc('xmlByteConsumed')
     d                                     like(xmlClong)
     d  ctxt                               value like(xmlParserCtxtPtr)

      * New set of simpler/more flexible APIs

      * xmlParserOption:
      *
      * This is the set of XML parser options that can be passed down
      * to the xmlReadDoc() and similar calls.

     d xmlParserOption...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_PARSE_RECOVER...                                                    Recover on errors
     d                 c                   X'00000001'
     d  XML_PARSE_NOENT...                                                      Substitute entities
     d                 c                   X'00000002'
     d  XML_PARSE_DTDLOAD...                                                    Load external subset
     d                 c                   X'00000004'
     d  XML_PARSE_DTDATTR...                                                    Default DTD attrs
     d                 c                   X'00000008'
     d  XML_PARSE_DTDVALID...                                                   Validate with DTD
     d                 c                   X'00000010'
     d  XML_PARSE_NOERROR...                                                    Suppress err reports
     d                 c                   X'00000020'
     d  XML_PARSE_NOWARNING...                                                  Suppr warn reports
     d                 c                   X'00000040'
     d  XML_PARSE_PEDANTIC...                                                   Pedantic err report
     d                 c                   X'00000080'
     d  XML_PARSE_NOBLANKS...                                                   Remove blank nodes
     d                 c                   X'00000100'
     d  XML_PARSE_SAX1...                                                       Use SAX1 internally
     d                 c                   X'00000200'
     d  XML_PARSE_XINCLUDE...                                                   Impl XInclude subst
     d                 c                   X'00000400'
     d  XML_PARSE_NONET...                                                      Forbid netwrk access
     d                 c                   X'00000800'
     d  XML_PARSE_NODICT...                                                     No contxt dict reuse
     d                 c                   X'00001000'
     d  XML_PARSE_NSCLEAN...                                                    Rmv redndnt ns decls
     d                 c                   X'00002000'
     d  XML_PARSE_NOCDATA...                                                    CDATA as text nodes
     d                 c                   X'00004000'
     d  XML_PARSE_NOXINCNODE...                                                 No XINCL START/END
     d                 c                   X'00008000'
     d  XML_PARSE_COMPACT...                                                    Compact text nodes
     d                 c                   X'00010000'
     d  XML_PARSE_OLD10...                                                      B4 upd5 compatible
     d                 c                   X'00020000'
     d  XML_PARSE_NOBASEFIX...                                                  No XINC xml:base fix
     d                 c                   X'00040000'
     d  XML_PARSE_HUGE...                                                       No parsing limit
     d                 c                   X'00080000'
     d  XML_PARSE_OLDSAX...                                                     Use SAX2 b4 2.7.0
     d                 c                   X'00100000'
     d  XML_PARSE_IGNORE_ENC...                                                 No int doc code hint
     d                 c                   X'00200000'
     d  XML_PARSE_BIG_LINES...                                                  Big line#-->PSVI fld
     d                 c                   X'00400000'

     d xmlCtxtReset    pr                  extproc('xmlCtxtReset')
     d  ctxt                               value like(xmlParserCtxtPtr)

     d xmlCtxtResetPush...
     d                 pr                  extproc('xmlCtxtResetPush')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  chunk                          *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *

     d xmlCtxtUseOptions...
     d                 pr                  extproc('xmlCtxtUseOptions')
     d                                     like(xmlCint)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  options                            value like(xmlCint)

     d xmlReadDoc      pr                  extproc('xmlReadDoc')
     d                                     like(xmlDocPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReadFile     pr                  extproc('xmlReadFile')
     d                                     like(xmlDocPtr)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReadMemory   pr                  extproc('xmlReadMemory')
     d                                     like(xmlDocPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReadFd       pr                  extproc('xmlReadFd')
     d                                     like(xmlDocPtr)
     d  fd                                 value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlReadIO       pr                  extproc('xmlReadIO')
     d                                     like(xmlDocPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlCtxtReadDoc  pr                  extproc('xmlCtxtReadDoc')
     d                                     like(xmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  cur                            *   value options(*string)               const xmlChar *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlCtxtReadFile...
     d                 pr                  extproc('xmlCtxtReadFile')
     d                                     like(xmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  filename                       *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlCtxtReadMemory...
     d                 pr                  extproc('xmlCtxtReadMemory')
     d                                     like(xmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  buffer                         *   value options(*string)               const char *
     d  size                               value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlCtxtReadFd   pr                  extproc('xmlCtxtReadFd')
     d                                     like(xmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  fd                                 value like(xmlCint)
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

     d xmlCtxtReadIO   pr                  extproc('xmlCtxtReadIO')
     d                                     like(xmlDocPtr)
     d  ctxt                               value like(xmlParserCtxtPtr)
     d  ioread                             value like(xmlInputReadCallback)
     d  ioclose                            value like(xmlInputCloseCallback)
     d  ioctx                          *   value                                void *
     d  URL                            *   value options(*string)               const char *
     d  encoding                       *   value options(*string)               const char *
     d  options                            value like(xmlCint)

      * Library wide options

      * xmlFeature:
      *
      * Used to examine the existance of features that can be enabled
      * or disabled at compile-time.
      * They used to be called XML_FEATURE_xxx but this clashed with Expat

     d xmlFeature      s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_WITH_THREAD...
     d                 c                   1
     d  XML_WITH_TREE  c                   2
     d  XML_WITH_OUTPUT...
     d                 c                   3
     d  XML_WITH_PUSH  c                   4
     d  XML_WITH_READER...
     d                 c                   5
     d  XML_WITH_PATTERN...
     d                 c                   6
     d  XML_WITH_WRITER...
     d                 c                   7
     d  XML_WITH_SAX1  c                   8
     d  XML_WITH_FTP   c                   9
     d  XML_WITH_HTTP  c                   10
     d  XML_WITH_VALID...
     d                 c                   11
     d  XML_WITH_HTML  c                   12
     d  XML_WITH_LEGACY...
     d                 c                   13
     d  XML_WITH_C14N  c                   14
     d  XML_WITH_CATALOG...
     d                 c                   15
     d  XML_WITH_XPATH...
     d                 c                   16
     d  XML_WITH_XPTR  c                   17
     d  XML_WITH_XINCLUDE...
     d                 c                   18
     d  XML_WITH_ICONV...
     d                 c                   19
     d  XML_WITH_ISO8859X...
     d                 c                   20
     d  XML_WITH_UNICODE...
     d                 c                   21
     d  XML_WITH_REGEXP...
     d                 c                   22
     d  XML_WITH_AUTOMATA...
     d                 c                   23
     d  XML_WITH_EXPR  c                   24
     d  XML_WITH_SCHEMAS...
     d                 c                   25
     d  XML_WITH_SCHEMATRON...
     d                 c                   26
     d  XML_WITH_MODULES...
     d                 c                   27
     d  XML_WITH_DEBUG...
     d                 c                   28
     d  XML_WITH_DEBUG_MEM...
     d                 c                   29
     d  XML_WITH_DEBUG_RUN...
     d                 c                   30
     d  XML_WITH_ZLIB  c                   31
     d  XML_WITH_ICU   c                   32
     d  XML_WITH_LZMA  c                   33
     d  XML_WITH_NONE  c                   99999

     d xmlHasFeature   pr                  extproc('xmlHasFeature')
     d                                     like(xmlCint)
     d  feature                            value like(xmlFeature)

      /endif                                                                    XML_PARSER_H__
