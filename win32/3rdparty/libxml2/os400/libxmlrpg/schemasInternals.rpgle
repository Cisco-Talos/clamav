      * Summary: internal interfaces for XML Schemas
      * Description: internal interfaces for the XML Schemas handling
      *              and schema validity checking
      *              The Schemas development is a Work In Progress.
      *              Some of those interfaces are not guaranteed to be API or
      *                ABI stable !
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_SCHEMA_INTERNALS_H__)
      /define XML_SCHEMA_INTERNALS_H__

      /include "libxmlrpg/xmlversion"

      /if defined(LIBXML_SCHEMAS_ENABLED)

      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/xmlregexp"
      /include "libxmlrpg/hash"
      /include "libxmlrpg/dict"

     d xmlSchemaValType...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_SCHEMAS_UNKNOWN...
     d                 c                   0
     d  XML_SCHEMAS_STRING...
     d                 c                   1
     d  XML_SCHEMAS_NORMSTRING...
     d                 c                   2
     d  XML_SCHEMAS_DECIMAL...
     d                 c                   3
     d  XML_SCHEMAS_TIME...
     d                 c                   4
     d  XML_SCHEMAS_GDAY...
     d                 c                   5
     d  XML_SCHEMAS_GMONTH...
     d                 c                   6
     d  XML_SCHEMAS_GMONTHDAY...
     d                 c                   7
     d  XML_SCHEMAS_GYEAR...
     d                 c                   8
     d  XML_SCHEMAS_GYEARMONTH...
     d                 c                   9
     d  XML_SCHEMAS_DATE...
     d                 c                   10
     d  XML_SCHEMAS_DATETIME...
     d                 c                   11
     d  XML_SCHEMAS_DURATION...
     d                 c                   12
     d  XML_SCHEMAS_FLOAT...
     d                 c                   13
     d  XML_SCHEMAS_DOUBLE...
     d                 c                   14
     d  XML_SCHEMAS_BOOLEAN...
     d                 c                   15
     d  XML_SCHEMAS_TOKEN...
     d                 c                   16
     d  XML_SCHEMAS_LANGUAGE...
     d                 c                   17
     d  XML_SCHEMAS_NMTOKEN...
     d                 c                   18
     d  XML_SCHEMAS_NMTOKENS...
     d                 c                   19
     d  XML_SCHEMAS_NAME...
     d                 c                   20
     d  XML_SCHEMAS_QNAME...
     d                 c                   21
     d  XML_SCHEMAS_NCNAME...
     d                 c                   22
     d  XML_SCHEMAS_ID...
     d                 c                   23
     d  XML_SCHEMAS_IDREF...
     d                 c                   24
     d  XML_SCHEMAS_IDREFS...
     d                 c                   25
     d  XML_SCHEMAS_ENTITY...
     d                 c                   26
     d  XML_SCHEMAS_ENTITIES...
     d                 c                   27
     d  XML_SCHEMAS_NOTATION...
     d                 c                   28
     d  XML_SCHEMAS_ANYURI...
     d                 c                   29
     d  XML_SCHEMAS_INTEGER...
     d                 c                   30
     d  XML_SCHEMAS_NPINTEGER...
     d                 c                   31
     d  XML_SCHEMAS_NINTEGER...
     d                 c                   32
     d  XML_SCHEMAS_NNINTEGER...
     d                 c                   33
     d  XML_SCHEMAS_PINTEGER...
     d                 c                   34
     d  XML_SCHEMAS_INT...
     d                 c                   35
     d  XML_SCHEMAS_UINT...
     d                 c                   36
     d  XML_SCHEMAS_LONG...
     d                 c                   37
     d  XML_SCHEMAS_ULONG...
     d                 c                   38
     d  XML_SCHEMAS_SHORT...
     d                 c                   39
     d  XML_SCHEMAS_USHORT...
     d                 c                   40
     d  XML_SCHEMAS_BYTE...
     d                 c                   41
     d  XML_SCHEMAS_UBYTE...
     d                 c                   42
     d  XML_SCHEMAS_HEXBINARY...
     d                 c                   43
     d  XML_SCHEMAS_BASE64BINARY...
     d                 c                   44
     d  XML_SCHEMAS_ANYTYPE...
     d                 c                   45
     d  XML_SCHEMAS_ANYSIMPLETYPE...
     d                 c                   46

      * XML Schemas defines multiple type of types.

     d xmlSchemaTypeType...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_SCHEMA_TYPE_BASIC...                                                A builtin datatype
     d                 c                   1
     d  XML_SCHEMA_TYPE_ANY...
     d                 c                   2
     d  XML_SCHEMA_TYPE_FACET...
     d                 c                   3
     d  XML_SCHEMA_TYPE_SIMPLE...
     d                 c                   4
     d  XML_SCHEMA_TYPE_COMPLEX...
     d                 c                   5
     d  XML_SCHEMA_TYPE_SEQUENCE...
     d                 c                   6
     d  XML_SCHEMA_TYPE_CHOICE...
     d                 c                   7
     d  XML_SCHEMA_TYPE_ALL...
     d                 c                   8
     d  XML_SCHEMA_TYPE_SIMPLE_CONTENT...
     d                 c                   9
     d  XML_SCHEMA_TYPE_COMPLEX_CONTENT...
     d                 c                   10
     d  XML_SCHEMA_TYPE_UR...
     d                 c                   11
     d  XML_SCHEMA_TYPE_RESTRICTION...
     d                 c                   12
     d  XML_SCHEMA_TYPE_EXTENSION...
     d                 c                   13
     d  XML_SCHEMA_TYPE_ELEMENT...
     d                 c                   14
     d  XML_SCHEMA_TYPE_ATTRIBUTE...
     d                 c                   15
     d  XML_SCHEMA_TYPE_ATTRIBUTEGROUP...
     d                 c                   16
     d  XML_SCHEMA_TYPE_GROUP...
     d                 c                   17
     d  XML_SCHEMA_TYPE_NOTATION...
     d                 c                   18
     d  XML_SCHEMA_TYPE_LIST...
     d                 c                   19
     d  XML_SCHEMA_TYPE_UNION...
     d                 c                   20
     d  XML_SCHEMA_TYPE_ANY_ATTRIBUTE...
     d                 c                   21
     d  XML_SCHEMA_TYPE_IDC_UNIQUE...
     d                 c                   22
     d  XML_SCHEMA_TYPE_IDC_KEY...
     d                 c                   23
     d  XML_SCHEMA_TYPE_IDC_KEYREF...
     d                 c                   24
     d  XML_SCHEMA_TYPE_PARTICLE...
     d                 c                   25
     d  XML_SCHEMA_TYPE_ATTRIBUTE_USE...
     d                 c                   26
     d  XML_SCHEMA_FACET_MININCLUSIVE...
     d                 c                   1000
     d  XML_SCHEMA_FACET_MINEXCLUSIVE...
     d                 c                   1001
     d  XML_SCHEMA_FACET_MAXINCLUSIVE...
     d                 c                   1002
     d  XML_SCHEMA_FACET_MAXEXCLUSIVE...
     d                 c                   1003
     d  XML_SCHEMA_FACET_TOTALDIGITS...
     d                 c                   1004
     d  XML_SCHEMA_FACET_FRACTIONDIGITS...
     d                 c                   1005
     d  XML_SCHEMA_FACET_PATTERN...
     d                 c                   1006
     d  XML_SCHEMA_FACET_ENUMERATION...
     d                 c                   1007
     d  XML_SCHEMA_FACET_WHITESPACE...
     d                 c                   1008
     d  XML_SCHEMA_FACET_LENGTH...
     d                 c                   1009
     d  XML_SCHEMA_FACET_MAXLENGTH...
     d                 c                   1010
     d  XML_SCHEMA_FACET_MINLENGTH...
     d                 c                   1011
     d  XML_SCHEMA_EXTRA_QNAMEREF...
     d                 c                   2000
     d  XML_SCHEMA_EXTRA_ATTR_USE_PROHIB...
     d                 c                   2001

     d xmlSchemaContentType...
     d                 s                   based(######typedef######)
     d                                     like(xmlCenum)
     d  XML_SCHEMA_CONTENT_UNKNOWN...
     d                 c                   0
     d  XML_SCHEMA_CONTENT_EMPTY...
     d                 c                   1
     d  XML_SCHEMA_CONTENT_ELEMENTS...
     d                 c                   2
     d  XML_SCHEMA_CONTENT_MIXED...
     d                 c                   3
     d  XML_SCHEMA_CONTENT_SIMPLE...
     d                 c                   4
     d  XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS...                                 Obsolete
     d                 c                   5
     d  XML_SCHEMA_CONTENT_BASIC...
     d                 c                   6
     d  XML_SCHEMA_CONTENT_ANY...
     d                 c                   7

     d xmlSchemaValPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaTypePtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaFacetPtr...
     d                 s               *   based(######typedef######)

      * Annotation

     d xmlSchemaAnnotPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaAnnot  ds                  based(xmlSchemaAnnotPtr)
     d                                     align qualified
     d  next                               like(xmlSchemaAnnotPtr)
     d  content                            like(xmlNodePtr)                     The annotation

      * XML_SCHEMAS_ANYATTR_SKIP:
      *
      * Skip unknown attribute from validation
      * Obsolete, not used anymore.

     d XML_SCHEMAS_ANYATTR_SKIP...
     d                 c                   1

      * XML_SCHEMAS_ANYATTR_LAX:
      *
      * Ignore validation non definition on attributes
      * Obsolete, not used anymore.

     d XML_SCHEMAS_ANYATTR_LAX...
     d                 c                   2

      * XML_SCHEMAS_ANYATTR_STRICT:
      *
      * Apply strict validation rules on attributes
      * Obsolete, not used anymore.

     d XML_SCHEMAS_ANYATTR_STRICT...
     d                 c                   3

      * XML_SCHEMAS_ANY_SKIP:
      *
      * Skip unknown attribute from validation

     d XML_SCHEMAS_ANY_SKIP...
     d                 c                   1

      * XML_SCHEMAS_ANY_LAX:
      *
      * Used by wildcards.
      * Validate if type found, don't worry if not found

     d XML_SCHEMAS_ANY_LAX...
     d                 c                   2

      * XML_SCHEMAS_ANY_STRICT:
      *
      * Used by wildcards.
      * Apply strict validation rules

     d XML_SCHEMAS_ANY_STRICT...
     d                 c                   3

      * XML_SCHEMAS_ATTR_USE_PROHIBITED:
      *
      * Used by wildcards.
      * The attribute is prohibited.

     d XML_SCHEMAS_ATTR_USE_PROHIBITED...
     d                 c                   0

      * XML_SCHEMAS_ATTR_USE_REQUIRED:
      *
      * The attribute is required.

     d XML_SCHEMAS_ATTR_USE_REQUIRED...
     d                 c                   1

      * XML_SCHEMAS_ATTR_USE_OPTIONAL:
      *
      * The attribute is optional.

     d XML_SCHEMAS_ATTR_USE_OPTIONAL...
     d                 c                   2

      * XML_SCHEMAS_ATTR_GLOBAL:
      *
      * allow elements in no namespace

     d XML_SCHEMAS_ATTR_GLOBAL...
     d                 c                   X'0001'

      * XML_SCHEMAS_ATTR_NSDEFAULT:
      *
      * allow elements in no namespace

     d XML_SCHEMAS_ATTR_NSDEFAULT...
     d                 c                   X'0080'

      * XML_SCHEMAS_ATTR_INTERNAL_RESOLVED:
      *
      * this is set when the "type" and "ref" references
      * have been resolved.

     d XML_SCHEMAS_ATTR_INTERNAL_RESOLVED...
     d                 c                   X'0100'

      * XML_SCHEMAS_ATTR_FIXED:
      *
      * the attribute has a fixed value

     d XML_SCHEMAS_ATTR_FIXED...
     d                 c                   X'0200'

      * xmlSchemaAttribute:
      * An attribute definition.

     d xmlSchemaAttributePtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaAttribute...
     d                 ds                  based(xmlSchemaAttributePtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)
     d  next                               like(xmlSchemaAttributePtr)          Next attribute
     d  name                           *                                        const xmlChar *
     d  id                             *                                        const xmlChar *
     d  ref                            *                                        const xmlChar *
     d  refNs                          *                                        const xmlChar *
     d  typeName                       *                                        const xmlChar *
     d  typeNs                         *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
      *
     d  base                               like(xmlSchemaTypePtr)               Deprecated
     d  occurs                             like(xmlCint)                        Deprecated
     d  defValue                       *                                        const xmlChar *
     d  subtypes                           like(xmlSchemaTypePtr)               The type definition
     d  node                               like(xmlNodePtr)
     d  targetNamespace...                                                      const xmlChar *
     d                                 *
     d  flags                              like(xmlCint)
     d  refPrefix                      *                                        const xmlChar *
     d  defVal                             like(xmlSchemaValPtr)                Compiled constraint
     d  refDecl                            like(xmlSchemaAttributePtr)          Deprecated

      * xmlSchemaAttributeLink:
      * Used to build a list of attribute uses on complexType definitions.
      * WARNING: Deprecated; not used.

     d xmlSchemaAttributeLinkPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaAttributeLink...
     d                 ds                  based(xmlSchemaAttributeLinkPtr)
     d                                     align qualified
     d  next                               like(xmlSchemaAttributeLinkPtr)      The next link
     d  attr                               like(xmlSchemaAttributePtr)          The linked attribute

      * XML_SCHEMAS_WILDCARD_COMPLETE:
      *
      * If the wildcard is complete.

     d XML_SCHEMAS_WILDCARD_COMPLETE...
     d                 c                   X'0001'

      * xmlSchemaCharValueLink:
      * Used to build a list of namespaces on wildcards.

     d xmlSchemaWildcardNsPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaWildcardNs...
     d                 ds                  based(xmlSchemaWildcardNsPtr)
     d                                     align qualified
     d  next                               like(xmlSchemaWildcardNsPtr)         The next link
     d  value                          *                                        const xmlChar *

      * xmlSchemaWildcard.
      * A wildcard.

     d xmlSchemaWildcardPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaWildcard...
     d                 ds                  based(xmlSchemaWildcardPtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)              Kind of type
     d  id                             *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
     d  node                               like(xmlNodePtr)
     d  minOccurs                          like(xmlCint)                        Deprecated; not used
     d  maxOccurs                          like(xmlCint)                        Deprecated; not used
     d  processContents...
     d                                     like(xmlCint)
     d  any                                like(xmlCint)                        Ns constraint ##any?
     d  nsSet                              like(xmlSchemaWildcardNsPtr)         Allowed namspce list
     d  negNsSet                           like(xmlSchemaWildcardNsPtr)         Negated namespace
     d  flags                              like(xmlCint)                        Deprecated; not used

      * XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED:
      *
      * The attribute wildcard has been already builded.

     d XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED...
     d                 c                   X'0001'

      * XML_SCHEMAS_ATTRGROUP_GLOBAL:
      *
      * The attribute wildcard has been already builded.

     d XML_SCHEMAS_ATTRGROUP_GLOBAL...
     d                 c                   X'0002'

      * XML_SCHEMAS_ATTRGROUP_MARKED:
      *
      * Marks the attr group as marked; used for circular checks.

     d XML_SCHEMAS_ATTRGROUP_MARKED...
     d                 c                   X'0004'

      * XML_SCHEMAS_ATTRGROUP_REDEFINED:
      *
      * The attr group was redefined.

     d XML_SCHEMAS_ATTRGROUP_REDEFINED...
     d                 c                   X'0008'

      * XML_SCHEMAS_ATTRGROUP_HAS_REFS:
      *
      * Whether this attr. group contains attr. group references.

     d XML_SCHEMAS_ATTRGROUP_HAS_REFS...
     d                 c                   X'0010'

      * An attribute group definition.
      *
      * xmlSchemaAttribute and xmlSchemaAttributeGroup start of structures
      * must be kept similar

     d xmlSchemaAttributeGroupPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaAttributeGroup...
     d                 ds                  based(xmlSchemaAttributeGroupPtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)              Kind of type
     d  next                               like(xmlSchemaAttributePtr)          Next attribute
     d  name                           *                                        const xmlChar *
     d  id                             *                                        const xmlChar *
     d  ref                            *                                        const xmlChar *
     d  refNs                          *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
      *
     d  attributes                         like(xmlSchemaAttributePtr)          Deprecated; not used
     d  node                               like(xmlNodePtr)
     d  flags                              like(xmlCint)
     d  attributeWildcard...
     d                                     like(xmlSchemaWildcardPtr)
     d  refPrefix                      *                                        const xmlChar *
     d  refItem                            like(xmlSchemaAttributeGroupPtr)     Deprecated; not used
     d  targetNamespace...
     d                                 *                                        const xmlChar *
     d  attrUses                       *                                        void *

      * xmlSchemaTypeLink:
      * Used to build a list of types (e.g. member types of
      * simpleType with variety "union").

     d xmlSchemaTypeLinkPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaTypeLink...
     d                 ds                  based(xmlSchemaTypeLinkPtr)
     d                                     align qualified
     d  next                               like(xmlSchemaTypeLinkPtr)           Next type link
     d  type                               like(xmlSchemaTypePtr)               Linked type

      * xmlSchemaFacetLink:
      * Used to build a list of facets.

     d xmlSchemaFacetLinkPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaFacetLink...
     d                 ds                  based(xmlSchemaFacetLinkPtr)
     d                                     align qualified
     d  next                               like(xmlSchemaFacetLinkPtr)          Next facet link
     d  facet                              like(xmlSchemaFacetPtr)              Linked facet

      * XML_SCHEMAS_TYPE_MIXED:
      *
      * the element content type is mixed

     d XML_SCHEMAS_TYPE_MIXED...
     d                 c                   X'00000001'

      * XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION:
      *
      * the simple or complex type has a derivation method of "extension".

     d XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION...
     d                 c                   X'00000002'

      * XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION:
      *
      * the simple or complex type has a derivation method of "restriction".

     d XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION...
     d                 c                   X'00000004'

      * XML_SCHEMAS_TYPE_GLOBAL:
      *
      * the type is global

     d XML_SCHEMAS_TYPE_GLOBAL...
     d                 c                   X'00000008'

      * XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD:
      *
      * the complexType owns an attribute wildcard, i.e.
      * it can be freed by the complexType

     d XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD...                                  Obsolete.
     d                 c                   X'00000010'

      * XML_SCHEMAS_TYPE_VARIETY_ABSENT:
      *
      * the simpleType has a variety of "absent".
      * TODO: Actually not necessary :-/, since if
      * none of the variety flags occur then it's
      * automatically absent.

     d XML_SCHEMAS_TYPE_VARIETY_ABSENT...
     d                 c                   X'00000020'

      * XML_SCHEMAS_TYPE_VARIETY_LIST:
      *
      * the simpleType has a variety of "list".

     d XML_SCHEMAS_TYPE_VARIETY_LIST...
     d                 c                   X'00000040'

      * XML_SCHEMAS_TYPE_VARIETY_UNION:
      *
      * the simpleType has a variety of "union".

     d XML_SCHEMAS_TYPE_VARIETY_UNION...
     d                 c                   X'00000080'

      * XML_SCHEMAS_TYPE_VARIETY_ATOMIC:
      *
      * the simpleType has a variety of "union".

     d XML_SCHEMAS_TYPE_VARIETY_ATOMIC...
     d                 c                   X'00000100'

      * XML_SCHEMAS_TYPE_FINAL_EXTENSION:
      *
      * the complexType has a final of "extension".

     d XML_SCHEMAS_TYPE_FINAL_EXTENSION...
     d                 c                   X'00000200'

      * XML_SCHEMAS_TYPE_FINAL_RESTRICTION:
      *
      * the simpleType/complexType has a final of "restriction".

     d XML_SCHEMAS_TYPE_FINAL_RESTRICTION...
     d                 c                   X'00000400'

      * XML_SCHEMAS_TYPE_FINAL_LIST:
      *
      * the simpleType has a final of "list".

     d XML_SCHEMAS_TYPE_FINAL_LIST...
     d                 c                   X'00000800'

      * XML_SCHEMAS_TYPE_FINAL_UNION:
      *
      * the simpleType has a final of "union".

     d XML_SCHEMAS_TYPE_FINAL_UNION...
     d                 c                   X'00001000'

      * XML_SCHEMAS_TYPE_FINAL_DEFAULT:
      *
      * the simpleType has a final of "default".

     d XML_SCHEMAS_TYPE_FINAL_DEFAULT...
     d                 c                   X'00002000'

      * XML_SCHEMAS_TYPE_BUILTIN_PRIMITIVE:
      *
      * Marks the item as a builtin primitive.

     d XML_SCHEMAS_TYPE_BUILTIN_PRIMITIVE...
     d                 c                   X'00004000'

      * XML_SCHEMAS_TYPE_MARKED:
      *
      * Marks the item as marked; used for circular checks.

     d XML_SCHEMAS_TYPE_MARKED...
     d                 c                   X'00010000'

      * XML_SCHEMAS_TYPE_BLOCK_DEFAULT:
      *
      * the complexType did not specify 'block' so use the default of the
      * <schema> item.

     d XML_SCHEMAS_TYPE_BLOCK_DEFAULT...
     d                 c                   X'00020000'

      * XML_SCHEMAS_TYPE_BLOCK_EXTENSION:
      *
      * the complexType has a 'block' of "extension".

     d XML_SCHEMAS_TYPE_BLOCK_EXTENSION...
     d                 c                   X'00040000'

      * XML_SCHEMAS_TYPE_BLOCK_RESTRICTION:
      *
      * the complexType has a 'block' of "restriction".

     d XML_SCHEMAS_TYPE_BLOCK_RESTRICTION...
     d                 c                   X'00080000'

      * XML_SCHEMAS_TYPE_ABSTRACT:
      *
      * the simple/complexType is abstract.

     d XML_SCHEMAS_TYPE_ABSTRACT...
     d                 c                   X'00100000'

      * XML_SCHEMAS_TYPE_FACETSNEEDVALUE:
      *
      * indicates if the facets need a computed value

     d XML_SCHEMAS_TYPE_FACETSNEEDVALUE...
     d                 c                   X'00200000'

      * XML_SCHEMAS_TYPE_INTERNAL_RESOLVED:
      *
      * indicates that the type was typefixed

     d XML_SCHEMAS_TYPE_INTERNAL_RESOLVED...
     d                 c                   X'00400000'

      * XML_SCHEMAS_TYPE_INTERNAL_INVALID:
      *
      * indicates that the type is invalid

     d XML_SCHEMAS_TYPE_INTERNAL_INVALID...
     d                 c                   X'00800000'

      * XML_SCHEMAS_TYPE_WHITESPACE_PRESERVE:
      *
      * a whitespace-facet value of "preserve"

     d XML_SCHEMAS_TYPE_WHITESPACE_PRESERVE...
     d                 c                   X'01000000'

      * XML_SCHEMAS_TYPE_WHITESPACE_REPLACE:
      *
      * a whitespace-facet value of "replace"

     d XML_SCHEMAS_TYPE_WHITESPACE_REPLACE...
     d                 c                   X'02000000'

      * XML_SCHEMAS_TYPE_WHITESPACE_COLLAPSE:
      *
      * a whitespace-facet value of "collapse"

     d XML_SCHEMAS_TYPE_WHITESPACE_COLLAPSE...
     d                 c                   X'04000000'

      * XML_SCHEMAS_TYPE_HAS_FACETS:
      *
      * has facets

     d XML_SCHEMAS_TYPE_HAS_FACETS...
     d                 c                   X'08000000'

      * XML_SCHEMAS_TYPE_NORMVALUENEEDED:
      *
      * indicates if the facets (pattern) need a normalized value

     d XML_SCHEMAS_TYPE_NORMVALUENEEDED...
     d                 c                   X'10000000'

      * XML_SCHEMAS_TYPE_FIXUP_1:
      *
      * First stage of fixup was done.

     d XML_SCHEMAS_TYPE_FIXUP_1...
     d                 c                   X'20000000'

      * XML_SCHEMAS_TYPE_REDEFINED:
      *
      * The type was redefined.

     d XML_SCHEMAS_TYPE_REDEFINED...
     d                 c                   X'40000000'

      /if defined(DISABLED)
      * XML_SCHEMAS_TYPE_REDEFINING:
      *
      * The type redefines an other type.

     d XML_SCHEMAS_TYPE_REDEFINING...
     d                 c                   X'80000000'
      /endif

      * _xmlSchemaType:
      *
      * Schemas type definition.

     d xmlSchemaType...
     d                 ds                  based(xmlSchemaTypePtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)              Kind of type
     d  next                               like(xmlSchemaTypePtr)               Next type
     d  name                           *                                        const xmlChar *
     d  id                             *                                        const xmlChar *
     d  ref                            *                                        const xmlChar *
     d  refNs                          *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
     d  subtypes                           like(xmlSchemaTypePtr)
     d  attributes                         like(xmlSchemaAttributePtr)          Deprecated; not used
     d  node                               like(xmlNodePtr)
     d  minOccurs                          like(xmlCint)                        Deprecated; not used
     d  maxOccurs                          like(xmlCint)                        Deprecated; not used
      *
     d  flags                              like(xmlCint)
     d  contentType                        like(xmlSchemaContentType)
     d  base                           *                                        const xmlChar *
     d  baseNs                         *                                        const xmlChar *
     d  baseType                           like(xmlSchemaTypePtr)               Base type component
     d  facets                             like(xmlSchemaFacetPtr)              Local facets
     d  redef                              like(xmlSchemaTypePtr)               Deprecated; not used
     d  recurse                            like(xmlCint)                        Obsolete
     d  attributeUses                      like(xmlSchemaAttributeLinkPtr)      Deprecated; not used
     d  attributeWildcard...
     d                                     like(xmlSchemaWildcardPtr)
     d  builtInType                        like(xmlCint)                        Built-in types type
     d  memberTypes                        like(xmlSchemaTypeLinkPtr)           Union member-types
     d  facetSet                           like(xmlSchemaFacetLinkPtr)          All facets
     d  refPrefix                      *                                        const xmlChar *
     d  contentTypeDef...
     d                                     like(xmlSchemaTypePtr)
     d  contModel                          like(xmlRegexpPtr)                   Content model autom.
     d  targetNamespace...
     d                                 *                                        const xmlChar *
     d  attrUses                       *                                        void *

      * xmlSchemaElement:
      * An element definition.
      *
      * xmlSchemaType, xmlSchemaFacet and xmlSchemaElement start of
      * structures must be kept similar

      * XML_SCHEMAS_ELEM_NILLABLE:
      *
      * the element is nillable

     d XML_SCHEMAS_ELEM_NILLABLE...
     d                 c                   X'00000001'

      * XML_SCHEMAS_ELEM_GLOBAL:
      *
      * the element is global

     d XML_SCHEMAS_ELEM_GLOBAL...
     d                 c                   X'00000002'

      * XML_SCHEMAS_ELEM_DEFAULT:
      *
      * the element has a default value

     d XML_SCHEMAS_ELEM_DEFAULT...
     d                 c                   X'00000004'

      * XML_SCHEMAS_ELEM_FIXED:
      *
      * the element has a fixed value

     d XML_SCHEMAS_ELEM_FIXED...
     d                 c                   X'00000008'

      * XML_SCHEMAS_ELEM_ABSTRACT:
      *
      * the element is abstract

     d XML_SCHEMAS_ELEM_ABSTRACT...
     d                 c                   X'00000010'

      * XML_SCHEMAS_ELEM_TOPLEVEL:
      *
      * the element is top level
      * obsolete: use XML_SCHEMAS_ELEM_GLOBAL instead

     d XML_SCHEMAS_ELEM_TOPLEVEL...
     d                 c                   X'00000020'

      * XML_SCHEMAS_ELEM_REF:
      *
      * the element is a reference to a type

     d XML_SCHEMAS_ELEM_REF...
     d                 c                   X'00000040'

      * XML_SCHEMAS_ELEM_NSDEFAULT:
      *
      * allow elements in no namespace
      * Obsolete, not used anymore.

     d XML_SCHEMAS_ELEM_NSDEFAULT...
     d                 c                   X'00000080'

      * XML_SCHEMAS_ELEM_INTERNAL_RESOLVED:
      *
      * this is set when "type", "ref", "substitutionGroup"
      * references have been resolved.

     d XML_SCHEMAS_ELEM_INTERNAL_RESOLVED...
     d                 c                   X'00000100'

      * XML_SCHEMAS_ELEM_CIRCULAR:
      *
      * a helper flag for the search of circular references.

     d XML_SCHEMAS_ELEM_CIRCULAR...
     d                 c                   X'00000200'

      * XML_SCHEMAS_ELEM_BLOCK_ABSENT:
      *
      * the "block" attribute is absent

     d XML_SCHEMAS_ELEM_BLOCK_ABSENT...
     d                 c                   X'00000400'

      * XML_SCHEMAS_ELEM_BLOCK_EXTENSION:
      *
      * disallowed substitutions are absent

     d XML_SCHEMAS_ELEM_BLOCK_EXTENSION...
     d                 c                   X'00000800'

      * XML_SCHEMAS_ELEM_BLOCK_RESTRICTION:
      *
      * disallowed substitutions: "restriction"

     d XML_SCHEMAS_ELEM_BLOCK_RESTRICTION...
     d                 c                   X'00001000'

      * XML_SCHEMAS_ELEM_BLOCK_SUBSTITUTION:
      *
      * disallowed substitutions: "substituion"

     d XML_SCHEMAS_ELEM_BLOCK_SUBSTITUTION...
     d                 c                   X'00002000'

      * XML_SCHEMAS_ELEM_FINAL_ABSENT:
      *
      * substitution group exclusions are absent

     d XML_SCHEMAS_ELEM_FINAL_ABSENT...
     d                 c                   X'00004000'

      * XML_SCHEMAS_ELEM_FINAL_EXTENSION:
      *
      * substitution group exclusions: "extension"

     d XML_SCHEMAS_ELEM_FINAL_EXTENSION...
     d                 c                   X'00008000'

      * XML_SCHEMAS_ELEM_FINAL_RESTRICTION:
      *
      * substitution group exclusions: "restriction"

     d XML_SCHEMAS_ELEM_FINAL_RESTRICTION...
     d                 c                   X'00010000'

      * XML_SCHEMAS_ELEM_SUBST_GROUP_HEAD:
      *
      * the declaration is a substitution group head

     d XML_SCHEMAS_ELEM_SUBST_GROUP_HEAD...
     d                 c                   X'00020000'

      * XML_SCHEMAS_ELEM_INTERNAL_CHECKED:
      *
      * this is set when the elem decl has been checked against
      * all constraints

     d XML_SCHEMAS_ELEM_INTERNAL_CHECKED...
     d                 c                   X'00040000'

     d xmlSchemaElementPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaElement...
     d                 ds                  based(xmlSchemaElementPtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)              Kind of type
     d  next                               like(xmlSchemaElementPtr)            Not used ?
     d  name                           *                                        const xmlChar *
     d  id                             *                                        const xmlChar *
     d  ref                            *                                        const xmlChar *
     d  refNs                          *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
     d  subtypes                           like(xmlSchemaTypePtr)
     d  attributes                         like(xmlSchemaAttributePtr)          Deprecated; not used
     d  node                               like(xmlNodePtr)
     d  minOccurs                          like(xmlCint)                        Deprecated; not used
     d  maxOccurs                          like(xmlCint)                        Deprecated; not used
      *
     d  flags                              like(xmlCint)
     d  targetNamespace...
     d                                 *                                        const xmlChar *
     d  namedType                      *                                        const xmlChar *
     d  namedTypeNs                    *                                        const xmlChar *
     d  substGroup                     *                                        const xmlChar *
     d  substGroupNs                   *                                        const xmlChar *
     d  scope                          *                                        const xmlChar *
     d  value                          *                                        const xmlChar *
     d  refDecl                            like(xmlSchemaElementPtr)
     d  contModel                          like(xmlRegexpPtr)
     d  contentType                        like(xmlSchemaContentType)
     d  refPrefix                      *                                        const xmlChar *
     d  devVal                             like(xmlSchemaValPtr)                Comp val constraint
     d  idcs                           *                                        void *

      * XML_SCHEMAS_FACET_UNKNOWN:
      *
      * unknown facet handling

     d XML_SCHEMAS_FACET_UNKNOWN...
     d                 c                   0

      * XML_SCHEMAS_FACET_PRESERVE:
      *
      * preserve the type of the facet

     d XML_SCHEMAS_FACET_PRESERVE...
     d                 c                   1

      * XML_SCHEMAS_FACET_REPLACE:
      *
      * replace the type of the facet

     d XML_SCHEMAS_FACET_REPLACE...
     d                 c                   2

      * XML_SCHEMAS_FACET_COLLAPSE:
      *
      * collapse the types of the facet

     d XML_SCHEMAS_FACET_COLLAPSE...
     d                 c                   3

      * A facet definition.

     d xmlSchemaFacet...
     d                 ds                  based(xmlSchemaFacetPtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)              Kind of type
     d  next                               like(xmlSchemaFacetPtr)              Next type in seq.
     d  value                          *                                        const xmlChar *
     d  id                             *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
     d  node                               like(xmlNodePtr)
     d  fixed                              like(xmlCint)                        _FACET_PRESERVE, etc
     d  whitespace                         like(xmlCint)
     d  val                                like(xmlSchemaValPtr)                Compiled value
     d  regexp                             like(xmlRegexpPtr)                   Regexp for patterns

      * A notation definition.

     d xmlSchemaNotationPtr...
     d                 s               *   based(######typedef######)

     d xmlSchemaNotation...
     d                 ds                  based(xmlSchemaNotationPtr)
     d                                     align qualified
     d  type                               like(xmlSchemaTypeType)              Kind of type
     d  name                           *                                        const xmlChar *
     d  annot                              like(xmlSchemaAnnotPtr)
     d  identifier                     *                                        const xmlChar *
     d  targetNamespace...
     d                                 *                                        const xmlChar *

      * TODO: Actually all those flags used for the schema should sit
      * on the schema parser context, since they are used only
      * during parsing an XML schema document, and not available
      * on the component level as per spec.

      * XML_SCHEMAS_QUALIF_ELEM:
      *
      * Reflects elementFormDefault == qualified in
      * an XML schema document.

     d XML_SCHEMAS_QUALIF_ELEM...
     d                 c                   X'00000001'

      * XML_SCHEMAS_QUALIF_ATTR:
      *
      * Reflects attributeFormDefault == qualified in
      * an XML schema document.

     d XML_SCHEMAS_QUALIF_ATTR...
     d                 c                   X'00000002'

      * XML_SCHEMAS_FINAL_DEFAULT_EXTENSION:
      *
      * the schema has "extension" in the set of finalDefault.

     d XML_SCHEMAS_FINAL_DEFAULT_EXTENSION...
     d                 c                   X'00000004'

      * XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION:
      *
      * the schema has "restriction" in the set of finalDefault.

     d XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION...
     d                 c                   X'00000008'

      * XML_SCHEMAS_FINAL_DEFAULT_LIST:
      *
      * the cshema has "list" in the set of finalDefault.

     d XML_SCHEMAS_FINAL_DEFAULT_LIST...
     d                 c                   X'00000010'

      * XML_SCHEMAS_FINAL_DEFAULT_UNION:
      *
      * the schema has "union" in the set of finalDefault.

     d XML_SCHEMAS_FINAL_DEFAULT_UNION...
     d                 c                   X'00000020'

      * XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION:
      *
      * the schema has "extension" in the set of blockDefault.

     d XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION...
     d                 c                   X'00000040'

      * XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION:
      *
      * the schema has "restriction" in the set of blockDefault.

     d XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION...
     d                 c                   X'00000080'

      * XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION:
      *
      * the schema has "substitution" in the set of blockDefault.

     d XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION...
     d                 c                   X'00000100'

      * XML_SCHEMAS_INCLUDING_CONVERT_NS:
      *
      * the schema is currently including an other schema with
      * no target namespace.

     d XML_SCHEMAS_INCLUDING_CONVERT_NS...
     d                 c                   X'00000200'

      * _xmlSchema:
      *
      * A Schemas definition

     d xmlSchema       ds                  based(xmlSchemaPtr)
     d                                     align qualified
     d  name                           *                                        const xmlChar *
     d  targetNamespace...
     d                                 *                                        const xmlChar *
     d  version                        *                                        const xmlChar *
     d  id                             *                                        const xmlChar *
     d  doc                                like(xmlDocPtr)
     d  annot                              like(xmlSchemaAnnotPtr)
     d  flags                              like(xmlCint)
      *
     d  typeDecl                           like(xmlHashTablePtr)
     d  attrDecl                           like(xmlHashTablePtr)
     d  attrGrpDecl                        like(xmlHashTablePtr)
     d  elemDecl                           like(xmlHashTablePtr)
     d  notaDecl                           like(xmlHashTablePtr)
     d  schemasImports...
     d                                     like(xmlHashTablePtr)
      *
     d  #private                       *                                        void *
     d  groupDecl                          like(xmlHashTablePtr)
     d  dict                               like(xmlDictPtr)
     d  includes                       *                                        void *
     d  preserve                           like(xmlCint)                        Do not free doc ?
     d  counter                            like(xmlCint)                        For name uniqueness
     d  idcDef                             like(xmlHashTablePtr)                All id-constr. defs
     d  volatiles                      *                                        void *

     d xmlSchemaFreeType...
     d                 pr                  extproc('xmlSchemaFreeType')
     d type                                value like(xmlSchemaTypePtr)

     d xmlSchemaFreeWildcard...
     d                 pr                  extproc('xmlSchemaFreeWildcard')
     d wildcard                            value like(xmlSchemaWildcardPtr)

      /endif                                                                    LIBXML_SCHEMAS_ENBLD
      /endif                                                                    SCHEMA_INTERNALS_H__
