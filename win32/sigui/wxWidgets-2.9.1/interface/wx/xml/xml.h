/////////////////////////////////////////////////////////////////////////////
// Name:        xml/xml.h
// Purpose:     interface of wxXmlNode, wxXmlAttribute, wxXmlDocument
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/// Represents XML node type.
enum wxXmlNodeType
{
    // note: values are synchronized with xmlElementType from libxml
    wxXML_ELEMENT_NODE       =  1,
    wxXML_ATTRIBUTE_NODE     =  2,
    wxXML_TEXT_NODE          =  3,
    wxXML_CDATA_SECTION_NODE =  4,
    wxXML_ENTITY_REF_NODE    =  5,
    wxXML_ENTITY_NODE        =  6,
    wxXML_PI_NODE            =  7,
    wxXML_COMMENT_NODE       =  8,
    wxXML_DOCUMENT_NODE      =  9,
    wxXML_DOCUMENT_TYPE_NODE = 10,
    wxXML_DOCUMENT_FRAG_NODE = 11,
    wxXML_NOTATION_NODE      = 12,
    wxXML_HTML_DOCUMENT_NODE = 13
};

/**
    @class wxXmlNode

    Represents a node in an XML document. See wxXmlDocument.

    Node has a name and may have content and attributes.

    Most common node types are @c wxXML_TEXT_NODE (name and attributes are irrelevant)
    and @c wxXML_ELEMENT_NODE.

    Example: in <tt>\<title\>hi\</title\></tt> there is an element with the name
    @c title and irrelevant content and one child of type @c wxXML_TEXT_NODE
    with @c hi as content.

    If @c wxUSE_UNICODE is 0, all strings are encoded in the encoding given to
    wxXmlDocument::Load (default is UTF-8).

    @library{wxxml}
    @category{xml}

    @see wxXmlDocument, wxXmlAttribute
*/
class wxXmlNode
{
public:
    /**
        Creates this XML node and eventually insert it into an existing XML tree.

        @param parent
            The parent node to which append this node instance.
            If this argument is @NULL this new node will be floating and it can
            be appended later to another one using the AddChild() or InsertChild()
            functions. Otherwise the child is already added to the XML tree by
            this constructor and it shouldn't be done again.
        @param type
            One of the ::wxXmlNodeType enumeration value.
        @param name
            The name of the node. This is the string which appears between angular brackets.
        @param content
            The content of the node.
            Only meaningful when type is @c wxXML_TEXT_NODE or @c wxXML_CDATA_SECTION_NODE.
        @param attrs
            If not @NULL, this wxXmlAttribute object and its eventual siblings are attached to the node.
        @param next
            If not @NULL, this node and its eventual siblings are attached to the node.
        @param lineNo
            Number of line this node was present at in input file or -1.
    */
    wxXmlNode(wxXmlNode* parent, wxXmlNodeType type,
              const wxString& name,
              const wxString& content = wxEmptyString,
              wxXmlAttribute* attrs = NULL,
              wxXmlNode* next = NULL, int lineNo = -1);

    /**
        A simplified version of the first constructor form, assuming a @NULL parent.

        @param type
            One of the ::wxXmlNodeType enumeration value.
        @param name
            The name of the node. This is the string which appears between angular brackets.
        @param content
            The content of the node.
            Only meaningful when type is @c wxXML_TEXT_NODE or @c wxXML_CDATA_SECTION_NODE.
        @param lineNo
            Number of line this node was present at in input file or -1.
    */
    wxXmlNode(wxXmlNodeType type, const wxString& name,
              const wxString& content = wxEmptyString,
              int lineNo = -1);

    /**
        Copy constructor.

        Note that this does NOT copy syblings and parent pointer, i.e. GetParent()
        and GetNext() will return @NULL after using copy ctor and are never unmodified by operator=().
        On the other hand, it DOES copy children and attributes.
    */
    wxXmlNode(const wxXmlNode& node);

    /**
        The virtual destructor. Deletes attached children and attributes.
    */
    virtual ~wxXmlNode();

    /**
        Appends a attribute with given @a name and @a value to the list of
        attributes for this node.
    */
    virtual void AddAttribute(const wxString& name, const wxString& value);

    /**
        Appends given attribute to the list of attributes for this node.
    */
    virtual void AddAttribute(wxXmlAttribute* attr);

    /**
        Adds node @a child as the last child of this node.

        @note
        Note that this function works in O(n) time where @e n is the number
        of existing children. Consequently, adding large number of child
        nodes using this method can be expensive, because it has O(n^2) time
        complexity in number of nodes to be added. Use InsertChildAfter() to
        populate XML tree in linear time.

        @see InsertChild(), InsertChildAfter()
    */
    virtual void AddChild(wxXmlNode* child);

    /**
        Removes the first attributes which has the given @a name from the list of
        attributes for this node.
    */
    virtual bool DeleteAttribute(const wxString& name);

    /**
        Returns true if a attribute named attrName could be found.
        The value of that attribute is saved in value (which must not be @NULL).
    */
    bool GetAttribute(const wxString& attrName, wxString* value) const;

    /**
        Returns the value of the attribute named @a attrName if it does exist.
        If it does not exist, the @a defaultVal is returned.
    */
    wxString GetAttribute(const wxString& attrName,
                          const wxString& defaultVal = wxEmptyString) const;

    /**
        Return a pointer to the first attribute of this node.
    */
    wxXmlAttribute* GetAttributes() const;

    /**
        Returns the first child of this node.
        To get a pointer to the second child of this node (if it does exist), use the
        GetNext() function on the returned value.
    */
    wxXmlNode* GetChildren() const;

    /**
        Returns the content of this node. Can be an empty string.
        Be aware that for nodes of type @c wxXML_ELEMENT_NODE (the most used node type)
        the content is an empty string. See GetNodeContent() for more details.
    */
    const wxString& GetContent() const;

    /**
        Returns the number of nodes which separe this node from @c grandparent.

        This function searches only the parents of this node until it finds
        @a grandparent or the @NULL node (which is the parent of non-linked
        nodes or the parent of a wxXmlDocument's root node).
    */
    int GetDepth(wxXmlNode* grandparent = NULL) const;

    /**
        Returns line number of the node in the input XML file or @c -1 if it is unknown.
    */
    int GetLineNumber() const;

    /**
        Returns the name of this node.
        Can be an empty string (e.g. for nodes of type @c wxXML_TEXT_NODE or
        @c wxXML_CDATA_SECTION_NODE).
    */
    const wxString& GetName() const;

    /**
        Returns a pointer to the sibling of this node or @NULL if there are no
        siblings.
    */
    wxXmlNode* GetNext() const;

    /**
        Returns the content of the first child node of type @c wxXML_TEXT_NODE
        or @c wxXML_CDATA_SECTION_NODE.
        This function is very useful since the XML snippet @c "tagnametagcontent/tagname"
        is represented by expat with the following tag tree:

        @code
        wxXML_ENTITY_NODE name="tagname", content=""
        |-- wxXML_TEXT_NODE name="", content="tagcontent"
        @endcode

        or eventually:

        @code
        wxXML_ENTITY_NODE name="tagname", content=""
        |-- wxXML_CDATA_SECTION_NODE name="", content="tagcontent"
        @endcode

        An empty string is returned if the node has no children of type
        @c wxXML_TEXT_NODE or @c wxXML_CDATA_SECTION_NODE, or if the content
        of the first child of such types is empty.
    */
    wxString GetNodeContent() const;

    /**
        Returns a pointer to the parent of this node or @NULL if this node has no
        parent.
    */
    wxXmlNode* GetParent() const;

    /**
        Returns the type of this node.
    */
    wxXmlNodeType GetType() const;

    /**
        Returns @true if this node has a attribute named @a attrName.
    */
    bool HasAttribute(const wxString& attrName) const;

    /**
        Inserts the @a child node immediately before @a followingNode in the
        children list.

        @return @true if @a followingNode has been found and the @a child
                node has been inserted.

        @note
        For historical reasons, @a followingNode may be @NULL. In that case,
        then @a child is prepended to the list of children and becomes the
        first child of this node, i.e. it behaves identically to using the
        first children (as returned by GetChildren()) for @a followingNode).

        @see AddChild(), InsertChildAfter()
    */
    virtual bool InsertChild(wxXmlNode* child, wxXmlNode* followingNode);

    /**
        Inserts the @a child node immediately after @a precedingNode in the
        children list.

        @return @true if @a precedingNode has been found and the @a child
                node has been inserted.

        @param child
            The child to insert.
        @param precedingNode
            The node to insert @a child after. As a special case, this can be
            @NULL if this node has no children yet -- in that case, @a child
            will become this node's only child node.

        @since 2.8.8

        @see InsertChild(), AddChild()
    */
    virtual bool InsertChildAfter(wxXmlNode* child, wxXmlNode* precedingNode);

    /**
        Returns @true if the content of this node is a string containing only
        whitespaces (spaces, tabs, new lines, etc).

        Note that this function is locale-independent since the parsing of XML
        documents must always produce the exact same tree regardless of the
        locale it runs under.
    */
    bool IsWhitespaceOnly() const;

    /**
        Removes the given node from the children list.

        Returns @true if the node was found and removed or @false if the node
        could not be found.
        Note that the caller is reponsible for deleting the removed node in order
        to avoid memory leaks.
    */
    virtual bool RemoveChild(wxXmlNode* child);

    /**
        Sets as first attribute the given wxXmlAttribute object.

        The caller is responsible to delete any previously present attributes
        attached to this node.
    */
    void SetAttributes(wxXmlAttribute* attr);

    /**
        Sets as first child the given node.

        The caller is responsible to delete any previously present children node.
    */
    void SetChildren(wxXmlNode* child);

    /**
        Sets the content of this node.
    */
    void SetContent(const wxString& con);

    /**
        Sets the name of this node.
    */
    void SetName(const wxString& name);

    /**
        Sets as sibling the given node.

        The caller is responsible to delete any previously present sibling node.
    */
    void SetNext(wxXmlNode* next);

    /**
        Sets as parent the given node.

        The caller is responsible to delete any previously present parent node.
    */
    void SetParent(wxXmlNode* parent);

    /**
        Sets the type of this node.
    */
    void SetType(wxXmlNodeType type);

    /**
        See the copy constructor for more info.
    */
    wxXmlNode& operator=(const wxXmlNode& node);
};



/**
    @class wxXmlAttribute

    Represents a node attribute.

    Example: in <tt>\<img src="hello.gif" id="3"/\></tt>, @c src is an attribute
    with value @c hello.gif and @c id is an attribute with value @c 3.

    @library{wxxml}
    @category{xml}

    @see wxXmlDocument, wxXmlNode
*/
class wxXmlAttribute
{
public:
    /**
        Default constructor.
    */
    wxXmlAttribute();

    /**
        Creates the attribute with given @a name and @a value.
        If @a next is not @NULL, then sets it as sibling of this attribute.
    */
    wxXmlAttribute(const wxString& name, const wxString& value,
                   wxXmlAttribute* next = NULL);

    /**
        The virtual destructor.
    */
    virtual ~wxXmlAttribute();

    /**
        Returns the name of this attribute.
    */
    wxString GetName() const;

    /**
        Returns the sibling of this attribute or @NULL if there are no siblings.
    */
    wxXmlAttribute* GetNext() const;

    /**
        Returns the value of this attribute.
    */
    wxString GetValue() const;

    /**
        Sets the name of this attribute.
    */
    void SetName(const wxString& name);

    /**
        Sets the sibling of this attribute.
    */
    void SetNext(wxXmlAttribute* next);

    /**
        Sets the value of this attribute.
    */
    void SetValue(const wxString& value);
};



/**
    @class wxXmlDocument

    This class holds XML data/document as parsed by XML parser in the root node.

    wxXmlDocument internally uses the expat library which comes with wxWidgets to
    parse the given stream.

    A simple example of using XML classes is:

    @code
    wxXmlDocument doc;
    if (!doc.Load("myfile.xml"))
        return false;

    // start processing the XML file
    if (doc.GetRoot()->GetName() != "myroot-node")
        return false;

    wxXmlNode *child = doc.GetRoot()->GetChildren();
    while (child) {

        if (child->GetName() == "tag1") {

            // process text enclosed by tag1/tag1
            wxString content = child->GetNodeContent();

            ...

            // process attributes of tag1
            wxString attrvalue1 =
                child->GetAttribute("attr1", "default-value");
            wxString attrvalue2 =
                child->GetAttribute("attr2", "default-value");

            ...

        } else if (child->GetName() == "tag2") {

            // process tag2 ...
        }

        child = child->GetNext();
    }
    @endcode

    Note that if you want to preserve the original formatting of the loaded file
    including whitespaces and indentation, you need to turn off whitespace-only
    textnode removal and automatic indentation:

    @code
    wxXmlDocument doc;
    doc.Load("myfile.xml", "UTF-8", wxXMLDOC_KEEP_WHITESPACE_NODES);

    // myfile2.xml will be indentic to myfile.xml saving it this way:
    doc.Save("myfile2.xml", wxXML_NO_INDENTATION);
    @endcode

    Using default parameters, you will get a reformatted document which in general
    is different from the original loaded content:

    @code
    wxXmlDocument doc;
    doc.Load("myfile.xml");
    doc.Save("myfile2.xml");  // myfile2.xml != myfile.xml
    @endcode

    @library{wxxml}
    @category{xml}

    @see wxXmlNode, wxXmlAttribute
*/
class wxXmlDocument : public wxObject
{
public:
    /**
        Default constructor.
    */
    wxXmlDocument();

    /**
        Copy constructor. Deep copies all the XML tree of the given document.
    */
    wxXmlDocument(const wxXmlDocument& doc);

    /**
        Loads the given filename using the given encoding. See Load().
    */
    wxXmlDocument(const wxString& filename,
                  const wxString& encoding = "UTF-8"));

    /**
        Loads the XML document from given stream using the given encoding. See Load().
    */
    wxXmlDocument(wxInputStream& stream,
                  const wxString& encoding = "UTF-8");

    /**
        Virtual destructor. Frees the document root node.
    */
    virtual ~wxXmlDocument();

    /**
        Detaches the document root node and returns it.

        The document root node will be set to @NULL and thus IsOk() will
        return @false after calling this function.

        Note that the caller is reponsible for deleting the returned node in order
        to avoid memory leaks.
    */
    wxXmlNode* DetachRoot();

    /**
        Returns encoding of in-memory representation of the document
        (same as passed to Load() or constructor, defaults to UTF-8).

        @note this is meaningless in Unicode build where data are stored as @c wchar_t*.
    */
    wxString GetEncoding() const;

    /**
        Returns encoding of document (may be empty).

        @note This is the encoding original file was saved in, @b not the
              encoding of in-memory representation!
    */
    const wxString& GetFileEncoding() const;

    /**
        Returns the root node of the document.
    */
    wxXmlNode* GetRoot() const;

    /**
        Returns the version of document.

        This is the value in the @c \<?xml version="1.0"?\> header of the XML document.
        If the version attribute was not explicitely given in the header, this function
        returns an empty string.
    */
    const wxString& GetVersion() const;

    /**
        Returns @true if the document has been loaded successfully.
    */
    bool IsOk() const;


    /**
        Parses @a filename as an xml document and loads its data.

        If @a flags does not contain wxXMLDOC_KEEP_WHITESPACE_NODES, then, while loading,
        all nodes of type @c wxXML_TEXT_NODE (see wxXmlNode) are automatically skipped
        if they contain whitespaces only.

        The removal of these nodes makes the load process slightly faster and requires
        less memory however makes impossible to recreate exactly the loaded text with a
        Save() call later. Read the initial description of this class for more info.

        Returns true on success, false otherwise.
    */
    virtual bool Load(const wxString& filename,
                      const wxString& encoding = "UTF-8", int flags = wxXMLDOC_NONE);

    /**
        Like Load(const wxString&, const wxString&, int) but takes the data from
        given input stream.
    */
    virtual bool Load(wxInputStream& stream,
                      const wxString& encoding = "UTF-8", int flags = wxXMLDOC_NONE);

    /**
        Saves XML tree creating a file named with given string.

        If @a indentstep is greater than or equal to zero, then, while saving,
        an automatic indentation is added with steps composed by indentstep spaces.

        If @a indentstep is @c wxXML_NO_INDENTATION, then, automatic indentation
        is turned off.
    */
    virtual bool Save(const wxString& filename, int indentstep = 2) const;

    /**
        Saves XML tree in the given output stream.
        See Save(const wxString&, int) for a description of @a indentstep.
    */
    virtual bool Save(wxOutputStream& stream, int indentstep = 2) const;

    /**
        Sets the enconding of the document.
    */
    void SetEncoding(const wxString& enc);

    /**
        Sets the enconding of the file which will be used to save the document.
    */
    void SetFileEncoding(const wxString& encoding);

    /**
        Sets the root node of this document. Deletes previous root node.
        Use DetachRoot() and then SetRoot() if you want to replace the root
        node without deleting the old document tree.
    */
    void SetRoot(wxXmlNode* node);

    /**
        Sets the version of the XML file which will be used to save the document.
    */
    void SetVersion(const wxString& version);

    /**
        Deep copies the given document.
    */
    wxXmlDocument& operator=(const wxXmlDocument& doc);
};

