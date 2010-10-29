/////////////////////////////////////////////////////////////////////////////
// Name:        richtext/richtextxml.h
// Purpose:     interface of wxRichTextXMLHandler
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxRichTextXMLHandler

    A handler for loading and saving content in an XML format specific
    to wxRichTextBuffer.

    You can either add the handler to the buffer and load and save through
    the buffer or control API, or you can create an instance of the handler
    on the stack and call its functions directly.


    @section richtextxmlhandler_flags Handler flags

    The following flags can be used with this handler, via the handler's SetFlags()
    function or the buffer or control's SetHandlerFlags() function:

    - wxRICHTEXT_HANDLER_INCLUDE_STYLESHEET
      Include the style sheet in loading and saving operations.


    @library{wxrichtext}
    @category{richtext}
*/
class wxRichTextXMLHandler : public wxRichTextFileHandler
{
public:
    /**
        Constructor.
    */
    wxRichTextXMLHandler(const wxString& name = "XML",
                         const wxString& ext = "xml",
                         int type = wxRICHTEXT_TYPE_XML);

    /**
        Returns @true.
    */
    virtual bool CanLoad() const;

    /**
        Returns @true.
    */
    virtual bool CanSave() const;

    /**
        Creates XML code for a given character or paragraph style.
    */
    wxString CreateStyle(const wxTextAttr& attr, bool isPara = false);

    /**
        Recursively exports an object to the stream.
    */
    bool ExportXML(wxOutputStream& stream, wxMBConv* convMem,
                   wxMBConv* convFile,
                   wxRichTextObject& obj,
                   int level);

    /**
        Helper function: gets node context.
    */
    wxString GetNodeContent(wxXmlNode* node);

    /**
        Helper function: gets a named parameter from the XML node.
    */
    wxXmlNode* GetParamNode(wxXmlNode* node, const wxString& param);

    /**
        Helper function: gets a named parameter from the XML node.
    */
    wxString GetParamValue(wxXmlNode* node, const wxString& param);

    /**
        Helper function: gets style parameters from the given XML node.
    */
    bool GetStyle(wxTextAttr& attr, wxXmlNode* node,
                  bool isPara = false);

    /**
        Helper function: gets text from the node.
    */
    wxString GetText(wxXmlNode* node,
                     const wxString& param = wxEmptyString,
                     bool translate = false);

    /**
        Helper function: returns @true if the node has the given parameter.
    */
    bool HasParam(wxXmlNode* node, const wxString& param);

    /**
        Recursively imports an object.
    */
    bool ImportXML(wxRichTextBuffer* buffer, wxXmlNode* node);

protected:

    /**
        Loads buffer context from the given stream.
    */
    virtual bool DoLoadFile(wxRichTextBuffer* buffer, wxInputStream& stream);

    /**
        Saves buffer context to the given stream.
    */
    virtual bool DoSaveFile(wxRichTextBuffer* buffer, wxOutputStream& stream);
};

