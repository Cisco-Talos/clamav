/////////////////////////////////////////////////////////////////////////////
// Name:        guiframe.h
// Purpose:     Defines the window containing all controls.
// Author:      Utensil Candel (UtensilCandel@@gmail.com)
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _GUIFRAME_H_
#define _GUIFRAME_H_

#include "wx/animate.h"
#include "wx/bmpcbox.h"
#include "wx/calctrl.h"
#include "wx/clrpicker.h"
#include "wx/collpane.h"
#include "wx/datectrl.h"
#include "wx/dirctrl.h"
#include "wx/filepicker.h"
#include "wx/fontpicker.h"
#include "wx/hyperlink.h"
#include "wx/listctrl.h"
#include "wx/notebook.h"
#include "wx/richtext/richtextctrl.h"
#include "wx/spinbutt.h"
#include "wx/spinctrl.h"
#include "wx/tglbtn.h"
#include "wx/treectrl.h"

#include "customcombo.h"


class GUIFrame : public wxFrame
{
public:

    GUIFrame( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("wxWidgets Control Screenshot Generator"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxDEFAULT_FRAME_STYLE|wxTAB_TRAVERSAL );
    ~GUIFrame();

protected:

    enum
    {
        idMenuCapFullScreen = 1000,
        idMenuCapAll
    };

    wxMenuBar* mbar;
    wxMenu* fileMenu;
    wxMenu* captureMenu;
    wxMenu* helpMenu;

    wxStatusBar* statusBar;

    wxNotebook* m_notebook1;

    wxPanel* m_panel1;
    wxButton* m_button1;
    wxStaticText* m_staticText1;
    wxCheckBox* m_checkBox1;
    wxCheckBox* m_checkBox2;
    wxRadioButton* m_radioBtn1;
    wxRadioButton* m_radioBtn2;
    wxBitmapButton* m_bpButton1;
    wxStaticBitmap* m_bitmap1;
    wxGauge* m_gauge1;
    wxSlider* m_slider1;
    wxToggleButton* m_toggleBtn1;
    wxToggleButton* m_toggleBtn2;
    wxHyperlinkCtrl* m_hyperlink1;
    wxSpinCtrl* m_spinCtrl1;
    wxSpinButton* m_spinBtn1;
    wxScrollBar* m_scrollBar1;

    wxPanel* m_panel2;
    wxCheckListBox* m_checkList1;
    wxListBox* m_listBox1;
    wxRadioBox* m_radioBox1;
    wxStaticBox * m_staticBox1;
    wxTreeCtrl* m_treeCtrl1;
    wxListCtrl* m_listCtrl1;
    wxAnimationCtrl * m_animationCtrl1;
    wxCollapsiblePane *m_collPane1;
    wxCollapsiblePane *m_collPane2;

    wxPanel* m_panel3;
    wxTextCtrl* m_textCtrl1;
    wxTextCtrl* m_textCtrl2;
    wxRichTextCtrl* m_richText1;

    wxPanel* m_panel4;
    wxColourPickerCtrl* m_colourPicker1;
    wxFontPickerCtrl* m_fontPicker1;
    wxFilePickerCtrl* m_filePicker1;
    wxCalendarCtrl* m_calendar1;
    wxDatePickerCtrl* m_datePicker1;
    wxGenericDirCtrl* m_genericDirCtrl1;
    wxDirPickerCtrl* m_dirPicker1;

    wxPanel* m_panel5;
    wxChoice* m_choice1;
    wxComboBox* m_comboBox1;
    wxBitmapComboBox * m_bmpComboBox1;
    PenStyleComboBox * m_ownerDrawnComboBox1;
    wxComboCtrl * m_comboCtrl1;
    wxComboCtrl * m_comboCtrl2;

    // Virtual event handlers, overide them in your derived class
    virtual void OnClose( wxCloseEvent& event ){ event.Skip(); }
    virtual void OnSeeScreenshots( wxCommandEvent& event ){ event.Skip(); }
    virtual void OnQuit( wxCommandEvent& event ){ event.Skip(); }
    virtual void OnCaptureFullScreen( wxCommandEvent& event ){ event.Skip(); }
    virtual void OnCaptureAllControls( wxCommandEvent& event ){ event.Skip(); }
    virtual void OnAbout( wxCommandEvent& event ){ event.Skip(); }

private:
    void AddMenuBar();
    void AddPanel_1();
    void AddPanel_2();
    void AddPanel_3();
    void AddPanel_4();
    void AddPanel_5();
};

#endif //_GUIFRAME_H_
