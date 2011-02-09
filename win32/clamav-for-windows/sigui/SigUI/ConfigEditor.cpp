/***************************************************************
 * Purpose:   Freshclam configuration editor
 *
 *  Copyright (C) 2010 Sourcefire, Inc.
 *
 *  Authors: Török Edwin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 **************************************************************/

#include "wx_pch.h"

#include "ConfigEditor.h"
#include <wx/log.h>
#include <wx/valgen.h>

#include <wx/arrimpl.cpp> //must be done
WX_DEFINE_OBJARRAY(AnyArray);
WX_DEFINE_OBJARRAY(ControlArray);

ConfigEditor::ConfigEditor(const wxString& filename)
    : file(filename),
    lastadd(0)
{
    if (!wxFile::Exists(filename)) {
	if (!file.Create()) {
#if wxUSE_LOG
	    wxLog::FlushActive();
#endif
	    wxLogFatalError(_("Can't create configuration file %s"), filename);
	}
	file.AddLine("DatabaseMirror db.local.win.clamav.net");
	file.AddLine("DNSDatabaseInfo current.cvd.win.clamav.net");
	file.AddLine("ConnectTimeout 5");
	file.Write(wxTextFile::typeDefault);
    } else {
	//bb #2343
	if (!file.Open(wxConvLibc)) {
#if wxUSE_LOG
	    wxLog::FlushActive();
#endif
	    wxLogFatalError(_("Can't open existing configuration file %s"), filename);
	}
    }
}

ConfigEditor::~ConfigEditor()
{
    file.Close();//loose changes
}

static inline bool checkKey(wxString& line, const wxString& key)
{
    line.Trim();
    line.Trim(false);
    if (line.length() <= key.length())
	return false;
    if (line[key.length()] != ' ')
	return false;
    if (!line.StartsWith(key))
	return false;
    return true;
}

wxString ConfigEditor::Get(const wxString& key, const wxString& Default)
{
    wxString &line = file.GetFirstLine();
    skey = key;
    if (!checkKey(line, key)) {
	wxString next = GetNext();
	return next.IsEmpty() ? Default : next;
    }
    wxString result = line.substr(key.length()+1);
    if (result.StartsWith("\"")) {
	int end = result.Find('\"', true);
	if (end != wxNOT_FOUND) {
	    return result.substr(0, end);
	}
    }
    return result;
}

wxString ConfigEditor::GetNext(void)
{
    // Not very efficient if we have lots of keys, but for a few keys it is good
    wxString line;
    for (;!file.Eof();line = file.GetNextLine()) {
	if (!checkKey(line, skey))
	    continue;
	return line.substr(skey.length()+1);
    }
    return wxEmptyString;
}

void ConfigEditor::Add(const wxString& key, const wxString &value, bool comment)
{
    if (value.IsEmpty())
	return;



    wxString writeLine = key + " " + value;

    if (comment) {
	//TODO: unique only
	writeLine.Prepend("#");
	return ;
    }

    if (value.find_first_of("\r\n") != wxString::npos) {
	wxFAIL;
	return;//TODO:error!
    }

    if (value.find_first_of(" \t\"") != wxString::npos)
	writeLine = "\"" + writeLine + "\"";

    for (wxString str = file.GetFirstLine(); !file.Eof(); str = file.GetNextLine()) {
	if (str.IsSameAs(writeLine))
	    return;
    }

    file.InsertLine(writeLine, lastadd);
    lastadd++;
}

void ConfigEditor::RemoveKey(const wxString& key)
{
    unsigned last = 0;
    bool found = false;
    for (wxString line = file.GetFirstLine(); !file.Eof();) {
        if (checkKey(line, key)) {
	    found = true;
	    last = file.GetCurrentLine();
            file.RemoveLine(last);
	    if (!file.Eof())
		line = file.GetLine(last);
	    continue;
	}
	if (!found && line.StartsWith("#") && line.Contains(key))
	    last = file.GetCurrentLine();
	line = file.GetNextLine();
    }
    // lastadd = last uncommented line if any, otherwise last commented line
    lastadd = last;
}

void ConfigEditor::Register(const wxString &name, wxAny &any, const wxControl *control)
{
    registeredNames.Add(name);
    registeredVariables.Add(any);
    registeredControls.Add(control);
}

void ConfigEditor::RegisterText(const wxString& name, wxString *variable, wxTextCtrl *control, const wxString &hint)
{
    control->SetValidator(wxGenericValidator(variable));
    if (!hint.IsEmpty())
	control->SetHint(hint);
    wxAny any = variable;
    Register(name, any, control);
}

void ConfigEditor::RegisterStatic(const wxString& name, const wxString &value)
{
    wxAny any = value;
    Register(name, any, 0);
}

void ConfigEditor::RegisterText(const wxString& name, wxString *variable, wxComboBox *control, const wxString &hint)
{
    control->SetValidator(wxGenericValidator(variable));
    if (!hint.IsEmpty())
	control->SetHint(hint);
    wxAny any = variable;
    Register(name, any, control);
}

void ConfigEditor::RegisterInt(const wxString& name, int *variable, wxSpinCtrl *control)
{
    control->SetValidator(wxGenericValidator(variable));
    wxAny any = variable;
    Register(name, any, control);
}

void ConfigEditor::RegisterBool(const wxString& name, bool *variable, wxCheckBox *control)
{
    control->SetValidator(wxGenericValidator(variable));
    wxAny any = variable;
    Register(name, any, control);
}

void ConfigEditor::RegisterList(const wxString &name, wxControlWithItems *control)
{
    wxAny any = control;
    Register(name, any, control);
}

void ConfigEditor::Load(void)
{
    for (unsigned i=0;i<registeredNames.GetCount();i++) {
	wxString value = Get(registeredNames[i], "");
	wxAny& any = registeredVariables[i];

	if (any.CheckType<wxString*>()) {
	    *any.As<wxString*>() = value;
	} else if (any.CheckType<int*>()) {
	    long v_long = 0;
	    value.ToLong(&v_long);
	    *any.As<int*>() = v_long;
	} else if (any.CheckType<bool*>()) {
	    *any.As<bool*>() = value != "No";
	} else if (any.CheckType<wxControlWithItems*>()) {
	    wxControlWithItems *c = any.As<wxControlWithItems*>();
	    while (!value.empty()) {
		c->Append(value);
		value = GetNext();
	    }
	} else if (any.CheckType<wxString>()) {
	    // ignore
	} else {
	    wxFAIL;
	}
    }
}

bool ConfigEditor::Save(bool checkOnly)
{
    wxArrayString lines0;
    if (checkOnly) {
	for (unsigned i=0;i<file.GetLineCount();i++)
	    lines0.Add(file.GetLine(i));
    }

    for (unsigned i=0;i<registeredNames.GetCount();i++) {
	const wxString& key = registeredNames[i];

	if (registeredControls[i])
	    RemoveKey(key);
	//TODO: filter dupes

	bool enabled = !registeredControls[i] || registeredControls[i]->IsEnabled();
	wxAny& any = registeredVariables[i];
	if (any.CheckType<wxString*>())
	    Add(key, *any.As<wxString*>(), !enabled);
	else if (any.CheckType<int*>()) {
	    wxString s;
	    s << *any.As<int*>();
	    Add(key, s, !enabled);
	} else if (any.CheckType<bool*>()) {
	    bool e = *any.As<bool*>();
	    wxString s = e ? "Yes" : "No";
	    Add(key, s, !enabled);
	} else if (any.CheckType<wxControlWithItems*>()) {
	    wxControlWithItems *c = any.As<wxControlWithItems*>();
	    wxArrayString array = c->GetStrings();
	    for (unsigned i=0;i<array.GetCount();i++) {
		Add(key, array[i], !enabled);
	    }
	} else if (any.CheckType<wxString>()) {
	    Add(key, any.As<wxString>(), false);
	} else {
	    wxFAIL;
	}
    }

    if (checkOnly) {
	wxArrayString lines1;
	for (unsigned i=0;i<file.GetLineCount();i++)
	    lines1.Add(file.GetLine(i));
	return lines1 != lines0;
    }

    //bb #2343
    file.Write(wxTextFile::typeDefault, wxConvLibc);
    return true;
}
