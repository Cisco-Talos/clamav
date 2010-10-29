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
#ifndef CONFIG_EDITOR_H
#define CONFIG_EDITOR_H

#include <wx/any.h>
#include <wx/dynarray.h>
class wxTextFile;
WX_DECLARE_OBJARRAY(wxAny, AnyArray);
WX_DECLARE_OBJARRAY(const wxControl*, ControlArray);

class ConfigEditor
{
    public:
	ConfigEditor(const wxString& filename);
	~ConfigEditor();

	void RegisterText(const wxString& name, wxString *variable, wxTextCtrl *control, const wxString &hint = wxEmptyString);
	void RegisterText(const wxString& name, wxString *variable, wxComboBox *control, const wxString &hint = wxEmptyString);
	void RegisterInt(const wxString& name, int *variable, wxSpinCtrl *control);
	void RegisterBool(const wxString& name, bool *variable, wxCheckBox *control); 
	void RegisterList(const wxString &name, wxControlWithItems *control);
	void RegisterStatic(const wxString &name, const wxString &value);

	void Load(void);

	wxString Get(const wxString& key, const wxString& Default = wxEmptyString);
	wxString GetNext(void);

	void RemoveKey(const wxString& key);
	bool Save(bool checkOnly = false);
    private:
	wxTextFile file;
	wxString skey;
	unsigned lastadd;

	wxArrayString registeredNames;
	AnyArray registeredVariables;
	ControlArray registeredControls;

	void Add(const wxString& key, const wxString &value, bool comment);
	void DisableAll(const wxString &key);
	void Register(const wxString& name, wxAny &any, const wxControl *control);
};
#endif
