/***************************************************************
 * Purpose:   Defines Application Class
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
 *************************************************************/

#ifndef SIGUIAPP_H
#define SIGUIAPP_H

#include <wx/app.h>

class SigUIApp : public wxApp
{
    public:
        virtual bool OnInit();
	virtual int OnRun();
	virtual void OnInitCmdLine(wxCmdLineParser& parser);
	virtual bool OnCmdLineParsed(wxCmdLineParser& parser);
	virtual void OnEventLoopEnter(wxEventLoopBase *loop);
	static bool validate_dbname(const wxString &name);
    private:
	bool install_mode;
	bool verbose_mode;
	bool conf_mode;
};

#endif // SIGUIAPP_H
