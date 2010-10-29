/***************************************************************
 * Purpose:  Test and install ClamAV databases 
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
#ifndef INSTALLDB_H
#define INSTALLDB_H

#include "GUIFrame.h"
#include <wx/progdlg.h>

#include <csetjmp>

class SigUICopy
{
    public:
	        SigUICopy();
		bool installDBs(void);
		static bool writeFreshclamConf(void);
		static bool validate_dbname(const wxString &name, bool all = false);
    private:
		jmp_buf env;
		long cnt, max;
		wxProgressDialog* progress;
		bool installDB(const wxString& staging, const wxString &dest);
		bool copySignatures(const wxString &staging);
		bool loadDB(const wxString& dir);
		bool canceled(void);
		static int sigprogress(const char *type, const char *name, void *context);
};

#endif
