/***************************************************************
 * Purpose:   Proxy settings detection
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
#include "SigUIMain.h"

#ifdef _WIN32
#include <cstring>
#include <wx/uri.h>
#include <wx/dynlib.h>
#include <wx/tokenzr.h>

typedef struct
{
    BOOL   fAutoDetect;
    LPWSTR lpszAutoConfigUrl;
    LPWSTR lpszProxy;
    LPWSTR lpszProxyBypass;
} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;

typedef struct {
  DWORD   dwFlags;
  DWORD   dwAutoDetectFlags;
  LPCWSTR lpszAutoConfigUrl;
  LPVOID  lpvReserved;
  DWORD   dwReserved;
  BOOL    fAutoLogonIfChallenged;
} WINHTTP_AUTOPROXY_OPTIONS;

typedef struct {
  DWORD  dwAccessType;
  LPWSTR lpszProxy;
  LPWSTR lpszProxyBypass;
} WINHTTP_PROXY_INFO;

typedef void* HINTERNET;

#define wxDLW_VOIDMETHOD_DEFINE( name, args, argnames ) \
    typedef void (WINAPI * wxDL_METHOD_TYPE(name)) args ; \
    wxDL_METHOD_TYPE(name) wxDL_METHOD_NAME(name); \
    void name args \
        { if ( m_ok ) wxDL_METHOD_NAME(name) argnames ; }

#define wxDLW_METHOD_DEFINE( rettype, name, args, argnames, defret ) \
    typedef rettype (WINAPI * wxDL_METHOD_TYPE(name)) args ; \
    wxDL_METHOD_TYPE(name) wxDL_METHOD_NAME(name); \
    rettype name args \
        { return m_ok ? wxDL_METHOD_NAME(name) argnames : defret; }


class WHttp {
    public:
	WHttp() {
	    m_whttp.Load("winhttp.dll", wxDL_DEFAULT | wxDL_VERBATIM | wxDL_QUIET);
	    m_ok = m_whttp.IsLoaded();
	    if (!m_ok)
		return;
	    m_ok = InitializeMethods();
	}
	bool IsOK() const { return m_ok; }

	wxDLW_METHOD_DEFINE(BOOL, WinHttpGetIEProxyConfigForCurrentUser,
			   (WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig),
			   (pProxyConfig), FALSE)
    wxDLW_METHOD_DEFINE(BOOL, WinHttpGetProxyForUrl,
			   (HINTERNET hSession, LPCWSTR lpcwszUrl,
			    WINHTTP_AUTOPROXY_OPTIONS *pAutoProxyOptions,
			    WINHTTP_PROXY_INFO *pProxyInfo),
			   (hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo), FALSE)
	wxDLW_METHOD_DEFINE(HINTERNET, WinHttpOpen,
			   (LPCWSTR pwszUserAgent,
			    DWORD dwAccessType,
			    LPCWSTR pwszProxyName,
			    LPCWSTR pwszProxyByPass,
			    DWORD dwFlags),
			   (pwszUserAgent, dwAccessType, pwszProxyName,
			    pwszProxyByPass, dwFlags), 0)
	wxDLW_METHOD_DEFINE(BOOL, WinHttpCloseHandle,
			   (HINTERNET hInternet),
			   (hInternet), FALSE)
    private:
	wxDynamicLibrary m_whttp;
	bool m_ok;

	bool InitializeMethods() {
	    wxDL_METHOD_LOAD(m_whttp, WinHttpGetIEProxyConfigForCurrentUser);
	    wxDL_METHOD_LOAD(m_whttp, WinHttpGetProxyForUrl);
	    wxDL_METHOD_LOAD(m_whttp, WinHttpOpen);
	    wxDL_METHOD_LOAD(m_whttp, WinHttpCloseHandle);
	    return true;
	}
};

void SigUIFrame::m_proxy_autodetOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    // there should be a simpler API to do this

    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config;
    WINHTTP_AUTOPROXY_OPTIONS autoproxy_opts;
    WINHTTP_PROXY_INFO autoproxy_info;

    memset(&config, 0, sizeof(config));

    wxLogVerbose(_("Starting proxy autodetection"));
    WHttp whttp;
    if (!whttp.IsOK()) {
	wxLogVerbose(_("WinHTTP could not be loaded: %s"), wxSysErrorMsg(wxSysErrorCode()));
	return;
    }

    bool need_autoproxy = false;
    memset(&config, 0, sizeof(config));
    memset(&autoproxy_opts, 0, sizeof(autoproxy_opts));
    if (whttp.WinHttpGetIEProxyConfigForCurrentUser(&config) == TRUE) {
	wxLogVerbose(_("IE proxy: %s"), config.lpszProxy);
	if (config.fAutoDetect) {
	    wxLogVerbose(_("Autodetect is set"));
	    need_autoproxy = true;
	    autoproxy_opts.dwFlags |= 1;
	}
	if (config.lpszAutoConfigUrl) {
	    need_autoproxy = true;
	    wxLogVerbose(_("Autoconfig URL: %s"), config.lpszAutoConfigUrl);
	    autoproxy_opts.dwFlags |= 2;
	    autoproxy_opts.lpszAutoConfigUrl = config.lpszAutoConfigUrl;
	}
    } else {
	wxLogVerbose(_("Failed to get IE proxy settings: %s"), wxSysErrorMsg(wxSysErrorCode()));
	need_autoproxy = true;
	autoproxy_opts.dwFlags |= 1;
    }

    wxString proxy = wxEmptyString;

    if (need_autoproxy) {
	autoproxy_opts.dwAutoDetectFlags = 3;
	autoproxy_opts.fAutoLogonIfChallenged = TRUE;

	HINTERNET h = whttp.WinHttpOpen(L"SigUI",1,NULL,NULL,0);

	if (h) {
	    wxLogVerbose(_("Retrieving proxy settings for URL"));
	    if (whttp.WinHttpGetProxyForUrl(h,
					    L"http://database.clamav.net",
					    &autoproxy_opts,
					    &autoproxy_info)) {
		wxLogVerbose(_("proxy: %s, accesstype: %d"),
			     autoproxy_info.lpszProxy,
			     autoproxy_info.dwAccessType);
		if (autoproxy_info.dwAccessType == 3)
		    proxy = wxString(autoproxy_info.lpszProxy);
	    } else {
		wxLogVerbose(_("Autoconfig failed, falling back to manual IE settings"));
		proxy = config.lpszProxy;
	    }
	    whttp.WinHttpCloseHandle(h);
	} else {
	    wxLogVerbose(_("WinHttpOpen failed"), wxSysErrorMsg(wxSysErrorCode()));
	}
    } else {
	proxy = config.lpszProxy;
    }
    wxLogVerbose(_("Final proxy: %s"), proxy);

    if (proxy.empty()) {
        m_proxy->SetValue(false);
	wxCommandEvent ev;
	m_proxyOnCheckBox(ev);
        return;
    }

    wxStringTokenizer tokenizer(proxy, ";");
    while (tokenizer.HasMoreTokens()) {
	wxString token = tokenizer.GetNextToken();
	if (token.Find('=') == wxNOT_FOUND) {
	    token = token.Prepend("http=");
	}
	if (!token.StartsWith("http="))
	    continue;
	token = token.Mid(5);
	if (token.StartsWith("http://"))
	    token = token.Mid(7);
	token = "http://" + token;
	wxLogVerbose(_("token: %s"), token);
	wxURI uri(token);
	m_proxy->SetValue(true);
        m_proxy_server->SetValue(uri.GetServer());
        if (uri.HasPort())
            m_proxy_port->SetValue(uri.GetPort());
        else
            m_proxy_port->SetValue(80);
        m_proxyauth->SetValue(false);
	wxCommandEvent ev;
	m_proxyOnCheckBox(ev);
	return;
    }
}
#else
void SigUIFrame::m_proxy_autodetOnButtonClick( wxCommandEvent& event )
{ }
#endif
