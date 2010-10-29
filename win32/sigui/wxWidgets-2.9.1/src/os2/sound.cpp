/////////////////////////////////////////////////////////////////////////////
// Name:        sound.cpp
// Purpose:     wxSound class implementation: optional
// Author:      David Webster
// Modified by:
// Created:     10/17/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include "wx/file.h"
#include "wx/sound.h"
#define INCL_32                         /* force 32 bit compile */
#define INCL_GPIBITMAPS
#define INCL_DOSFILEMGR
#define INCL_WIN
#define INCL_GPI
#define INCL_PM
#include <os2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <os2medef.h>
#include <mmioos2.h>

wxSound::wxSound()
  : m_waveData(NULL), m_waveLength(0), m_isResource(FALSE)
{
}

wxSound::wxSound(const wxString& sFileName, bool isResource)
  : m_waveData(NULL), m_waveLength(0), m_isResource(isResource)
{
  Create(sFileName, isResource);
}

wxSound::wxSound(int size, const wxByte* data)
  : m_waveData(NULL), m_waveLength(0), m_isResource(FALSE)
{
  Create(size, data);
}

wxSound::~wxSound()
{
  Free();
}

bool wxSound::Create(const wxString& fileName, bool isResource)
{
  Free();

  if (isResource)
  {
    m_isResource = TRUE;
// TODO:
/*
    HRSRC hresInfo;
#ifdef _UNICODE
    hresInfo = ::FindResourceW((HMODULE) wxhInstance, fileName, wxT("WAVE"));
#else
    hresInfo = ::FindResourceA((HMODULE) wxhInstance, fileName, wxT("WAVE"));
#endif
    if (!hresInfo)
        return FALSE;

    HGLOBAL waveData = ::LoadResource((HMODULE) wxhInstance, hresInfo);

    if (waveData)
    {
      m_waveData= (wxByte*)::LockResource(waveData);
      m_waveLength = (int) ::SizeofResource((HMODULE) wxhInstance, hresInfo);
    }

    return (m_waveData ? TRUE : FALSE);
*/
    return FALSE;
  }
  else
  {
    m_isResource = FALSE;
#if wxUSE_FILE

    wxFile fileWave;
    if (!fileWave.Open(fileName, wxFile::read))
        return FALSE;

    m_waveLength = (int) fileWave.Length();
// TODO:
/*
    m_waveData = (wxByte*)::GlobalLock(::GlobalAlloc(GMEM_MOVEABLE | GMEM_SHARE, m_waveLength));
    if (!m_waveData)
        return FALSE;

    fileWave.Read(m_waveData, m_waveLength);
*/
    return TRUE;
#else
    return FALSE;
#endif //wxUSE_FILE
  }
}

bool wxSound::Create(int size, const wxByte* data)
{
  Free();
  m_isResource = FALSE;
  m_waveLength=size;
  m_waveData = NULL; // (wxByte*)::GlobalLock(::GlobalAlloc(GMEM_MOVEABLE | GMEM_SHARE, m_waveLength));
  if (!m_waveData)
     return FALSE;

  for (int i=0; i<size; i++) m_waveData[i] = data[i];
  return TRUE;
}

bool wxSound::DoPlay(unsigned WXUNUSED(flags)) const
{
    if (!IsOk())
        return false;

// TODO:
/*
    return ( ::PlaySound((LPCTSTR)m_waveData, NULL, SND_MEMORY |
             SND_NODEFAULT | (async ? SND_ASYNC : SND_SYNC) | (looped ? (SND_LOOP | SND_ASYNC) : 0)) != 0 );
*/
    return false;
}

bool wxSound::Free()
{
    if (m_waveData)
    {
//  HGLOBAL waveData = ::GlobalHandle(m_waveData);

// TODO:
/*
    if (waveData)
    {
      if (m_isResource)
        ::FreeResource(waveData);
      else
      {
        ::GlobalUnlock(waveData);
        ::GlobalFree(waveData);
      }

      m_waveData = NULL;
      m_waveLength = 0;
      return TRUE;
    }
*/
    }
    return false;
}
