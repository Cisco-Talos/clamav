#include "rar.hpp"

RAROptions::RAROptions()
{
  Init();
}


void RAROptions::Init()
{
  memset(this,0,sizeof(RAROptions));
  WinSize=0x2000000;
  // ClamAV limits RAR 7 dictionaries to 1 GiB.
  WinSizeLimit=0x40000000;
  Overwrite=OVERWRITE_DEFAULT;
  Method=3;
  MsgStream=MSG_STDOUT;
  ConvertNames=NAMES_ORIGINALCASE;
  xmtime=EXTTIME_MAX;
  FileSizeLess=INT64NDF;
  FileSizeMore=INT64NDF;
  HashType=HASH_CRC32;
#ifdef RAR_SMP
  Threads=GetNumberOfThreads();
#endif
#ifdef USE_QOPEN
  QOpenMode=QOPEN_AUTO;
#endif
}
