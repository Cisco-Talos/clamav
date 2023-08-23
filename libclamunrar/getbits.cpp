#include "rar.hpp"

BitInput::BitInput(bool AllocBuffer)
{
  ExternalBuffer=false;
  if (AllocBuffer)
  {
    // getbits*() attempt to read data from InAddr, ... InAddr+4 positions.
    // So let's allocate 4 additional bytes for situation, when we need to
    // read only 1 byte from the last position of buffer and avoid a crash
    // from access to next 4 bytes, which contents we do not need.
    size_t BufSize=MAX_SIZE+4;
    InBuf=new byte[BufSize];

    // Ensure that we get predictable results when accessing bytes in area
    // not filled with read data.
    memset(InBuf,0,BufSize);
  }
  else
    InBuf=NULL;
}


BitInput::~BitInput()
{
  if (!ExternalBuffer)
    delete[] InBuf;
}


void BitInput::faddbits(uint Bits)
{
  // Function wrapped version of inline addbits to save code size.
  addbits(Bits);
}


uint BitInput::fgetbits()
{
  // Function wrapped version of inline getbits to save code size.
  return getbits();
}


void BitInput::SetExternalBuffer(byte *Buf)
{
  if (InBuf!=NULL && !ExternalBuffer)
    delete[] InBuf;
  InBuf=Buf;
  ExternalBuffer=true;
}

