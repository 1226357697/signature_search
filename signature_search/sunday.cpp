#include "sunday.h"
#include <assert.h>
#include <limits.h>
#include <memory.h>

inline static bool is_hexchar(char ch)
{
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
}
inline static unsigned char hexchar2byte(char ch)
{
  unsigned char byte = 0;
  if (ch >= '0' && ch <= '9')
    byte = (ch - '0');
  else if (ch >= 'A' && ch <= 'F')
    byte = ch - 'A' + 10;
  else if (ch >= 'a' && ch <= 'f')
    byte = ch - 'a' + 10;
  else
    ;//assert(false);

  return byte;
}

inline static unsigned char hexstr2byte(const char* str)
{
  return hexchar2byte(str[0]) << 4 | hexchar2byte(str[1]);
}

inline static char is_wildcard(const char* str)
{
  return (!is_hexchar(str[0]) && !is_hexchar(str[1]));
}

size_t sunday_search_enc(const unsigned char* buffer, size_t size, const char* pattern, size_t len, unsigned char xorbyte)
{
  assert(len % 2 == 0);
  if (len % 2 != 0)
    return SINATURE_SEARCH_NOT_FOUND;

  size_t byte_len = len >> 1;
  const int WILDCARD_INDEX = UCHAR_MAX + 1;
  const int SHIFT_ARRAY_SIZE = WILDCARD_INDEX + 1;
  int s_shift_array[SHIFT_ARRAY_SIZE];

  memset(s_shift_array, 0, sizeof(s_shift_array));
  s_shift_array[WILDCARD_INDEX] = byte_len;
#if 0
  //for(int i = 0;i < SHIFT_ARRAY_SIZE; ++i)
  //  s_shift_array[i] = byte_len;
#endif // 0

  for (int i = 0; i < len; i += 2)
  {
    unsigned short b = !is_wildcard(pattern + i) ? hexstr2byte(&pattern[i]) : WILDCARD_INDEX;
    assert(b < SHIFT_ARRAY_SIZE);
    s_shift_array[b] = byte_len - (i / 2);
  }

  int i = 0;
  while (i <= size - byte_len)
  {
    int  j = 0;
    while (j < len)
    {
      unsigned char byte = hexstr2byte(&pattern[j]);
      if (is_wildcard(&pattern[j]) || buffer[i + (j / 2)] == (xorbyte != 0 ? (byte ^ xorbyte) : byte))
        j += 2;
      else
        break;
    }
    if (j == len)
      return i;

    if (i + byte_len >= size)
      return SINATURE_SEARCH_NOT_FOUND;

    int added = s_shift_array[buffer[i + byte_len]];
    i += added != 0 ? added : s_shift_array[WILDCARD_INDEX];
  }
  return SINATURE_SEARCH_NOT_FOUND;
}

size_t sunday_search(const unsigned char* buffer, size_t size, const char* pattern, size_t len)
{
  return sunday_search_enc(buffer, size, pattern, len, 0);
}

#ifdef _WIN32

#include <Windows.h>
size_t sunday_search_section_enc(const unsigned char* imagebase, const char* pattern, size_t len, unsigned char xorbyte, int attribute)
{
  PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)imagebase;
  PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(imagebase + dos_hdr->e_lfanew);
  if(dos_hdr->e_magic != IMAGE_DOS_SIGNATURE  || nt_hdr->Signature != IMAGE_NT_SIGNATURE)
    return SINATURE_SEARCH_NOT_FOUND;

  PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_hdr);
  int sct_cnt = nt_hdr->FileHeader.SizeOfOptionalHeader;
  for (int i = 0; i < sct_cnt; i++)
  {
    PIMAGE_SECTION_HEADER section = &sections[i];
    if ((section->Characteristics & attribute) == attribute)
    {
      const unsigned char* buffer = imagebase + section->VirtualAddress;
      size_t size = section->Misc.VirtualSize;
      size_t offset = sunday_search_enc(buffer, size, pattern, len, xorbyte);
      if(offset != SINATURE_SEARCH_NOT_FOUND)
        return offset + +section->VirtualAddress;
    }
  }

  return SINATURE_SEARCH_NOT_FOUND;
}

size_t sunday_search_code_enc(const unsigned char* imagebase, const char* pattern, size_t len, unsigned char xorbyte)
{
  return sunday_search_section_enc(imagebase, pattern, len, xorbyte, IMAGE_SCN_MEM_EXECUTE);
}

size_t sunday_search_data_enc(const unsigned char* imagebase, const char* pattern, size_t len, unsigned char xorbyte)
{
  return sunday_search_section_enc(imagebase, pattern, len, xorbyte, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
}

size_t sunday_search_rdata_enc(const unsigned char* imagebase, const char* pattern, size_t len, unsigned char xorbyte)
{
  return sunday_search_section_enc(imagebase, pattern, len, xorbyte, IMAGE_SCN_MEM_READ);
}

#endif // _WIN32

