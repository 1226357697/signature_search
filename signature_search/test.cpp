#include <Windows.h>
#include <assert.h>
#include <vector>
#include <functional>
#include <chrono>
#include "sunday.h"


// 单元测试
void test_sunday_search_pattern() {
  // 测试用例1：简单匹配
  unsigned char buffer[] = { 0xff, 0x25, 0x00, 0x00, 0x00 };
  const char* pattern_hex = "ff25??00";
  size_t buffer_size = sizeof(buffer);

  // 调用sunday_search
  size_t result = sunday_search_pattern(buffer, buffer_size, pattern_hex, strlen(pattern_hex), 0);
  assert(result == 0);  // 预期匹配从索引0开始

  // 测试用例2：不匹配的情况
  const char* pattern_hex2 = "ff25ff00";

  result = sunday_search_pattern(buffer, buffer_size, pattern_hex2, strlen(pattern_hex2), 0);
  assert(result == -1);  // 未找到匹配，返回缓冲区大小

  // 测试用例3：复杂匹配
  const char* pattern_hex3 = "25??00";

  result = sunday_search_pattern(buffer, buffer_size, pattern_hex3, strlen(pattern_hex3), 0);
  assert(result == 1);  // 预期匹配从索引1开始

  // 测试用例4：完全通配符匹配
  const char* pattern_hex4 = "????????";

  result = sunday_search_pattern(buffer, buffer_size, pattern_hex4, strlen(pattern_hex4), 0);
  assert(result == 0);  // 任何情况下都应匹配到开头

  printf("所有单元测试都通过了！\n");
}

void test_sunday_search_bytes() {
  // 测试用例1：简单匹配
  unsigned char buffer[] = { 0xff, 0x25, 0x00, 0x00, 0x00 };
  const uint8_t pattern_hex[] = {0Xff, 0X25, 0X00, 0X00};
  uint64_t mark1 = 1ULL <<2;
  size_t buffer_size = sizeof(buffer);

  // 调用sunday_search
  size_t result = sunday_search_bytes(buffer, buffer_size, pattern_hex, sizeof(pattern_hex), mark1, 0);
  assert(result == 0);  // 预期匹配从索引0开始

  // 测试用例2：不匹配的情况
  const uint8_t pattern_hex2[] = { 0Xff, 0X25, 0Xff, 0X00 };
  uint64_t mark2 = 0;

  result = sunday_search_bytes(buffer, buffer_size, pattern_hex2, sizeof(pattern_hex2), mark2, 0);
  assert(result == -1);  // 未找到匹配，返回缓冲区大小

  // 测试用例3：复杂匹配
  const uint8_t pattern_hex3[] = { 0X25, 0, 0X00 };
  uint64_t mark3 = 1<<1;

  result = sunday_search_bytes(buffer, buffer_size, pattern_hex3, sizeof(pattern_hex3), mark3, 0);
  assert(result == 1);  // 预期匹配从索引1开始

  // 测试用例4：完全通配符匹配
  const uint8_t pattern_hex4[] = { 0X25, 0, 0X00 ,0};
  uint64_t mark4 = 1 << 0 | 1<<1 | 1 <<2 | 1<<3;

  result = sunday_search_bytes(buffer, buffer_size, pattern_hex4, sizeof(pattern_hex4), mark4, 0);
  assert(result == 0);  // 任何情况下都应匹配到开头

  printf("所有单元测试都通过了！\n");
}

class scope_clocker
{
public:
  using action_type = std::function<void(std::chrono::steady_clock::time_point, std::chrono::steady_clock::time_point)>;
  scope_clocker(action_type action)
    :start_(std::chrono::high_resolution_clock::now()), action_(action)
  {
  }
  ~scope_clocker()
  {
    std::chrono::steady_clock::time_point end = std::chrono::high_resolution_clock::now();
    action_(start_, end);
  }

public:
  std::chrono::steady_clock::time_point start_;
  action_type action_;
};

void test_search_signature_pattern(DWORD pid, const char* pattern)
{
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (process == NULL)
    return;

  size_t pattern_len = strlen(pattern);
  MEMORY_BASIC_INFORMATION mm_info;
  SYSTEM_INFO sys_info;
  GetSystemInfo(&sys_info);
  std::vector<unsigned char*> collect;
  std::vector<MEMORY_BASIC_INFORMATION> mm_infos;
  for (char* address = (char*)sys_info.lpMinimumApplicationAddress; address < (char*)sys_info.lpMaximumApplicationAddress; address += mm_info.RegionSize)
  {
    if (VirtualQueryEx(process, address, &mm_info, sizeof(mm_info)) == sizeof(mm_info) && (mm_info.State & MEM_COMMIT) != 0)
    {
      mm_infos.push_back(mm_info);
    }
  }

  {
    scope_clocker clocker([](std::chrono::steady_clock::time_point start, std::chrono::steady_clock::time_point end) {

      std::chrono::steady_clock::time_point diff(end - start);
      long long diff_count = std::chrono::duration_cast<std::chrono::milliseconds>(diff.time_since_epoch()).count();
      printf("耗时%.2fs(%lldms)", diff_count / 1000.0f, diff_count);
      });


    /// 0x0000017e29e71000
    size_t buffer_size = 0x1000;
    unsigned char* buffer = new unsigned char[buffer_size];
    for (const auto& info : mm_infos)
      //const auto& info = *std::find_if(mm_infos.begin(), mm_infos.end(), [](const MEMORY_BASIC_INFORMATION& e) {
      //    return e.BaseAddress == (PVOID)0x0000017e29e71000;
      //  });
    {
      if (buffer_size < info.RegionSize)
      {
        delete[] buffer;
        buffer_size = info.RegionSize;
        buffer = new unsigned char[buffer_size];
      }

      SIZE_T bytesofread = 0;
      if (ReadProcessMemory(process, info.BaseAddress, buffer, info.RegionSize, &bytesofread) && bytesofread > 0)
      {
        if ((PVOID)0x194DD14A6F3 >= info.BaseAddress && (CHAR*)0x194DD14A6F3 < (CHAR*)info.BaseAddress + info.RegionSize)
        {
          int j = 0;
        }

        size_t pos = 0;
        do
        {

          size_t i = sunday_search_pattern(buffer + pos, bytesofread - pos, pattern, pattern_len, 0);
          if (i == -1)
            break;
          pos += i;
          collect.push_back((unsigned char*)info.BaseAddress + pos);
          pos += pattern_len / 2;
        } while (pos < bytesofread);


      }
    }
    delete[] buffer;
  }

  printf("collect count:%d\n", collect.size());
  for (auto& i : collect)
  {
    printf("address:%p\n", i);
  }
  CloseHandle(process);
}



void test_search_signature_bytes(DWORD pid, const uint8_t* bytes, size_t bytes_len, uint64_t mark)
{
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (process == NULL)
    return;

  MEMORY_BASIC_INFORMATION mm_info;
  SYSTEM_INFO sys_info;
  GetSystemInfo(&sys_info);
  std::vector<unsigned char*> collect;
  std::vector<MEMORY_BASIC_INFORMATION> mm_infos;
  for (char* address = (char*)sys_info.lpMinimumApplicationAddress; address < (char*)sys_info.lpMaximumApplicationAddress; address += mm_info.RegionSize)
  {
    if (VirtualQueryEx(process, address, &mm_info, sizeof(mm_info)) == sizeof(mm_info) && (mm_info.State & MEM_COMMIT) != 0)
    {
      mm_infos.push_back(mm_info);
    }
  }

  {
    scope_clocker clocker([](std::chrono::steady_clock::time_point start, std::chrono::steady_clock::time_point end) {

      std::chrono::steady_clock::time_point diff(end - start);
      long long diff_count = std::chrono::duration_cast<std::chrono::milliseconds>(diff.time_since_epoch()).count();
      printf("耗时%.2fs(%lldms)", diff_count / 1000.0f, diff_count);
      });


    /// 0x0000017e29e71000
    size_t buffer_size = 0x1000;
    unsigned char* buffer = new unsigned char[buffer_size];
    for (const auto& info : mm_infos)
      //const auto& info = *std::find_if(mm_infos.begin(), mm_infos.end(), [](const MEMORY_BASIC_INFORMATION& e) {
      //    return e.BaseAddress == (PVOID)0x0000017e29e71000;
      //  });
    {
      if (buffer_size < info.RegionSize)
      {
        delete[] buffer;
        buffer_size = info.RegionSize;
        buffer = new unsigned char[buffer_size];
      }

      SIZE_T bytesofread = 0;
      if (ReadProcessMemory(process, info.BaseAddress, buffer, info.RegionSize, &bytesofread) && bytesofread > 0)
      {
        if ((PVOID)0x7FF9AF9FD0A4 >= info.BaseAddress && (CHAR*)0x7FF9AF9FD0A4 < (CHAR*)info.BaseAddress + info.RegionSize)
        {
          int j = 0;
        }

        size_t pos = 0;
        do
        {

          size_t i = sunday_search_bytes(buffer + pos, bytesofread - pos, bytes, bytes_len, mark, 0);
          if (i == -1)
            break;
          pos += i;
          collect.push_back((unsigned char*)info.BaseAddress + pos);
          pos += bytes_len;
        } while (pos < bytesofread);


      }
    }
    delete[] buffer;
  }

  printf("collect count:%d\n", collect.size());
  for (auto& i : collect)
  {
    printf("address:%p\n", i);
  }
  CloseHandle(process);
}

int main()
{

  //unsigned char buffer[] = {0x80, 0xc8, 0x01, 0x00, 0x00, 0x48, 0xff, 0x25, 0xa1, 0x48, 0x03, 0x00, 0xcc, 0xcc, 0xcc, 0xcc};
  //uint8_t bytes[] = {0xff, 0x25, 0x0,0x48};
  //uint64_t mark = 1 << 2;

  //size_t i = sunday_search_pattern(buffer, sizeof(buffer), "ff25??48", strlen("ff25??48"), 0);
  //size_t j = sunday_search_bytes(buffer, sizeof(buffer), bytes, sizeof(bytes), mark,0);


  //test_sunday_search_pattern();
  // test_sunday_search_bytes();
  int pid = 9896;
  test_search_signature_pattern(pid, "ff25??48");
  test_search_signature_pattern(pid, "ff2548");

  uint8_t bytes2[] = { 0xff, 0x25, 0x00, 0x48 };
  uint64_t mark2 = 1<< 2;
  test_search_signature_bytes(pid, bytes2, sizeof(bytes2), mark2);

  uint8_t bytes3[] = { 0xff, 0x25, 0x48 };
  uint64_t mark3 = 0;
  test_search_signature_bytes(pid, bytes3, sizeof(bytes3), mark3);

  return 0;
}