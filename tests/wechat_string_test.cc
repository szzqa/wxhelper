// Standalone offline test: compile with an x64 C++17 compiler; no DLL is loaded.
#include <Windows.h>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <new>
#include <string>
#include <vector>
#include "../src/wechat_function.h"

using wxhelper::V3_9_5_81::prototype::WeChatString;

static_assert(sizeof(WeChatString) == 0x20, "Preserve the 3.9.5.81 x64 ABI");
static_assert(offsetof(WeChatString, ptr) == 0);
static_assert(offsetof(WeChatString, length) == 8);
static_assert(offsetof(WeChatString, max_length) == 12);
static_assert(offsetof(WeChatString, c_ptr) == 16);
static_assert(offsetof(WeChatString, c_len) == 24);

void CheckEmpty(const WeChatString &value) {
  assert(value.ptr == nullptr);
  assert(value.length == 0 && value.max_length == 0);
  assert(value.c_ptr == 0 && value.c_len == 0);
}

int main() {
  // Poison memory so the original temporary-constructor bug cannot pass by luck.
  alignas(WeChatString) unsigned char storage[sizeof(WeChatString)];
  memset(storage, 0xA5, sizeof(storage));
  auto *empty = new (storage) WeChatString;
  CheckEmpty(*empty);
  empty->~WeChatString();

  const wchar_t *text = L"hello";
  memset(storage, 0xA5, sizeof(storage));
  auto *constant = new (storage) WeChatString(text);
  assert(constant->ptr == text);
  assert(constant->length == 5 && constant->max_length == 5);
  assert(constant->c_ptr == 0 && constant->c_len == 0);
  constant->~WeChatString();

  wchar_t mutable_text[] = L"hello";
  WeChatString mutable_value(mutable_text);
  assert(mutable_value.ptr == mutable_text && mutable_value.length == 5);
  std::wstring owned_text = L"hello";
  WeChatString string_value(owned_text);
  assert(string_value.ptr == owned_text.c_str() && string_value.length == 5);
  CheckEmpty(WeChatString(0));
  CheckEmpty(WeChatString(static_cast<const wchar_t *>(nullptr)));
  CheckEmpty(WeChatString(static_cast<wchar_t *>(nullptr)));
  mutable_value.set_value(text);
  assert(mutable_value.length == 5 && mutable_value.max_length == 10);
  mutable_value.set_value(nullptr);
  CheckEmpty(mutable_value);
}
