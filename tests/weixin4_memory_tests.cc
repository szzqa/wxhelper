#include "weixin4/memory_reader.h"
#include "weixin4/profile.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <limits>

using namespace wxhelper::weixin4;
namespace {
class Snapshot final : public MemoryReader {
 public:
  std::vector<unsigned char> bytes = std::vector<unsigned char>(4096);
  bool Read(std::uint64_t address, void* out, std::size_t count) const override {
    if (address > bytes.size() || count > bytes.size() - address) return false;
    std::memcpy(out, bytes.data() + address, count);
    return true;
  }
  void U64(std::size_t at, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) bytes.at(at + i) = static_cast<unsigned char>(value >> (8 * i));
  }
  void String(std::size_t at, const std::string& value, std::size_t heap = 0) {
    assert(value.size() < 16 || heap);
    std::memset(bytes.data() + at, 0, 32);
    U64(at + 16, value.size());
    U64(at + 24, heap ? value.size() : 15);
    if (heap) U64(at, heap);
    std::memcpy(bytes.data() + (heap ? heap : at), value.c_str(), value.size() + 1);
  }
};
}

int main() {
  Snapshot memory;
  std::string value;
  memory.String(64, "wxid_test");
  assert(ReadString(memory, 64, value) == ReadError::None && value == "wxid_test");
  const std::string long_value = "contact_user_with_long_identifier";
  memory.String(128, long_value, 1024);
  assert(ReadString(memory, 128, value) == ReadError::None && value == long_value);
  memory.String(192, std::string("a\0b", 3));
  assert(ReadString(memory, 192, value) == ReadError::None && value.size() == 3);
  memory.U64(64 + 16, 16);
  assert(ReadString(memory, 64, value) == ReadError::InvalidString && value.empty());
  memory.String(64, "wxid_test");
  memory.bytes[64 + 9] = 1;
  assert(ReadString(memory, 64, value) == ReadError::InvalidString);
  memory.U64(128, 4090);
  assert(ReadString(memory, 128, value) == ReadError::Unreadable);
  memory.U64(128, (std::numeric_limits<std::uint64_t>::max)() - 2);
  assert(ReadString(memory, 128, value) == ReadError::AddressOverflow);
  Limits limited;
  limited.max_string_bytes = 4;
  memory.String(64, "12345");
  assert(ReadString(memory, 64, value, limited) == ReadError::LimitExceeded);
  assert(ReadString(memory, (std::numeric_limits<std::uint64_t>::max)(), value) == ReadError::AddressOverflow);

  // Third pointer is reserved capacity, not an extra live contact identifier.
  memory.U64(256, 512); memory.U64(264, 576); memory.U64(272, 608);
  memory.String(512, "alice"); memory.String(544, "bob");
  memory.U64(592, 9999);  // Poison the unused capacity element.
  std::vector<std::string> values;
  assert(ReadStringVector(memory, 256, values) == ReadError::None);
  assert(values.size() == 2 && values[1] == "bob");
  limited.max_string_bytes = 1024;
  limited.max_total_string_bytes = 7;
  assert(ReadStringVector(memory, 256, values, limited) == ReadError::LimitExceeded && values.empty());
  limited.max_total_string_bytes = 8;
  assert(ReadStringVector(memory, 256, values, limited) == ReadError::None);
  limited.max_elements = 1;
  assert(ReadStringVector(memory, 256, values, limited) == ReadError::LimitExceeded);
  VectorRange range;
  memory.U64(264, 577);
  assert(ReadVectorRange(memory, 256, 32, range) == ReadError::InvalidVector);
  memory.U64(264, 480);
  assert(ReadVectorRange(memory, 256, 32, range) == ReadError::InvalidVector);
  memory.U64(256, 0); memory.U64(264, 0); memory.U64(272, 0);
  assert(ReadStringVector(memory, 256, values) == ReadError::None && values.empty());
  assert(ReadVectorRange(memory, 256, 0, range) == ReadError::InvalidVector);
  memory.U64(272, 64);
  assert(ReadVectorRange(memory, 256, 32, range) == ReadError::InvalidVector);

  BinaryIdentity identity{kVersion, kSha256, kMachine};
  assert(MatchesProfile(identity));
  for (char& c : identity.sha256) if (c >= 'a' && c <= 'f') c -= 'a' - 'A';
  assert(MatchesProfile(identity));
  identity.version = "4.1.15.14";
  assert(!MatchesProfile(identity));
  identity = {kVersion, "b8cc1844a6ef2a092baa06976ffb11195f845e02877a6a0126576112b96fe5fb", kMachine};
  assert(!MatchesProfile(identity));
  identity = {kVersion, kSha256, 0x14c};
  assert(!MatchesProfile(identity));
  assert(!kRuntimeSupported);
  std::cout << "Weixin 4 snapshot strings, containers, limits and identity: PASS\n";
}
