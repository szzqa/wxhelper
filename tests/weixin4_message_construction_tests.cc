#include "weixin4/message_construction.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>

using namespace wxhelper::weixin4;
#define CHECK(e) do { if (!(e)) { std::cerr << "line " << __LINE__ << ": " #e "\n"; std::exit(1); } } while (false)

namespace {
class Snapshot final : public MemoryReader {
 public:
  std::map<std::uint64_t, unsigned char> bytes;
  mutable std::size_t reads = 0;
  bool Read(std::uint64_t at, void* destination, std::size_t size) const override {
    ++reads;
    auto* out = static_cast<unsigned char*>(destination);
    for (std::size_t i = 0; i < size; ++i) {
      const auto found = bytes.find(at + i);
      if (found == bytes.end()) return false;
      out[i] = found->second;
    }
    return true;
  }
  void U64(std::uint64_t at, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
      bytes[at + i] = static_cast<unsigned char>(value >> (8 * i));
  }
  void U32(std::uint64_t at, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
      bytes[at + i] = static_cast<unsigned char>(value >> (8 * i));
  }
  void String(std::uint64_t at, const std::string& value, std::uint64_t heap = 0) {
    for (unsigned i = 0; i < 32; ++i) bytes[at + i] = 0;
    if (heap) U64(at, heap);
    U64(at + 16, value.size());
    U64(at + 24, heap ? value.size() : 15);
    const auto start = heap ? heap : at;
    for (std::size_t i = 0; i < value.size(); ++i)
      bytes[start + i] = static_cast<unsigned char>(value[i]);
    bytes[start + value.size()] = 0;
  }
};
constexpr std::uint64_t base = 0x180000000ULL;
constexpr std::uint64_t pair = 0x1000;
constexpr std::uint64_t control = 0x2000;
constexpr std::uint64_t object = control + 0x10;
const BinaryIdentity identity{kVersion, kSha256, kMachine};

Snapshot Fixture(std::uint64_t image_base = base) {
  Snapshot memory;
  memory.U64(pair, object);
  memory.U64(pair + 8, control);
  memory.U64(control, image_base + 0x8e534f8);
  memory.U32(control + 8, 1);
  memory.U32(control + 12, 2);
  memory.U64(object, image_base + 0x8e53588);
  memory.U64(object + 8, object);
  memory.U64(object + 0x10, control);
  memory.U32(object + 0x118, 1);
  memory.String(object + 0xb0, "fixture_chat");
  memory.String(object + 0x758, "fixture text");
  return memory;
}

void Cleared(const TextMessageDraftSnapshot& value) {
  CHECK(value.chat_id.empty() && value.text_argument_bytes.empty());
  CHECK(value.word_118_raw == 0);
  CHECK(!value.owner.object_address && !value.owner.control_block_address);
  CHECK(!value.owner.strong_count && !value.owner.weak_count);
  CHECK(!value.owner.has_control_block);
}
}  // namespace

int main() {
  auto memory = Fixture();
  TextMessageDraftSnapshot result;
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::None);
  CHECK(result.chat_id == "fixture_chat" && result.text_argument_bytes == "fixture text");
  CHECK(result.word_118_raw == 1 && result.owner.object_address == object);
  CHECK(result.owner.control_block_address == control && result.owner.strong_count == 1);
  CHECK(result.owner.weak_count == 2 && result.owner.has_control_block);
  // All other object fields, native vtable bytes and callbacks are unmapped.
  // Only the selected construction layout is required by this reader.
  for (const auto word : {0U, 1U, 2U, 0xffffffffU}) {
    memory.U32(object + 0x118, word);
    CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::None);
    CHECK(result.word_118_raw == word);
  }
  memory.U32(control + 8, 5);
  memory.U32(control + 12, 8);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::None);
  CHECK(result.owner.strong_count == 5 && result.owner.weak_count == 8);
  memory = Fixture(0x7ff800000000ULL);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, 0x7ff800000000ULL, pair, result) == ReadError::None);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::InvalidObject);
  Cleared(result);

  memory = Fixture();
  const std::string text = std::string("long text argument") + '\0' + "with raw bytes";
  memory.String(object + 0x758, text, 0x4000);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::None);
  CHECK(result.text_argument_bytes == text);
  memory.bytes[0x4000] = 'X';
  CHECK(result.text_argument_bytes == text);
  memory.String(object + 0x758, text, 0x4000);
  Limits limits;
  limits.max_string_bytes = text.size();
  limits.max_total_string_bytes = text.size() + std::string("fixture_chat").size();
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result, limits) == ReadError::None);
  --limits.max_total_string_bytes;
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result, limits) == ReadError::LimitExceeded);
  Cleared(result);
  ++limits.max_total_string_bytes;
  --limits.max_string_bytes;
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result, limits) == ReadError::LimitExceeded);
  Cleared(result);
  memory.String(object + 0xb0, "");
  memory.String(object + 0x758, "");
  limits.max_string_bytes = limits.max_total_string_bytes = 0;
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result, limits) == ReadError::None);
  CHECK(result.chat_id.empty() && result.text_argument_bytes.empty());

  // A stable owner cannot have non-positive/overflowed interlocked counters.
  for (const auto count : {0U, 0x80000000U, 0xffffffffU}) {
    memory = Fixture();
    memory.U32(control + 8, count);
    CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::InvalidObject);
    Cleared(result);
  }
  for (const auto count : {0U, 1U, 0x80000000U, 0xffffffffU}) {
    memory = Fixture();
    memory.U32(control + 12, count);
    CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::InvalidObject);
    Cleared(result);
  }
  for (const auto at : {pair, pair + 8, control, object, object + 8, object + 0x10}) {
    memory = Fixture();
    memory.U64(at, 0);
    CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::InvalidObject);
    Cleared(result);
  }
  memory = Fixture();
  memory.U64(pair, object + 8);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::InvalidObject);
  Cleared(result);
  for (const auto at : {pair + 15, control + 15, object + 0x17,
                        object + 0x11b, object + 0xb0 + 31, object + 0x758 + 31}) {
    memory = Fixture();
    memory.bytes.erase(at);
    CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::Unreadable);
    Cleared(result);
  }
  memory = Fixture();
  memory.U64(object + 0x758 + 16, 16);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::InvalidString);
  Cleared(result);
  memory = Fixture();
  memory.String(object + 0x758, text, 0x4000);
  memory.bytes.erase(0x4000 + text.size());
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, pair, result) == ReadError::Unreadable);
  Cleared(result);

  memory = Fixture();
  auto wrong = identity;
  wrong.sha256[0] = 'f';
  CHECK(ReadTextMessageDraftSnapshot(memory, wrong, base, pair, result) == ReadError::ProfileMismatch);
  CHECK(memory.reads == 0);
  Cleared(result);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, 0, pair, result) == ReadError::InvalidObject);
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, base, 0, result) == ReadError::InvalidObject);
  const auto max = (std::numeric_limits<std::uint64_t>::max)();
  CHECK(ReadTextMessageDraftSnapshot(memory, identity, max, pair, result) == ReadError::AddressOverflow);
  Cleared(result);
  Snapshot overflow;
  overflow.U64(max - 7, object);
  CHECK(ReadTextMessageDraftSnapshot(overflow, identity, base, max - 7, result) == ReadError::AddressOverflow);
  Cleared(result);
  overflow = Fixture();
  overflow.U64(pair + 8, max - 7);
  CHECK(ReadTextMessageDraftSnapshot(overflow, identity, base, pair, result) == ReadError::AddressOverflow);
  Cleared(result);
  std::cout << "weixin4 text message construction snapshot tests passed\n";
}
