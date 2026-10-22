#include "weixin4/notification_contract.h"

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
constexpr std::uint64_t closure = 0x1000;
constexpr std::uint64_t control = 0x2000;
constexpr std::uint64_t records = 0x3000;
constexpr std::uint64_t stride = 0x2e8;
const BinaryIdentity identity{kVersion, kSha256, kMachine};

Snapshot Fixture(std::size_t count = 2, std::uint64_t image_base = base) {
  Snapshot memory;
  memory.U64(closure, image_base + 0x90d86e8);
  // Deliberately unmapped: observation must not follow or invoke these.
  memory.U64(closure + 8, 0x9000);
  memory.U64(closure + 0x10, 0xa000);
  memory.U64(closure + 0x48, 0xb000);
  memory.U64(closure + 0x50, 0xc000);
  memory.U64(closure + 0x58, control);
  memory.U32(control + 8, 2);
  memory.U32(control + 12, 1);
  memory.U64(closure + 0x68, count ? records : 0);
  memory.U64(closure + 0x70, count ? records + count * stride : 0);
  // Spare capacity is unmapped and must not be decoded.
  memory.U64(closure + 0x78, count ? records + (count + 1) * stride : 0);
  for (std::size_t i = 0; i < count; ++i) {
    const auto record = records + i * stride;
    memory.U32(record + 0xc, 0xf0000000U + static_cast<std::uint32_t>(i));
    memory.U64(record + 0x148, 0xfedcba9800000000ULL + i);
    memory.U64(record + 0x150, 123 + i);
    for (const auto offset : {0x164, 0x168, 0x16c, 0x170, 0x178})
      memory.U32(record + offset, 0xffffffffU);
    memory.String(record + 0x18, "from");
    memory.String(record + 0x38, "to");
    memory.String(record + 0x58, "sender");
    memory.String(record + 0x180, i ? "second" : "first");
  }
  return memory;
}

void Cleared(const NotificationDispatchSnapshot& value) {
  CHECK(!value.callback_context_address && !value.callback_function_address);
  CHECK(!value.scheduler_address && value.records.empty());
  CHECK(!value.lifetime_owner.object_address && !value.lifetime_owner.control_block_address);
  CHECK(!value.lifetime_owner.strong_count && !value.lifetime_owner.weak_count);
  CHECK(!value.lifetime_owner.has_control_block);
}
}  // namespace

int main() {
  auto memory = Fixture();
  NotificationDispatchSnapshot value;
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::None);
  CHECK(value.callback_context_address == 0x9000 && value.callback_function_address == 0xa000);
  CHECK(value.scheduler_address == 0xb000 && value.lifetime_owner.object_address == 0xc000);
  CHECK(value.lifetime_owner.control_block_address == control && value.lifetime_owner.has_control_block);
  CHECK(value.lifetime_owner.strong_count == 2 && value.lifetime_owner.weak_count == 1);
  CHECK(value.records.size() == 2 && value.records[1].server_id == 0xfedcba9800000001ULL);
  CHECK(value.records[0].message_type == 0xf0000000U && value.records[1].time_raw == 0xffffffffU);
  memory.bytes.clear();
  CHECK(value.records[0].content == "first" && value.records[1].content == "second");
  memory = Fixture(0);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::None);
  CHECK(value.records.empty());
  memory = Fixture(1, 0x7ff800000000ULL);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, 0x7ff800000000ULL, closure, value) == ReadError::None);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::InvalidObject);
  Cleared(value);

  memory = Fixture(1);
  memory.U64(closure + 8, 0);
  memory.U64(closure + 0x50, 0);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::None);
  CHECK(!value.callback_context_address && !value.lifetime_owner.object_address);
  CHECK(value.lifetime_owner.has_control_block);  // Null alias with nonempty control.
  memory.U64(closure + 0x58, 0);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::None);
  CHECK(!value.lifetime_owner.has_control_block);
  memory.U64(closure + 0x50, 0xf0000000);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::None);
  CHECK(value.lifetime_owner.object_address == 0xf0000000 && !value.lifetime_owner.has_control_block);

  for (const auto at : {closure, closure + 0x10, closure + 0x48}) {
    memory = Fixture();
    memory.U64(at, 0);
    CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::InvalidObject);
    Cleared(value);
  }
  for (const auto offset : {8U, 12U}) {
    for (const auto count : {0U, 0x80000000U, 0xffffffffU}) {
      memory = Fixture();
      memory.U32(control + offset, count);
      CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::InvalidObject);
      Cleared(value);
    }
  }
  for (const auto at : {closure + 0x17, closure + 0x5f, control + 15, closure + 0x7f,
                        records + stride + 0x180 + 31}) {
    memory = Fixture();
    memory.bytes.erase(at);
    CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::Unreadable);
    Cleared(value);
  }
  memory = Fixture();
  memory.U64(closure + 0x70, records + 1);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::InvalidVector);
  Cleared(value);
  memory = Fixture();
  memory.U64(records + stride + 0x180 + 16, 16);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::InvalidString);
  Cleared(value);
  memory = Fixture();
  Limits limits;
  limits.max_elements = 1;
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value, limits) == ReadError::LimitExceeded);
  Cleared(value);
  limits.max_elements = 2;
  limits.max_total_string_bytes = 4 + 2 + 6 + 5 + 4 + 2 + 6 + 6;
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value, limits) == ReadError::None);
  --limits.max_total_string_bytes;
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value, limits) == ReadError::LimitExceeded);
  Cleared(value);
  memory = Fixture(1);
  const std::string text = std::string("queued raw content") + '\0' + "tail";
  memory.String(records + 0x180, text, 0x5000);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, closure, value) == ReadError::None);
  CHECK(value.records[0].content == text);

  memory = Fixture();
  auto wrong = identity;
  wrong.sha256[0] = 'f';
  CHECK(ReadNotificationDispatchSnapshot(memory, wrong, base, closure, value) == ReadError::ProfileMismatch);
  CHECK(memory.reads == 0);
  Cleared(value);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, 0, closure, value) == ReadError::InvalidObject);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, 0, value) == ReadError::InvalidObject);
  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, maximum, closure, value) == ReadError::AddressOverflow);
  CHECK(ReadNotificationDispatchSnapshot(memory, identity, base, maximum - 32, value) == ReadError::AddressOverflow);
  Cleared(value);
  std::cout << "weixin4 notification dispatch snapshot tests passed\n";
}
