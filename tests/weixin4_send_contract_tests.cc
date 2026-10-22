#include "weixin4/send_contract.h"

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
  void U64(std::uint64_t at, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) bytes[at + i] = static_cast<unsigned char>(v >> (i * 8));
  }
  void String(std::uint64_t at, const std::string& value, std::uint64_t heap = 0) {
    for (unsigned i = 0; i < 32; ++i) bytes[at + i] = 0;
    if (heap) U64(at, heap);
    U64(at + 16, value.size());
    U64(at + 24, heap ? value.size() : 15);
    auto start = heap ? heap : at;
    for (std::size_t i = 0; i < value.size(); ++i) bytes[start + i] = value[i];
    bytes[start + value.size()] = 0;
  }
};
const BinaryIdentity identity{kVersion, kSha256, kMachine};
constexpr std::uint64_t address = 0x1000;
Snapshot Fixture() {
  Snapshot memory;
  memory.U64(address, 0);
  memory.String(address + 8, "fixture detail");
  // Deliberately not mapped: the payload's object/owner types remain unknown.
  memory.U64(address + 0x28, 0xfedcba9876543210ULL);
  memory.U64(address + 0x30, 0xabcdef9876543210ULL);
  return memory;
}
void Cleared(const TextSendCompletionSnapshot& result) {
  CHECK(result.status.status_word0 == 0 && result.status.status_word1 == 0);
  CHECK(!result.status.call_succeeded && result.detail_string.empty());
  CHECK(!result.payload_object_address && !result.payload_control_address);
}
}  // namespace

int main() {
  auto memory = Fixture();
  TextSendCompletionSnapshot result;
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::None);
  CHECK(result.status.call_succeeded && result.detail_string == "fixture detail");
  CHECK(result.payload_object_address == 0xfedcba9876543210ULL);
  CHECK(result.payload_control_address == 0xabcdef9876543210ULL);
  memory.String(address + 8, "");
  memory.U64(address + 0x28, 0);
  memory.U64(address + 0x30, 0);
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::None);
  CHECK(result.detail_string.empty() && result.payload_object_address == 0 && result.payload_control_address == 0);
  for (auto words : {0ULL, 1ULL, 0x100000000ULL, 0xffffffffffffffffULL}) {
    memory.U64(address, words);
    CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::None);
    CHECK(result.status.call_succeeded == (words == 0));
    CHECK(result.status.status_word0 == static_cast<std::uint32_t>(words));
    CHECK(result.status.status_word1 == static_cast<std::uint32_t>(words >> 32));
  }
  const std::string detail = std::string("long owned detail") + '\0' + "with bytes";
  memory.String(address + 8, detail, 0x2000);
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::None);
  CHECK(result.detail_string == detail);
  memory.bytes[0x2000] = 'X';
  CHECK(result.detail_string == detail);
  memory.String(address + 8, detail, 0x2000);
  Limits limits;
  limits.max_string_bytes = detail.size();
  limits.max_total_string_bytes = detail.size();
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result, limits) == ReadError::None);
  --limits.max_total_string_bytes;
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result, limits) == ReadError::LimitExceeded);
  Cleared(result);
  limits.max_total_string_bytes = detail.size();
  --limits.max_string_bytes;
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result, limits) == ReadError::LimitExceeded);
  Cleared(result);
  memory.bytes.erase(0x2000 + detail.size());
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::Unreadable);
  Cleared(result);
  memory.bytes[0x2000 + detail.size()] = 'x';
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::InvalidString);
  Cleared(result);
  memory = Fixture();
  memory.bytes.erase(address + 0x37);
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, address, result) == ReadError::Unreadable);
  Cleared(result);
  memory = Fixture();
  auto wrong = identity;
  wrong.sha256[0] = 'f';
  CHECK(ReadTextSendCompletionSnapshot(memory, wrong, address, result) == ReadError::ProfileMismatch);
  CHECK(memory.reads == 0);
  Cleared(result);
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, 0, result) == ReadError::InvalidObject);
  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  memory.U64(maximum - 7, 0);
  CHECK(ReadTextSendCompletionSnapshot(memory, identity, maximum - 7, result) == ReadError::AddressOverflow);
  Cleared(result);
  // The original status-only interface still accepts exactly eight bytes.
  Snapshot prefix;
  prefix.U64(address, 0);
  TextSendResultSnapshot status;
  CHECK(ReadTextSendResultSnapshot(prefix, identity, address, status) == ReadError::None);
  CHECK(status.call_succeeded);
  CHECK(ReadTextSendCompletionSnapshot(prefix, identity, address, result) == ReadError::Unreadable);
  std::cout << "weixin4 send completion contract tests passed\n";
}
