#include "weixin4/receive_contract.h"

#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace wxhelper::weixin4;

namespace {
void Check(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

class Snapshot final : public MemoryReader {
 public:
  std::vector<unsigned char> bytes = std::vector<unsigned char>(4096);
  mutable std::size_t reads = 0;
  bool Read(std::uint64_t at, void* out, std::size_t count) const override {
    ++reads;
    if (at > bytes.size() || count > bytes.size() - at) return false;
    std::memcpy(out, bytes.data() + at, count);
    return true;
  }
  void U64(std::size_t at, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i)
      bytes.at(at + i) = static_cast<unsigned char>(value >> (i * 8));
  }
  void String(std::size_t at, const std::string& text) {
    Check(text.size() <= 15, "fixture uses inline strings");
    std::memcpy(bytes.data() + at, text.c_str(), text.size() + 1);
    U64(at + 16, text.size());
    U64(at + 24, 15);
  }
};

constexpr std::size_t kResult = 0x100;
constexpr std::size_t kRecords = 0x200;
constexpr std::size_t kStride = 0x2e8;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

Snapshot Fixture(unsigned char flag, std::size_t count) {
  Snapshot memory;
  memory.U64(kResult, count ? kRecords : 0);
  memory.U64(kResult + 8, count ? kRecords + count * kStride : 0);
  // Spare capacity is deliberately not populated and must not be decoded.
  memory.U64(kResult + 16, count ? kRecords + (count + 1) * kStride : 0);
  memory.bytes[kResult + 24] = flag;
  for (std::size_t i = 0; i < count; ++i) {
    const auto record = kRecords + i * kStride;
    memory.U64(record + 0x148, 0xf000000000000001ull + i);
    memory.String(record + 0x18, "peer-a");
    memory.String(record + 0x38, "peer-b");
    memory.String(record + 0x58, "sender");
    memory.String(record + 0x180, i ? "second" : "first");
  }
  return memory;
}

void CheckCleared(const ReceiveStorageResultSnapshot& value) {
  Check(!value.storage_result_flag && value.success_subset.empty(), "error clears full result");
}
}  // namespace

int main() {
  ReceiveStorageResultSnapshot value;
  auto memory = Fixture(1, 2);
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value) == ReadError::None,
        "decode extracted storage payload");
  Check(value.storage_result_flag && value.success_subset.size() == 2,
        "result flag and subset are independent observations");
  Check(value.success_subset[0].server_id == 0xf000000000000001ull &&
        value.success_subset[1].server_id == 0xf000000000000002ull,
        "full 64-bit IDs and exact record stride");
  memory.bytes.assign(memory.bytes.size(), 0);
  Check(value.success_subset[0].content == "first" && value.success_subset[1].content == "second",
        "DTO owns its strings after native storage disappears");

  for (const auto count : {0u, 1u}) {
    for (const auto flag : {0u, 1u}) {
      memory = Fixture(static_cast<unsigned char>(flag), count);
      Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value) == ReadError::None,
            "retain flag and subset without inventing a cross-field invariant");
      Check(value.storage_result_flag == (flag != 0) && value.success_subset.size() == count,
            "empty success is permitted and true does not encode original batch count");
    }
  }

  for (const auto flag : {2u, 255u}) {
    memory = Fixture(static_cast<unsigned char>(flag), 1);
    Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value) == ReadError::InvalidObject,
          "reject noncanonical native bool");
    Check(memory.reads == 1, "invalid bool rejects before dereferencing the vector");
    CheckCleared(value);
  }

  memory = Fixture(1, 2);
  Limits limits;
  limits.max_elements = 1;
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value, limits) == ReadError::LimitExceeded,
        "element budget applies to result subset");
  CheckCleared(value);
  limits.max_elements = 10;
  limits.max_total_string_bytes = 25;
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value, limits) == ReadError::LimitExceeded,
        "string budget spans all records");
  CheckCleared(value);

  memory = Fixture(1, 2);
  memory.U64(kRecords + kStride + 0x180 + 16, 16);
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value) == ReadError::InvalidString,
        "late invalid record must not leak early subset members or flag");
  CheckCleared(value);
  memory = Fixture(1, 1);
  memory.U64(kResult + 8, kRecords + kStride - 1);
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value) == ReadError::InvalidVector,
        "partial native record is invalid");
  CheckCleared(value);

  memory = Fixture(1, 1);
  auto wrong = kIdentity;
  wrong.sha256[0] = 'f';
  Check(ReadReceiveStorageResultSnapshot(memory, wrong, kResult, value) == ReadError::ProfileMismatch,
        "profile gate");
  Check(memory.reads == 0, "profile mismatch must not read snapshot");
  CheckCleared(value);
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, 0, value) == ReadError::InvalidObject,
        "null payload address");
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity,
        (std::numeric_limits<std::uint64_t>::max)() - 8, value) == ReadError::AddressOverflow,
        "payload flag address overflow");
  CheckCleared(value);
  memory.bytes.resize(kResult + 24);
  Check(ReadReceiveStorageResultSnapshot(memory, kIdentity, kResult, value) == ReadError::Unreadable,
        "missing result byte");
  CheckCleared(value);
  std::cout << "weixin4 receive contract tests passed\n";
}
