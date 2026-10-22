#include "weixin4/contact_contract.h"

#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>

using namespace wxhelper::weixin4;
namespace {
#define CHECK(condition)                                                     \
  do {                                                                       \
    if (!(condition))                                                        \
      throw std::runtime_error("check failed at line " +                     \
                               std::to_string(__LINE__) + ": " #condition); \
  } while (false)

constexpr std::size_t kTask = 0x100;
constexpr std::size_t kVector = kTask + 0x38;
constexpr std::size_t kFirst = 0x400;
constexpr std::size_t kHeap = 0x1000;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

class Snapshot final : public MemoryReader {
 public:
  std::vector<unsigned char> bytes = std::vector<unsigned char>(0x2000, 0xaa);
  std::vector<std::pair<std::uint64_t, std::size_t>> readable;
  mutable std::size_t reads = 0;
  bool Read(std::uint64_t at, void* destination, std::size_t size) const override {
    ++reads;
    if (at > bytes.size() || size > bytes.size() - at) return false;
    for (const auto& range : readable) {
      if (at >= range.first && at - range.first <= range.second &&
          size <= range.second - (at - range.first)) {
        std::memcpy(destination, bytes.data() + at, size);
        return true;
      }
    }
    return false;
  }
  void U64(std::size_t at, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i)
      bytes.at(at + i) = static_cast<unsigned char>(value >> (8 * i));
  }
  void String(std::size_t at, const std::string& value, std::size_t heap = 0) {
    CHECK(value.size() < 16 || heap != 0);
    std::memset(bytes.data() + at, 0, 32);
    U64(at + 16, value.size());
    U64(at + 24, heap ? value.size() : 15);
    if (heap) U64(at, heap);
    std::memcpy(bytes.data() + (heap ? heap : at), value.c_str(), value.size() + 1);
    readable.emplace_back(at, 32);
    if (heap) readable.emplace_back(heap, value.size() + 1);
  }
};

Snapshot Fixture() {
  Snapshot memory;
  memory.readable.emplace_back(kVector, 24);
  memory.U64(kVector, kFirst);
  memory.U64(kVector + 8, kFirst + 4 * 32);
  memory.U64(kVector + 16, kFirst + 5 * 32);
  memory.String(kFirst, "alice");
  memory.String(kFirst + 32, "a_long_contact_username", kHeap);
  memory.String(kFirst + 64, "alice");
  memory.String(kFirst + 96, std::string("a\0b", 3));
  // No readable range covers vtable, owner pairs, storage, result, or unused
  // capacity. A decoder that follows any of them must fail this fixture.
  return memory;
}

void ExpectError(const Snapshot& memory, ReadError expected,
                 std::uint64_t address = kTask, const Limits& limits = {}) {
  ContactStorageTaskRequestSnapshot out{{"old"}};
  CHECK(ReadContactStorageTaskRequestSnapshot(memory, kIdentity, address, out,
                                             limits) == expected);
  CHECK(out.usernames.empty());
}
}  // namespace

int RunTests() {
  auto memory = Fixture();
  ContactStorageTaskRequestSnapshot out;
  CHECK(ReadContactStorageTaskRequestSnapshot(memory, kIdentity, kTask, out) ==
        ReadError::None);
  CHECK(out.usernames == std::vector<std::string>(
                            {"alice", "a_long_contact_username", "alice",
                             std::string("a\0b", 3)}));
  memory.bytes[kHeap] = 'X';
  memory.bytes[kFirst] = 'X';
  CHECK(out.usernames[0] == "alice");
  CHECK(out.usernames[1] == "a_long_contact_username");

  for (int field = 0; field < 3; ++field) {
    auto identity = kIdentity;
    if (field == 0) identity.version = "4.1.15.14";
    if (field == 1) identity.sha256[0] = 'f';
    if (field == 2) identity.machine = 0x14c;
    memory.reads = 0;
    out.usernames = {"old"};
    CHECK(ReadContactStorageTaskRequestSnapshot(memory, identity, kTask, out) ==
          ReadError::ProfileMismatch);
    CHECK(memory.reads == 0 && out.usernames.empty());
  }

  memory = Fixture();
  Limits limits;
  const auto long_size = std::string("a_long_contact_username").size();
  limits.max_total_string_bytes = 5 + long_size + 5 + 3;
  CHECK(ReadContactStorageTaskRequestSnapshot(memory, kIdentity, kTask, out,
                                             limits) == ReadError::None);
  --limits.max_total_string_bytes;
  ExpectError(memory, ReadError::LimitExceeded, kTask, limits);
  limits = {}; limits.max_elements = 3;
  ExpectError(memory, ReadError::LimitExceeded, kTask, limits);
  limits = {}; limits.max_string_bytes = long_size - 1;
  ExpectError(memory, ReadError::LimitExceeded, kTask, limits);

  // Empty input is not a request to enumerate all contacts. Both null storage
  // and allocated empty vectors are valid snapshots, including a zero budget.
  limits = {}; limits.max_elements = 0; limits.max_total_string_bytes = 0;
  for (const auto begin : {std::uint64_t{0}, std::uint64_t{kFirst}}) {
    memory = Fixture();
    memory.U64(kVector, begin); memory.U64(kVector + 8, begin);
    memory.U64(kVector + 16, begin ? begin + 32 : 0);
    CHECK(ReadContactStorageTaskRequestSnapshot(memory, kIdentity, kTask, out,
                                               limits) == ReadError::None);
    CHECK(out.usernames.empty());
  }

  for (int failure = 0; failure < 5; ++failure) {
    memory = Fixture();
    switch (failure) {
      case 0: memory.U64(kVector + 8, kFirst - 32); break;
      case 1: memory.U64(kVector + 16, kFirst + 32); break;
      case 2: memory.U64(kVector + 8, kFirst + 33); break;
      case 3: memory.U64(kVector + 16, kFirst + 4 * 32 + 1); break;
      case 4: memory.U64(kVector, 0); break;
    }
    ExpectError(memory, ReadError::InvalidVector);
  }
  memory = Fixture();
  memory.U64(kFirst + 96 + 24, 14);
  ExpectError(memory, ReadError::InvalidString);
  memory = Fixture();
  memory.U64(kFirst + 32, 0x3000);
  ExpectError(memory, ReadError::Unreadable);
  memory = Fixture();
  memory.bytes[kHeap + long_size] = '!';
  ExpectError(memory, ReadError::InvalidString);
  memory = Fixture();
  memory.readable.clear();
  ExpectError(memory, ReadError::Unreadable);
  ExpectError(memory, ReadError::InvalidObject, 0);
  ExpectError(memory, ReadError::InvalidObject, kTask + 1);
  const auto top = (std::numeric_limits<std::uint64_t>::max)();
  ExpectError(memory, ReadError::AddressOverflow, top - 7);
  ExpectError(memory, ReadError::AddressOverflow, top - 63);

  std::cout << "Contact storage task input: owned usernames, profile, bounds, "
               "budgets and error clearing: PASS\n";
  return 0;
}

int main() {
  try {
    return RunTests();
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
