#include "weixin4/contact_enumeration.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <utility>

using namespace wxhelper::weixin4;
namespace {
constexpr std::size_t kResult = 0x100;
constexpr std::size_t kSentinel = 0x200;
constexpr std::size_t kFirst = 0x300;
constexpr std::size_t kSecond = 0x340;
constexpr std::size_t kRowA = 0x1000;
constexpr std::size_t kRowB = 0x1800;
constexpr std::size_t kHeap = 0x5000;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};
constexpr std::size_t kStrings[] = {
    0x08, 0x28, 0x48, 0x78, 0x98, 0xb8, 0xd8,
    0xf8, 0x118, 0x138, 0x158, 0x178, 0x1a0};
constexpr std::size_t kIntegers[] = {
    0x00, 0x04, 0x68, 0x6c, 0x70, 0x198, 0x19c, 0x1c0};

void Check(bool condition, const char* reason) {
  if (!condition) {
    std::cerr << "FAIL: " << reason << '\n';
    std::exit(1);
  }
}

class Snapshot final : public MemoryReader {
 public:
  std::vector<unsigned char> bytes = std::vector<unsigned char>(0x8000, 0xaa);
  std::vector<std::pair<std::uint64_t, std::uint64_t>> forbidden;
  mutable std::size_t reads = 0;
  bool Read(std::uint64_t address, void* output, std::size_t size) const override {
    ++reads;
    if (address > bytes.size() || size > bytes.size() - address) return false;
    for (const auto& range : forbidden)
      if (address < range.second && address + size > range.first) return false;
    std::memcpy(output, bytes.data() + address, size);
    return true;
  }
  void U64(std::size_t at, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i)
      bytes.at(at + i) = static_cast<unsigned char>(value >> (8 * i));
  }
  void U32(std::size_t at, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i)
      bytes.at(at + i) = static_cast<unsigned char>(value >> (8 * i));
  }
  void String(std::size_t at, const std::string& value, std::size_t heap = 0) {
    Check(value.size() < 16 || heap, "fixture string allocation");
    std::memset(bytes.data() + at, 0, 32);
    U64(at + 16, value.size());
    U64(at + 24, heap ? value.size() : 15);
    if (heap) U64(at, heap);
    std::memcpy(bytes.data() + (heap ? heap : at), value.c_str(), value.size() + 1);
  }
  void Record(std::size_t at, std::uint32_t type) {
    for (const auto field : kIntegers) U32(at + field, 0);
    for (const auto field : kStrings) String(at + field, "");
    U32(at, 17); U32(at + 4, type);
    U32(at + 0x68, 0x80000001); U32(at + 0x6c, 8);
    U32(at + 0x70, 0xffffffff);
    U32(at + 0x198, 11); U32(at + 0x19c, 12); U32(at + 0x1c0, 13);
    String(at + 8, "same_username");
    String(at + 0xd8, std::string("ni\0ck", 5));
    forbidden.emplace_back(at + 0x1c4, at + 0x460);
  }
};

Snapshot Fixture() {
  Snapshot memory;
  memory.bytes[kResult + 0x10] = 1;
  memory.U64(kResult, kSentinel); memory.U64(kResult + 8, 2);
  memory.U64(kSentinel, kFirst); memory.U64(kSentinel + 8, kSecond);
  memory.U64(kFirst, kSecond); memory.U64(kFirst + 8, kSentinel);
  memory.U64(kSecond, kSentinel); memory.U64(kSecond + 8, kFirst);
  memory.U64(kFirst + 0x10, kRowA); memory.U64(kSecond + 0x10, kRowB);
  memory.Record(kRowA, 1); memory.Record(kRowB, 4);
  memory.String(kRowB + 0x1a0, "description stored outside the record", kHeap);
  // No native owner, mutex, vtable, sentinel payload or derived-record reads.
  memory.forbidden.emplace_back(kFirst + 0x18, kFirst + 0x20);
  memory.forbidden.emplace_back(kSecond + 0x18, kSecond + 0x20);
  memory.forbidden.emplace_back(kSentinel + 0x10, kSentinel + 0x20);
  return memory;
}

std::size_t TextBytes(const ContactRecord& c) {
  return c.username.size() + c.alias.size() + c.encrypt_username.size() +
      c.remark.size() + c.remark_quan_pin.size() + c.remark_pin_yin_initial.size() +
      c.nick_name.size() + c.pin_yin_initial.size() + c.quan_pin.size() +
      c.big_head_url.size() + c.small_head_url.size() + c.head_img_md5.size() +
      c.description.size();
}

void ExpectFailure(const Snapshot& memory, std::uint64_t address, ReadError expected,
                   const Limits& limits = {}) {
  ContactTypeQuerySnapshot out;
  out.result_present = true; out.contacts.emplace_back();
  Check(ReadContactTypeQuerySnapshot(memory, kIdentity, address, out, limits) == expected,
        "expected malformed/bounded result error");
  Check(!out.result_present && out.contacts.empty(), "failure clears all prior output");
}
}  // namespace

int main() {
  auto memory = Fixture();
  ContactTypeQuerySnapshot out;
  Check(ReadContactTypeQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::None,
        "valid completed optional list");
  Check(out.result_present && out.contacts.size() == 2, "present two-record result");
  const auto& first = out.contacts[0];
  Check(first.id == 17 && first.username == "same_username" && first.local_type == 1,
        "known fields decoded");
  Check(first.delete_flag == 0x80000001 && first.flag == 8 && first.verify_flag == 0xffffffff,
        "raw flags preserved without service filtering");
  Check(first.chat_room_notify == 11 && first.is_in_chat_room == 12 && first.chat_room_type == 13,
        "remaining integer fields");
  Check(first.nick_name == std::string("ni\0ck", 5), "embedded NUL preserved");
  Check(out.contacts[1].id == first.id && out.contacts[1].username == first.username &&
            out.contacts[1].local_type == 4,
        "cross-table order and duplicate identities preserved");
  const auto total = TextBytes(first) + TextBytes(out.contacts[1]);
  const auto description = out.contacts[1].description;
  memory.bytes[kHeap] = 'X'; memory.bytes[kRowA + 8] = 'X';
  Check(out.contacts[1].description == description && first.username == "same_username",
        "all returned strings are owned");

  memory = Fixture();
  Limits limits;
  limits.max_elements = 2; limits.max_total_string_bytes = total;
  Check(ReadContactTypeQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::None,
        "exact list and aggregate string budgets");
  --limits.max_total_string_bytes;
  ExpectFailure(memory, kResult, ReadError::LimitExceeded, limits);
  limits = {}; limits.max_elements = 1;
  ExpectFailure(memory, kResult, ReadError::LimitExceeded, limits);
  limits = {}; limits.max_string_bytes = description.size() - 1;
  ExpectFailure(memory, kResult, ReadError::LimitExceeded, limits);

  for (int mismatch = 0; mismatch < 3; ++mismatch) {
    auto identity = kIdentity;
    if (mismatch == 0) identity.version = "4.1.15.14";
    if (mismatch == 1) identity.sha256[0] = '0';
    if (mismatch == 2) identity.machine = 0x14c;
    memory.reads = 0; out.result_present = true; out.contacts.emplace_back();
    Check(ReadContactTypeQuerySnapshot(memory, identity, kResult, out) == ReadError::ProfileMismatch,
          "all binary identity fields required");
    Check(memory.reads == 0 && !out.result_present && out.contacts.empty(),
          "identity rejected before any memory read");
  }

  memory = Fixture();
  memory.bytes[kResult + 0x10] = 0;
  memory.forbidden.emplace_back(kResult, kResult + 0x10);
  memory.reads = 0;
  Check(ReadContactTypeQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::None,
        "disengaged result is readable without touching stale list bytes");
  Check(!out.result_present && out.contacts.empty() && memory.reads == 1,
        "disengaged result differs from present empty result");
  constexpr unsigned char invalid_statuses[] = {2, 3, 255};
  for (const auto status : invalid_statuses) {
    memory.bytes[kResult + 0x10] = status;
    ExpectFailure(memory, kResult, ReadError::InvalidObject);
  }
  memory = Fixture();
  memory.U64(kResult + 8, 0);
  memory.U64(kSentinel, kSentinel); memory.U64(kSentinel + 8, kSentinel);
  limits = {}; limits.max_elements = 0; limits.max_total_string_bytes = 0;
  Check(ReadContactTypeQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::None,
        "present empty result with zero budgets");
  Check(out.result_present && out.contacts.empty(), "present does not imply nonempty");

  for (int corruption = 0; corruption < 11; ++corruption) {
    memory = Fixture();
    switch (corruption) {
      case 0: memory.U64(kSecond + 8, kSentinel); break;
      case 1: memory.U64(kSentinel + 8, kFirst); break;
      case 2: memory.U64(kResult + 8, 1); break;
      case 3: memory.U64(kResult + 8, 3); break;
      case 4: memory.U64(kSecond, kFirst); memory.U64(kResult + 8, 3); break;
      case 5: memory.U64(kFirst, 0); break;
      case 6: memory.U64(kSecond + 0x10, 0); break;
      case 7: memory.U64(kSecond + 0x10, kRowB + 1); break;
      case 8: memory.U64(kResult, kSentinel + 1); break;
      case 9: memory.U64(kFirst, kSecond + 1); break;
      case 10: memory.U64(kResult + 8, 0); break;
    }
    ExpectFailure(memory, kResult, ReadError::InvalidObject);
  }
  memory = Fixture();
  memory.U64(kSecond + 0x10, 0x10000);
  ExpectFailure(memory, kResult, ReadError::Unreadable);
  memory = Fixture();
  memory.U64(kRowB + 0x1a0, 0x10000);
  ExpectFailure(memory, kResult, ReadError::Unreadable);
  memory = Fixture();
  memory.bytes[kHeap + description.size()] = 1;
  ExpectFailure(memory, kResult, ReadError::InvalidString);
  memory = Fixture();
  memory.U64(kRowB + 8 + 24, 14);
  ExpectFailure(memory, kResult, ReadError::InvalidString);

  memory = Fixture();
  const auto top = (std::numeric_limits<std::uint64_t>::max)();
  ExpectFailure(memory, top - 15, ReadError::AddressOverflow);
  memory.U64(kResult, top - 7);
  ExpectFailure(memory, kResult, ReadError::AddressOverflow);
  memory = Fixture(); memory.U64(kSentinel, top - 0x17);
  ExpectFailure(memory, kResult, ReadError::AddressOverflow);
  memory = Fixture(); memory.U64(kSecond + 0x10, top - 0x1ff);
  ExpectFailure(memory, kResult, ReadError::AddressOverflow);
  ExpectFailure(memory, 0, ReadError::InvalidObject);
  ExpectFailure(memory, kResult + 1, ReadError::InvalidObject);
  ExpectFailure(memory, 0x10000, ReadError::Unreadable);
  std::cout << "Contact type-query optional list snapshots, ownership, limits and malformed data: PASS\n";
}
