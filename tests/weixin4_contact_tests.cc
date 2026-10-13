#include "weixin4/contact_backend.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <limits>

using namespace wxhelper::weixin4;
namespace {
constexpr std::size_t kResult = 0x100;
constexpr std::size_t kSentinel = 0x200;
constexpr std::size_t kFirst = 0x800;
constexpr std::size_t kSecond = 0x1000;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

class Snapshot final : public MemoryReader {
 public:
  std::vector<unsigned char> bytes = std::vector<unsigned char>(0x10000, 0xaa);
  mutable std::size_t reads = 0;
  bool Read(std::uint64_t address, void* out, std::size_t count) const override {
    ++reads;
    if (address > bytes.size() || count > bytes.size() - address) return false;
    std::memcpy(out, bytes.data() + address, count);
    return true;
  }
  void U64(std::size_t at, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) bytes.at(at + i) = static_cast<unsigned char>(value >> (8 * i));
  }
  void U32(std::size_t at, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(at + i) = static_cast<unsigned char>(value >> (8 * i));
  }
  void String(std::size_t at, const std::string& value, std::size_t heap = 0) {
    assert(value.size() < 16 || heap);
    std::memset(bytes.data() + at, 0, 32);
    U64(at + 16, value.size());
    U64(at + 24, heap ? value.size() : 15);
    if (heap) U64(at, heap);
    std::memcpy(bytes.data() + (heap ? heap : at), value.c_str(), value.size() + 1);
  }
  void Record(std::size_t node, std::uint32_t id, const std::string& username,
              std::size_t heap = 0) {
    U32(node + 0x10, id);
    const auto row = node + 0x18;
    U32(row, id); U32(row + 4, 7);
    U32(row + 0x68, 0x80000001); U32(row + 0x6c, 0x12345678);
    U32(row + 0x70, 0xabcdef01);
    U32(row + 0x198, 11); U32(row + 0x19c, 12); U32(row + 0x1c0, 13);
    String(row + 0x08, username, heap);
    String(row + 0x28, "alias"); String(row + 0x48, "encrypted");
    String(row + 0x78, "remark"); String(row + 0x98, "remark-full");
    String(row + 0xb8, "remark-initial");
    String(row + 0xd8, std::string("\xe6\xb5\x8b\xe8\xaf\x95", 6));
    String(row + 0xf8, "initial"); String(row + 0x118, "full");
    String(row + 0x138, "big"); String(row + 0x158, "small");
    String(row + 0x178, "digest"); String(row + 0x1a0, "description");
    // Unknown extra_buffer/derived objects stay poisoned. No dereference allowed.
  }
};

Snapshot Fixture() {
  Snapshot memory;
  memory.bytes[kResult + 0x40] = 1;
  memory.U64(kResult + 8, kSentinel); memory.U64(kResult + 16, 2);
  memory.U64(kSentinel, kFirst); memory.U64(kSentinel + 8, kSecond);
  memory.U64(kFirst, kSecond); memory.U64(kFirst + 8, kSentinel);
  memory.U64(kSecond, kSentinel); memory.U64(kSecond + 8, kFirst);
  memory.Record(kFirst, 101, "alice");
  memory.Record(kSecond, 202, "long_contact_username", 0x8000);
  return memory;
}

std::size_t TextBytes(const ContactRecord& c) {
  return c.username.size() + c.alias.size() + c.encrypt_username.size() +
      c.remark.size() + c.remark_quan_pin.size() + c.remark_pin_yin_initial.size() +
      c.nick_name.size() + c.pin_yin_initial.size() + c.quan_pin.size() +
      c.big_head_url.size() + c.small_head_url.size() + c.head_img_md5.size() +
      c.description.size();
}
}  // namespace

int main() {
  auto memory = Fixture();
  ContactQuerySnapshot out;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::None);
  assert(out.query_succeeded && out.contacts.size() == 2);
  const auto& a = out.contacts[0];
  assert(a.id == 101 && a.username == "alice" && a.local_type == 7);
  assert(a.delete_flag == 0x80000001 && a.flag == 0x12345678 && a.verify_flag == 0xabcdef01);
  assert(a.alias == "alias" && a.encrypt_username == "encrypted" && a.remark == "remark");
  assert(a.remark_quan_pin == "remark-full" && a.remark_pin_yin_initial == "remark-initial");
  assert(a.nick_name == std::string("\xe6\xb5\x8b\xe8\xaf\x95", 6));
  assert(a.pin_yin_initial == "initial" && a.quan_pin == "full");
  assert(a.big_head_url == "big" && a.small_head_url == "small");
  assert(a.head_img_md5 == "digest" && a.description == "description");
  assert(a.chat_room_notify == 11 && a.is_in_chat_room == 12 && a.chat_room_type == 13);
  const auto total = TextBytes(a) + TextBytes(out.contacts[1]);
  memory.bytes[0x8000] = 'X';
  assert(out.contacts[1].username == "long_contact_username");

  memory = Fixture();
  Limits limits;
  limits.max_total_string_bytes = total;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::None);
  --limits.max_total_string_bytes;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::LimitExceeded);
  assert(!out.query_succeeded && out.contacts.empty());
  limits = {}; limits.max_string_bytes = 20;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::LimitExceeded);
  limits = {}; limits.max_elements = 1;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::LimitExceeded);

  auto bad_identity = kIdentity;
  bad_identity.sha256[0] = 'f';
  memory.reads = 0;
  assert(ReadContactQuerySnapshot(memory, bad_identity, kResult, out) == ReadError::ProfileMismatch);
  assert(memory.reads == 0);
  memory.bytes[kResult + 0x40] = 0;
  memory.U64(kResult + 8, 0xffffffffffffffffULL);
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::None);
  assert(!out.query_succeeded && out.contacts.empty() && memory.reads == 1);
  memory.bytes[kResult + 0x40] = 2;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::InvalidObject);

  memory = Fixture();
  memory.U64(kResult + 16, 0); memory.U64(kSentinel, kSentinel); memory.U64(kSentinel + 8, kSentinel);
  limits = {}; limits.max_elements = 0; limits.max_total_string_bytes = 0;
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out, limits) == ReadError::None);
  assert(out.query_succeeded && out.contacts.empty());

  // Every malformed topology must fail without exposing an earlier valid row.
  for (int failure = 0; failure < 8; ++failure) {
    memory = Fixture();
    switch (failure) {
      case 0: memory.U64(kSecond + 8, kSentinel); break;  // Broken backlink.
      case 1: memory.U64(kSentinel + 8, kFirst); break;  // Incorrect tail.
      case 2: memory.U64(kResult + 16, 1); break;       // Longer than count.
      case 3: memory.U64(kResult + 16, 3); break;       // Shorter than count.
      case 4: memory.U64(kSecond, kSecond); memory.U64(kResult + 16, 3); break;
      case 5: memory.U32(kSecond + 0x10, 303); break;   // Key differs from row id.
      case 6: memory.U32(kSecond + 0x10, 101); memory.U32(kSecond + 0x18, 101); break;
      case 7: memory.U64(kFirst, 0); break;
    }
    out.query_succeeded = true; out.contacts.emplace_back();
    assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::InvalidObject);
    assert(!out.query_succeeded && out.contacts.empty());
  }
  memory = Fixture();
  memory.U64(kSecond + 0x18 + 8, 0x20000);
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::Unreadable);
  assert(out.contacts.empty());
  memory = Fixture();
  memory.U64(kFirst + 0x18 + 8 + 24, 14);
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::InvalidString);
  memory = Fixture();
  const auto top = (std::numeric_limits<std::uint64_t>::max)();
  assert(ReadContactQuerySnapshot(memory, kIdentity, top - 63, out) == ReadError::AddressOverflow);
  memory.U64(kSentinel, top - 0x3ff);
  assert(ReadContactQuerySnapshot(memory, kIdentity, kResult, out) == ReadError::AddressOverflow);
  assert(ReadContactQuerySnapshot(memory, kIdentity, 0, out) == ReadError::InvalidObject);
  assert(ReadContactQuerySnapshot(memory, kIdentity, 0x20000, out) == ReadError::Unreadable);
  std::cout << "Weixin 4 contact query snapshots, owned fields, bounds and malformed maps: PASS\n";
}
