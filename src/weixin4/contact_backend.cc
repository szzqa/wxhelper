#include "contact_backend.h"
#include "contact_record_reader.h"

#include <algorithm>
#include <unordered_set>
#include <utility>

namespace wxhelper::weixin4 {
namespace {
// Original Weixin.dll 4.1.15.13, binding RVA 0xf1fbf0; verified against
// constructor 0xf1f280, copy 0x6f9130 and destructor 0x6fad10.
struct TextField {
  std::uint64_t offset;
  std::string ContactRecord::*member;
};
constexpr TextField kTextFields[] = {
    {0x08, &ContactRecord::username},
    {0x28, &ContactRecord::alias},
    {0x48, &ContactRecord::encrypt_username},
    {0x78, &ContactRecord::remark},
    {0x98, &ContactRecord::remark_quan_pin},
    {0xb8, &ContactRecord::remark_pin_yin_initial},
    {0xd8, &ContactRecord::nick_name},
    {0xf8, &ContactRecord::pin_yin_initial},
    {0x118, &ContactRecord::quan_pin},
    {0x138, &ContactRecord::big_head_url},
    {0x158, &ContactRecord::small_head_url},
    {0x178, &ContactRecord::head_img_md5},
    {0x1a0, &ContactRecord::description},
};
struct IntegerField {
  std::uint64_t offset;
  std::uint32_t ContactRecord::*member;
};
constexpr IntegerField kIntegerFields[] = {
    {0x00, &ContactRecord::id},
    {0x04, &ContactRecord::local_type},
    {0x68, &ContactRecord::delete_flag},
    {0x6c, &ContactRecord::flag},
    {0x70, &ContactRecord::verify_flag},
    {0x198, &ContactRecord::chat_room_notify},
    {0x19c, &ContactRecord::is_in_chat_room},
    {0x1c0, &ContactRecord::chat_room_type},
};

bool AlignedPointer(std::uint64_t address) {
  return address != 0 && (address & 7) == 0;
}

ReadError ReadLinks(const MemoryReader& memory, std::uint64_t address,
                    std::uint64_t& next, std::uint64_t& previous) {
  if (!AlignedPointer(address)) return ReadError::InvalidObject;
  std::uint64_t last = 0;
  if (!CheckedAdd(address, 15, last)) return ReadError::AddressOverflow;
  auto error = ReadU64(memory, address, next);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, address + 8, previous);
  if (error != ReadError::None) return error;
  if (!AlignedPointer(next) || !AlignedPointer(previous)) return ReadError::InvalidObject;
  return ReadError::None;
}

}  // namespace

namespace detail {
ReadError ReadContactRecord(const MemoryReader& memory, std::uint64_t address,
                            ContactRecord& record, const Limits& limits,
                            std::size_t& remaining) {
  std::uint64_t last = 0;
  if (!CheckedAdd(address, 0x45f, last)) return ReadError::AddressOverflow;
  for (const auto& field : kIntegerFields) {
    const auto error = ReadU32(memory, address + field.offset, record.*field.member);
    if (error != ReadError::None) return error;
  }
  for (const auto& field : kTextFields) {
    auto field_limits = limits;
    field_limits.max_string_bytes = (std::min)(remaining, limits.max_string_bytes);
    auto& text = record.*field.member;
    const auto error = ReadString(memory, address + field.offset, text, field_limits);
    if (error != ReadError::None) return error;
    remaining -= text.size();
  }
  return ReadError::None;
}
}  // namespace detail

ReadError ReadContactQuerySnapshot(const MemoryReader& memory,
                                   const BinaryIdentity& identity,
                                   std::uint64_t result_address,
                                   ContactQuerySnapshot& output,
                                   const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!AlignedPointer(result_address)) return ReadError::InvalidObject;
  std::uint64_t status_address = 0;
  if (!CheckedAdd(result_address, 0x40, status_address)) return ReadError::AddressOverflow;
  unsigned char engaged = 0;
  if (!memory.Read(status_address, &engaged, 1)) return ReadError::Unreadable;
  if (engaged == 0) return ReadError::None;
  if (engaged != 1) return ReadError::InvalidObject;

  std::uint64_t sentinel = 0, count = 0;
  auto error = ReadU64(memory, result_address + 8, sentinel);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, result_address + 16, count);
  if (error != ReadError::None) return error;
  if (count > limits.max_elements) return ReadError::LimitExceeded;
  std::uint64_t current = 0, tail = 0;
  error = ReadLinks(memory, sentinel, current, tail);
  if (error != ReadError::None) return error;

  ContactQuerySnapshot decoded;
  decoded.contacts.reserve(static_cast<std::size_t>(count));
  std::unordered_set<std::uint64_t> visited;
  std::unordered_set<std::uint32_t> ids;
  std::uint64_t previous = sentinel;
  auto remaining = limits.max_total_string_bytes;
  for (std::uint64_t index = 0; index < count; ++index) {
    if (current == sentinel || !visited.insert(current).second)
      return ReadError::InvalidObject;
    std::uint64_t last = 0;
    if (!CheckedAdd(current, 0x477, last)) return ReadError::AddressOverflow;
    std::uint64_t next = 0, back = 0;
    error = ReadLinks(memory, current, next, back);
    if (error != ReadError::None) return error;
    if (back != previous) return ReadError::InvalidObject;
    std::uint32_t key = 0;
    error = ReadU32(memory, current + 0x10, key);
    if (error != ReadError::None) return error;
    ContactRecord record;
    error = detail::ReadContactRecord(memory, current + 0x18, record, limits, remaining);
    if (error != ReadError::None) return error;
    if (key != record.id || !ids.insert(key).second) return ReadError::InvalidObject;
    decoded.contacts.push_back(std::move(record));
    previous = current;
    current = next;
  }
  if (current != sentinel || tail != previous) return ReadError::InvalidObject;
  decoded.query_succeeded = true;
  output = std::move(decoded);
  return ReadError::None;
}
}  // namespace wxhelper::weixin4
