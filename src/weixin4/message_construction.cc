#include "message_construction.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace wxhelper::weixin4 {
namespace {

// Original 4.1.15.13: message-lifecycle-pass1.json (0x54b02f0),
// message-construction-pass2.json (0x6f4c70/0x766680), and
// message-lifecycle-pass3.json (0x766780). RVAs are identity-gated data values,
// never callable pointers. The factory allocates 0x7a8, object at control+0x10.
constexpr std::uint64_t kControlVtableRva = 0x8e534f8;
constexpr std::uint64_t kObjectVtableRva = 0x8e53588;

ReadError Address(const MemoryReader& memory, std::uint64_t base,
                  std::uint64_t offset, std::uint64_t& value) {
  std::uint64_t at = 0;
  if (!CheckedAdd(base, offset, at)) return ReadError::AddressOverflow;
  return ReadU64(memory, at, value);
}

ReadError Word(const MemoryReader& memory, std::uint64_t base,
               std::uint64_t offset, std::uint32_t& value) {
  std::uint64_t at = 0;
  if (!CheckedAdd(base, offset, at)) return ReadError::AddressOverflow;
  return ReadU32(memory, at, value);
}

ReadError String(const MemoryReader& memory, std::uint64_t object,
                 std::uint64_t offset, std::string& value,
                 const Limits& limits, std::size_t& remaining) {
  std::uint64_t at = 0;
  if (!CheckedAdd(object, offset, at)) return ReadError::AddressOverflow;
  Limits bounded = limits;
  bounded.max_string_bytes = (std::min)(limits.max_string_bytes, remaining);
  const auto error = ReadString(memory, at, value, bounded);
  if (error == ReadError::None) remaining -= value.size();
  return error;
}

}  // namespace

ReadError ReadTextMessageDraftSnapshot(const MemoryReader& memory,
                                       const BinaryIdentity& identity,
                                       std::uint64_t module_base,
                                       std::uint64_t owner_pair_address,
                                       TextMessageDraftSnapshot& output,
                                       const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!module_base || !owner_pair_address) return ReadError::InvalidObject;
  std::uint64_t control_vtable = 0;
  std::uint64_t object_vtable = 0;
  if (!CheckedAdd(module_base, kControlVtableRva, control_vtable) ||
      !CheckedAdd(module_base, kObjectVtableRva, object_vtable))
    return ReadError::AddressOverflow;

  TextMessageDraftSnapshot value;
  auto& owner = value.owner;
  auto error = Address(memory, owner_pair_address, 0, owner.object_address);
  if (error != ReadError::None) return error;
  error = Address(memory, owner_pair_address, 8, owner.control_block_address);
  if (error != ReadError::None) return error;
  if (!owner.object_address || !owner.control_block_address)
    return ReadError::InvalidObject;
  std::uint64_t expected_object = 0;
  if (!CheckedAdd(owner.control_block_address, 0x10, expected_object))
    return ReadError::AddressOverflow;
  if (owner.object_address != expected_object) return ReadError::InvalidObject;

  std::uint64_t observed = 0;
  error = Address(memory, owner.control_block_address, 0, observed);
  if (error != ReadError::None) return error;
  if (observed != control_vtable) return ReadError::InvalidObject;
  error = Address(memory, owner.object_address, 0, observed);
  if (error != ReadError::None) return error;
  if (observed != object_vtable) return ReadError::InvalidObject;
  error = Word(memory, owner.control_block_address, 8, owner.strong_count);
  if (error != ReadError::None) return error;
  error = Word(memory, owner.control_block_address, 12, owner.weak_count);
  if (error != ReadError::None) return error;
  constexpr auto maximum =
      static_cast<std::uint32_t>((std::numeric_limits<std::int32_t>::max)());
  // The factory's embedded weak reference adds to the implicit weak reference
  // held by a live strong owner. Do not require exact counts: more owners exist.
  if (!owner.strong_count || owner.strong_count > maximum ||
      owner.weak_count < 2 || owner.weak_count > maximum)
    return ReadError::InvalidObject;
  owner.has_control_block = true;

  error = Address(memory, owner.object_address, 8, observed);
  if (error != ReadError::None) return error;
  if (observed != owner.object_address) return ReadError::InvalidObject;
  error = Address(memory, owner.object_address, 0x10, observed);
  if (error != ReadError::None) return error;
  if (observed != owner.control_block_address) return ReadError::InvalidObject;

  error = Word(memory, owner.object_address, 0x118, value.word_118_raw);
  if (error != ReadError::None) return error;
  std::size_t remaining = limits.max_total_string_bytes;
  error = String(memory, owner.object_address, 0xb0, value.chat_id,
                  limits, remaining);
  if (error != ReadError::None) return error;
  error = String(memory, owner.object_address, 0x758, value.text_argument_bytes,
                  limits, remaining);
  if (error != ReadError::None) return error;
  output = std::move(value);
  return ReadError::None;
}

}  // namespace wxhelper::weixin4
