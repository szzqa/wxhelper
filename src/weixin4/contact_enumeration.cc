#include "contact_enumeration.h"

#include "contact_record_reader.h"

#include <unordered_set>
#include <utility>

namespace wxhelper::weixin4 {
namespace {
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

ReadError ReadContactTypeQuerySnapshot(const MemoryReader& memory,
                                      const BinaryIdentity& identity,
                                      std::uint64_t result_address,
                                      ContactTypeQuerySnapshot& output,
                                      const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!AlignedPointer(result_address)) return ReadError::InvalidObject;
  std::uint64_t status_address = 0;
  if (!CheckedAdd(result_address, 0x10, status_address)) return ReadError::AddressOverflow;
  unsigned char engaged = 0;
  if (!memory.Read(status_address, &engaged, 1)) return ReadError::Unreadable;
  if (engaged == 0) return ReadError::None;
  if (engaged != 1) return ReadError::InvalidObject;

  std::uint64_t sentinel = 0, count = 0;
  auto error = ReadU64(memory, result_address, sentinel);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, result_address + 8, count);
  if (error != ReadError::None) return error;
  if (count > limits.max_elements) return ReadError::LimitExceeded;
  std::uint64_t current = 0, tail = 0;
  error = ReadLinks(memory, sentinel, current, tail);
  if (error != ReadError::None) return error;

  ContactTypeQuerySnapshot decoded;
  decoded.contacts.reserve(static_cast<std::size_t>(count));
  std::unordered_set<std::uint64_t> visited;
  std::uint64_t previous = sentinel;
  auto remaining = limits.max_total_string_bytes;
  for (std::uint64_t index = 0; index < count; ++index) {
    if (current == sentinel || !visited.insert(current).second)
      return ReadError::InvalidObject;
    std::uint64_t last = 0;
    if (!CheckedAdd(current, 0x1f, last)) return ReadError::AddressOverflow;
    std::uint64_t next = 0, back = 0;
    error = ReadLinks(memory, current, next, back);
    if (error != ReadError::None) return error;
    if (back != previous) return ReadError::InvalidObject;
    std::uint64_t contact_address = 0;
    error = ReadU64(memory, current + 0x10, contact_address);
    if (error != ReadError::None) return error;
    if (!AlignedPointer(contact_address)) return ReadError::InvalidObject;
    // +0x18 is the native owner/control pointer. Its lifetime is the snapshot
    // provider's responsibility; never follow it or modify reference counts.
    ContactRecord record;
    error = detail::ReadContactRecord(memory, contact_address, record, limits, remaining);
    if (error != ReadError::None) return error;
    decoded.contacts.push_back(std::move(record));
    previous = current;
    current = next;
  }
  if (current != sentinel || tail != previous) return ReadError::InvalidObject;
  decoded.result_present = true;
  output = std::move(decoded);
  return ReadError::None;
}

}  // namespace wxhelper::weixin4
