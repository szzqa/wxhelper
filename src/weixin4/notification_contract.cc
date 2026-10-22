#include "notification_contract.h"

#include <limits>
#include <utility>

namespace wxhelper::weixin4 {
namespace {

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

}  // namespace

ReadError ReadNotificationDispatchSnapshot(const MemoryReader& memory,
                                           const BinaryIdentity& identity,
                                           std::uint64_t module_base,
                                           std::uint64_t closure_address,
                                           NotificationDispatchSnapshot& output,
                                           const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!module_base || !closure_address) return ReadError::InvalidObject;
  // message-lifecycle-pass3.json: emitter 0x17b8970 allocates this 0x80-byte
  // closure and copies the source vector through 0xa9c3e0. Its run leaf
  // 0x472a80 passes +0x68 as R8 and tail-jumps through captured +0x10.
  std::uint64_t expected_vtable = 0;
  std::uint64_t vector_address = 0;
  if (!CheckedAdd(module_base, 0x90d86e8, expected_vtable) ||
      !CheckedAdd(closure_address, 0x68, vector_address))
    return ReadError::AddressOverflow;
  std::uint64_t vtable = 0;
  auto error = ReadU64(memory, closure_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != expected_vtable) return ReadError::InvalidObject;

  NotificationDispatchSnapshot value;
  error = Address(memory, closure_address, 8, value.callback_context_address);
  if (error != ReadError::None) return error;
  error = Address(memory, closure_address, 0x10, value.callback_function_address);
  if (error != ReadError::None) return error;
  error = Address(memory, closure_address, 0x48, value.scheduler_address);
  if (error != ReadError::None) return error;
  // Null context is permitted. The producer only builds this queued variant
  // for a non-null scheduler, and the run leaf unconditionally calls the func.
  if (!value.callback_function_address || !value.scheduler_address)
    return ReadError::InvalidObject;
  auto& owner = value.lifetime_owner;
  error = Address(memory, closure_address, 0x50, owner.object_address);
  if (error != ReadError::None) return error;
  error = Address(memory, closure_address, 0x58, owner.control_block_address);
  if (error != ReadError::None) return error;
  if (owner.control_block_address) {
    error = Word(memory, owner.control_block_address, 8, owner.strong_count);
    if (error != ReadError::None) return error;
    error = Word(memory, owner.control_block_address, 12, owner.weak_count);
    if (error != ReadError::None) return error;
    constexpr auto maximum =
        static_cast<std::uint32_t>((std::numeric_limits<std::int32_t>::max)());
    if (!owner.strong_count || !owner.weak_count ||
        owner.strong_count > maximum || owner.weak_count > maximum)
      return ReadError::InvalidObject;
    owner.has_control_block = true;
  }
  // No object/control offset or cross-field invariant is established for this
  // generic captured owner: empty and aliasing pairs must remain representable.
  error = ReadReceiveBatchSnapshot(memory, identity, vector_address,
                                   value.records, limits);
  if (error != ReadError::None) return error;
  output = std::move(value);
  return ReadError::None;
}

}  // namespace wxhelper::weixin4
