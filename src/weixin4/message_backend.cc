#include "message_backend.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace wxhelper::weixin4 {
namespace {

// Evidence: message-migration-pass1.json, original Weixin.dll SHA kSha256.
// RVA 0x54b1e10 closure: +0x38/+0x40 owner pair, +0x48 manager, +8 callback.
// RVA 0x54b2022 and 0x54b20a1 pass the closure +0x18 string as the first log
// argument; encoded format at RVA 0x9805f18 begins with "call_id=". The message
// +0xb0 string is the second argument (RVA 0x54b1feb..0x54b201b).
// RVA 0x178f040 increments control +8, decrements +8/+0xc, and returns the
// caller-owned result buffer. These are snapshot layouts, not callable ABIs.
constexpr std::uint64_t kCallId = 0x18;
constexpr std::uint64_t kMessageObject = 0x38;
constexpr std::uint64_t kMessageControl = 0x40;
constexpr std::uint64_t kManager = 0x48;
constexpr std::uint64_t kCallback = 8;
constexpr std::uint64_t kUnknownMessageString = 0xb0;
constexpr std::size_t kReceiveRecordStride = 0x2e8;

ReadError ReadAddress(const MemoryReader& memory, std::uint64_t base,
                      std::uint64_t offset, std::uint64_t& output) {
  std::uint64_t address = 0;
  if (!CheckedAdd(base, offset, address)) return ReadError::AddressOverflow;
  return ReadU64(memory, address, output);
}

ReadError ReadCount(const MemoryReader& memory, std::uint64_t base,
                    std::uint64_t offset, std::uint32_t& output) {
  std::uint64_t address = 0;
  if (!CheckedAdd(base, offset, address)) return ReadError::AddressOverflow;
  return ReadU32(memory, address, output);
}

ReadError ReadBudgetedString(const MemoryReader& memory, std::uint64_t base,
                             std::uint64_t offset, std::string& output,
                             const Limits& limits, std::size_t& remaining) {
  std::uint64_t address = 0;
  if (!CheckedAdd(base, offset, address)) return ReadError::AddressOverflow;
  Limits field_limits = limits;
  field_limits.max_string_bytes = (std::min)(limits.max_string_bytes, remaining);
  const auto error = ReadString(memory, address, output, field_limits);
  if (error == ReadError::None) remaining -= output.size();
  return error;
}

ReadError ReadReceiveRecord(const MemoryReader& memory, std::uint64_t address,
                            ReceiveRecordSnapshot& output, const Limits& limits,
                            std::size_t& remaining) {
  if (!address) return ReadError::InvalidObject;
  // message-migration-receive-pass3.json: RVA 0x3896fe0 reads record +328,
  // queries duplicates, and prints it as the first argument to the format at
  // RVA 0x94fc828: "duplicate svrid:%_ in session:%_ with message:%_".
  auto error = ReadAddress(memory, address, 0x148, output.server_id);
  if (error != ReadError::None) return error;
  error = ReadCount(memory, address, 0x0c, output.unknown_u32_0c);
  if (error != ReadError::None) return error;
  // RVA 0xa55490 reads these fields, but does not establish direction/content.
  error = ReadBudgetedString(memory, address, 0x18, output.unknown_string_18,
                             limits, remaining);
  if (error != ReadError::None) return error;
  return ReadBudgetedString(memory, address, 0x38, output.unknown_string_38,
                            limits, remaining);
}

}  // namespace

ReadError ReadTextSendTaskSnapshot(const MemoryReader& memory,
                                   const BinaryIdentity& identity,
                                   std::uint64_t closure_address,
                                   TextSendTaskSnapshot& output,
                                   const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!closure_address) return ReadError::InvalidObject;

  TextSendTaskSnapshot value;
  auto error = ReadAddress(memory, closure_address, kCallback,
                           value.callback_context_address);
  if (error != ReadError::None) return error;
  error = ReadAddress(memory, closure_address, kManager,
                      value.manager_context_address);
  if (error != ReadError::None) return error;
  error = ReadAddress(memory, closure_address, kMessageObject,
                      value.message.object_address);
  if (error != ReadError::None) return error;
  error = ReadAddress(memory, closure_address, kMessageControl,
                      value.message.control_block_address);
  if (error != ReadError::None) return error;
  if (!value.message.object_address || !value.manager_context_address)
    return ReadError::InvalidObject;

  if (value.message.control_block_address) {
    value.message.has_control_block = true;
    error = ReadCount(memory, value.message.control_block_address, 8,
                      value.message.strong_count);
    if (error != ReadError::None) return error;
    error = ReadCount(memory, value.message.control_block_address, 12,
                      value.message.weak_count);
    if (error != ReadError::None) return error;
    // MSVC shared ownership uses signed interlocked counters. A task's live
    // owning reference cannot have exhausted or non-positive counts.
    constexpr auto max_count =
        static_cast<std::uint32_t>((std::numeric_limits<std::int32_t>::max)());
    if (!value.message.strong_count || !value.message.weak_count ||
        value.message.strong_count > max_count ||
        value.message.weak_count > max_count)
      return ReadError::InvalidObject;
  }

  std::size_t remaining = limits.max_total_string_bytes;
  error = ReadBudgetedString(memory, closure_address, kCallId, value.call_id,
                             limits, remaining);
  if (error != ReadError::None) return error;
  error = ReadBudgetedString(memory, value.message.object_address,
                             kUnknownMessageString,
                             value.unknown_message_string_b0, limits, remaining);
  if (error != ReadError::None) return error;
  output = std::move(value);
  return ReadError::None;
}

ReadError ReadTextSendResultSnapshot(const MemoryReader& memory,
                                     const BinaryIdentity& identity,
                                     std::uint64_t result_address,
                                     TextSendResultSnapshot& output) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!result_address) return ReadError::InvalidObject;
  TextSendResultSnapshot value;
  auto error = ReadU32(memory, result_address, value.status_word0);
  if (error != ReadError::None) return error;
  error = ReadCount(memory, result_address, 4, value.status_word1);
  if (error != ReadError::None) return error;
  // RVA 0x54b1eb3..0x54b1ec0 ORs the two words before branching to the callback.
  // A successful task call is not evidence of server acknowledgement/delivery.
  value.call_succeeded = (value.status_word0 | value.status_word1) == 0;
  output = value;
  return ReadError::None;
}

ReadError ReadReceiveRecordSnapshot(const MemoryReader& memory,
                                    const BinaryIdentity& identity,
                                    std::uint64_t record_address,
                                    ReceiveRecordSnapshot& output,
                                    const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  ReceiveRecordSnapshot value;
  std::size_t remaining = limits.max_total_string_bytes;
  const auto error = ReadReceiveRecord(memory, record_address, value, limits, remaining);
  if (error != ReadError::None) return error;
  output = std::move(value);
  return ReadError::None;
}

ReadError ReadReceiveBatchSnapshot(const MemoryReader& memory,
                                   const BinaryIdentity& identity,
                                   std::uint64_t vector_address,
                                   std::vector<ReceiveRecordSnapshot>& output,
                                   const Limits& limits) {
  output.clear();
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!vector_address) return ReadError::InvalidObject;
  VectorRange range;
  auto error = ReadVectorRange(memory, vector_address, kReceiveRecordStride, range, limits);
  if (error != ReadError::None) return error;
  std::vector<ReceiveRecordSnapshot> values;
  values.reserve(range.size);
  std::size_t remaining = limits.max_total_string_bytes;
  for (std::size_t i = 0; i < range.size; ++i) {
    ReceiveRecordSnapshot value;
    // ReadVectorRange already verifies monotonic, aligned endpoints and count.
    const auto address = range.begin + i * kReceiveRecordStride;
    error = ReadReceiveRecord(memory, address, value, limits, remaining);
    if (error != ReadError::None) return error;
    values.push_back(std::move(value));
  }
  output = std::move(values);
  return ReadError::None;
}

}  // namespace wxhelper::weixin4
