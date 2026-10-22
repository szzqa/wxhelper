#include "send_contract.h"

#include <algorithm>
#include <utility>

namespace wxhelper::weixin4 {

ReadError ReadTextSendCompletionSnapshot(const MemoryReader& memory,
                                         const BinaryIdentity& identity,
                                         std::uint64_t result_address,
                                         TextSendCompletionSnapshot& output,
                                         const Limits& limits) {
  output = {};
  TextSendCompletionSnapshot value;
  auto error = ReadTextSendResultSnapshot(memory, identity, result_address, value.status);
  if (error != ReadError::None) return error;
  std::uint64_t string_address = 0;
  std::uint64_t pair_address = 0;
  std::uint64_t control_address = 0;
  if (!CheckedAdd(result_address, 8, string_address) ||
      !CheckedAdd(result_address, 0x28, pair_address) ||
      !CheckedAdd(result_address, 0x30, control_address))
    return ReadError::AddressOverflow;
  auto string_limits = limits;
  string_limits.max_string_bytes = (std::min)(limits.max_string_bytes,
                                             limits.max_total_string_bytes);
  error = ReadString(memory, string_address, value.detail_string, string_limits);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, pair_address, value.payload_object_address);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, control_address, value.payload_control_address);
  if (error != ReadError::None) return error;
  output = std::move(value);
  return ReadError::None;
}

}  // namespace wxhelper::weixin4
