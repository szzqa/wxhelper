#include "receive_contract.h"

#include <utility>

namespace wxhelper::weixin4 {

ReadError ReadReceiveStorageResultSnapshot(const MemoryReader& memory,
                                           const BinaryIdentity& identity,
                                           std::uint64_t result_payload_address,
                                           ReceiveStorageResultSnapshot& output,
                                           const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!result_payload_address) return ReadError::InvalidObject;

  std::uint64_t flag_address = 0;
  if (!CheckedAdd(result_payload_address, 0x18, flag_address))
    return ReadError::AddressOverflow;
  unsigned char flag = 0;
  if (!memory.Read(flag_address, &flag, sizeof(flag))) return ReadError::Unreadable;
  if (flag > 1) return ReadError::InvalidObject;

  ReceiveStorageResultSnapshot value;
  value.storage_result_flag = flag != 0;
  // The extracted payload starts with an ordinary vector of 0x2e8-byte records.
  // Reuse the common reader so element and total string budgets span the subset.
  const auto error = ReadReceiveBatchSnapshot(memory, identity, result_payload_address,
                                             value.success_subset, limits);
  if (error != ReadError::None) return error;
  output = std::move(value);
  return ReadError::None;
}

}  // namespace wxhelper::weixin4
