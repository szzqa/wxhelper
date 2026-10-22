#include "contact_contract.h"

namespace wxhelper::weixin4 {

ReadError ReadContactStorageTaskRequestSnapshot(
    const MemoryReader& memory, const BinaryIdentity& identity,
    std::uint64_t task_address, ContactStorageTaskRequestSnapshot& output,
    const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (task_address == 0 || (task_address & 7) != 0)
    return ReadError::InvalidObject;
  std::uint64_t vector_address = 0;
  if (!CheckedAdd(task_address, 0x38, vector_address))
    return ReadError::AddressOverflow;
  // Constructor 0x2fabc54..0x2fabc7b, worker 0x2fb4520, destructor 0x2fba880
  // independently establish this owned vector of 32-byte narrow strings.
  return ReadStringVector(memory, vector_address, output.usernames, limits);
}

}  // namespace wxhelper::weixin4
