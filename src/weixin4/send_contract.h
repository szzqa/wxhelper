#pragma once

#include "message_backend.h"

namespace wxhelper::weixin4 {

// The 0x38-byte caller output copied by RVA 0x179cb90 after erased-result
// type validation. It is not a callable object, acknowledgment or receipt.
struct TextSendCompletionSnapshot {
  TextSendResultSnapshot status;
  // An owned copy of output +8. Its error/message semantics are not established.
  std::string detail_string;
  // Output +0x28/+0x30 is a shared-owner pair of unresolved payload type.
  // Addresses are observations only; neither pointer is dereferenced or retained.
  std::uint64_t payload_object_address = 0;
  std::uint64_t payload_control_address = 0;
};

// Reads a stable caller-owned snapshot, not an unfinished task/erased holder.
// This extends the existing eight-byte result reader without changing its input
// requirements. Errors clear the complete output; no native code is executed.
ReadError ReadTextSendCompletionSnapshot(const MemoryReader&, const BinaryIdentity&,
                                         std::uint64_t result_address,
                                         TextSendCompletionSnapshot&,
                                         const Limits& = {});

}  // namespace wxhelper::weixin4
