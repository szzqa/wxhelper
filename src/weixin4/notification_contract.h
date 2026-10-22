#pragma once

#include "message_backend.h"

namespace wxhelper::weixin4 {

// A queued copy produced by the message signal emitter at RVA 0x17b8970.
// This is neither a live subscription nor proof that a subscriber ran. The
// same signal may represent history or locally originated messages.
struct NotificationDispatchSnapshot {
  std::uint64_t callback_context_address = 0;
  std::uint64_t callback_function_address = 0;
  std::uint64_t scheduler_address = 0;
  // Captured +0x50/+0x58 pair. Its object type and relationship to the raw
  // callback context are unknown. It must not be treated as permission to
  // invoke a callback, nor as proof that disconnect is a lifetime barrier.
  MessageReferenceSnapshot lifetime_owner;
  std::vector<ReceiveRecordSnapshot> records;
};

// Exact queued closure variant: vtable RVA 0x90d86e8, record vector +0x68.
// Copies records into owned DTOs from a stable caller-supplied snapshot. Never
// enumerates live subscribers, calls/schedules callbacks, or retains pointers.
// On any error the whole output is empty. Native addresses are observations.
ReadError ReadNotificationDispatchSnapshot(const MemoryReader&,
                                           const BinaryIdentity&,
                                           std::uint64_t module_base,
                                           std::uint64_t closure_address,
                                           NotificationDispatchSnapshot&,
                                           const Limits& = {});

}  // namespace wxhelper::weixin4
