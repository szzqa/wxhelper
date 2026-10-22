#pragma once

#include "message_backend.h"

namespace wxhelper::weixin4 {

// Payload returned by TaskInnerAddMessageListToDB (RVA 0x39255e0), after the
// asynchronous result has been extracted. This is not a task/closure address.
struct ReceiveStorageResultSnapshot {
  // Native result byte +0x18. A nonempty per-session map is combined with OR;
  // an empty filtered batch uses true. This is NOT an all-records-success flag.
  bool storage_result_flag = false;
  // The producer copies records from sessions whose result byte equals 1.
  // These owned field copies establish neither disk durability nor notification
  // delivery, message direction, or exactly-once semantics.
  std::vector<ReceiveRecordSnapshot> success_subset;
};

// Requires a stable caller-owned snapshot of the extracted payload. Does not
// await tasks, access a process, call native code, or create a receive event.
// Strictly rejects noncanonical native bool bytes; errors clear the full DTO.
ReadError ReadReceiveStorageResultSnapshot(const MemoryReader&,
                                           const BinaryIdentity&,
                                           std::uint64_t result_payload_address,
                                           ReceiveStorageResultSnapshot&,
                                           const Limits& = {});

}  // namespace wxhelper::weixin4
