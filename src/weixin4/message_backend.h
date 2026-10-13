#pragma once

#include "memory_reader.h"
#include "profile.h"

#include <cstdint>
#include <string>

namespace wxhelper::weixin4 {

// Integer addresses describe the supplied snapshot; none are callable pointers.
struct MessageReferenceSnapshot {
  std::uint64_t object_address = 0;
  std::uint64_t control_block_address = 0;
  std::uint32_t strong_count = 0;
  std::uint32_t weak_count = 0;
  bool has_control_block = false;
};

// The text-send closure is an internal task, not a native function signature or
// a supported send API. Both strings are copied out of the stable snapshot.
struct TextSendTaskSnapshot {
  std::string call_id;
  // The success log reads this string, but its semantic name is not established.
  // It must not be exposed as recipient, body, or message ID without new evidence.
  std::string unknown_message_string_b0;
  std::uint64_t callback_context_address = 0;
  std::uint64_t manager_context_address = 0;
  MessageReferenceSnapshot message;
};

struct TextSendResultSnapshot {
  // The caller tests both words together. Individual error-domain/code meanings
  // and the remaining result-object fields have not been recovered.
  std::uint32_t status_word0 = 0;
  std::uint32_t status_word1 = 0;
  bool call_succeeded = false;
};

// Selected owned fields of a 0x2e8-byte record in the sync storage batch.
// This is not the full native object, and may not be passed back to the client.
struct ReceiveRecordSnapshot {
  std::uint64_t server_id = 0;
  // The accessor checks this word against 10000; its enum is not yet proven.
  std::uint32_t unknown_u32_0c = 0;
  // The peer accessor compares these strings to the current account. Their
  // sender/recipient direction and payload semantics remain unproven.
  std::string unknown_string_18;
  std::string unknown_string_38;
};

// These readers require a stable caller-owned snapshot with original-binary
// provenance. Errors leave output empty. They never call client code, mutate
// reference counts, reconstruct a runnable task, or access a live process.
ReadError ReadTextSendTaskSnapshot(const MemoryReader&, const BinaryIdentity&,
                                   std::uint64_t closure_address,
                                   TextSendTaskSnapshot& output,
                                   const Limits& = {});
ReadError ReadTextSendResultSnapshot(const MemoryReader&, const BinaryIdentity&,
                                     std::uint64_t result_address,
                                     TextSendResultSnapshot& output);
ReadError ReadReceiveRecordSnapshot(const MemoryReader&, const BinaryIdentity&,
                                    std::uint64_t record_address,
                                    ReceiveRecordSnapshot& output,
                                    const Limits& = {});
ReadError ReadReceiveBatchSnapshot(const MemoryReader&, const BinaryIdentity&,
                                   std::uint64_t vector_address,
                                   std::vector<ReceiveRecordSnapshot>& output,
                                   const Limits& = {});

}  // namespace wxhelper::weixin4
