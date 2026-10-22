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
  // The success log labels message-object +0xb0 as chat_id. This does not
  // establish a callable send interface or recipient/delivery validation.
  std::string chat_id;
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
  // These names come from the record's diagnostic formatter. Enum values are
  // preserved as raw integers; no legacy type/status mapping is assumed.
  std::uint32_t message_type = 0;
  std::uint64_t sort_sequence = 0;
  // CoAddMessageToDB labels this value "time"; epoch and unit remain unknown.
  std::uint32_t time_raw = 0;
  std::uint32_t message_status = 0;
  std::uint32_t upload_status = 0;
  std::uint32_t download_status = 0;
  std::uint32_t origin_source = 0;
  // The formatter labels +0x58 "sender". Group-member and direction semantics
  // have not been recovered, so this must not be used to infer incoming/outgoing.
  std::string sender;
  // A 744-byte replacement record receives these XML fromusername/tousername
  // values. The ordinary sync record uses the same layout and peer accessor.
  std::string from_username;
  std::string to_username;
  // Raw content bytes. Depending on message type this may be structured data;
  // no text/XML/media interpretation or live message extraction is performed.
  std::string content;
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
