#pragma once

#include "message_backend.h"

namespace wxhelper::weixin4 {

// Selected fields of the source object created by RVA 0x6f4c70 and populated
// by the text-message function-call path at 0x54b02f0. "Draft" describes that
// construction path, not a verified lifecycle state of an arbitrary snapshot.
struct TextMessageDraftSnapshot {
  MessageReferenceSnapshot owner;
  std::string chat_id;
  // Bytes copied from the text-call argument into source +0x758. No encoding,
  // normalization, wire representation or recipient validation is implied.
  std::string text_argument_bytes;
  // This path writes 1 at +0x118. Its general enum meaning is not established.
  std::uint32_t word_118_raw = 0;
};

// Reads an existing factory-created object from a stable caller-owned snapshot.
// owner_pair_address points to {object, control}, not the object itself. Exact
// factory vtables, object/control relation, counters and the embedded self weak
// pair are checked. Other construction variants are intentionally unsupported.
// This never constructs a native object, retains a native reference or calls
// client code. Errors clear the entire output.
ReadError ReadTextMessageDraftSnapshot(const MemoryReader&, const BinaryIdentity&,
                                       std::uint64_t module_base,
                                       std::uint64_t owner_pair_address,
                                       TextMessageDraftSnapshot&,
                                       const Limits& = {});

}  // namespace wxhelper::weixin4
