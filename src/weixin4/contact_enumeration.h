#pragma once

#include "contact_backend.h"

namespace wxhelper::weixin4 {

struct ContactTypeQuerySnapshot {
  // The native optional list is engaged. This is NOT a completeness or overall
  // query-success flag: RVA 0x26ea550 can publish one successful table branch
  // even when another requested branch has no result. Requested types and
  // individual branch outcomes are not retained in this result object.
  bool result_present = false;
  std::vector<ContactRecord> contacts;
};

// Decode the stable completed output of RVA 0x26ea550: optional list of owned
// Contact pointers, not the map returned by 0x26e8250. Copies only known fields;
// does not call the query, access live memory, or establish contact coverage.
// Preserves order and duplicate records. A disengaged result returns None with
// result_present=false; any read/validation error clears all output.
ReadError ReadContactTypeQuerySnapshot(const MemoryReader&, const BinaryIdentity&,
                                      std::uint64_t result_address,
                                      ContactTypeQuerySnapshot& output,
                                      const Limits& = {});

}  // namespace wxhelper::weixin4
