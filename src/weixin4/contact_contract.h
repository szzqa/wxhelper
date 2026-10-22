#pragma once

#include "memory_reader.h"
#include "profile.h"

namespace wxhelper::weixin4 {

// The selected input of the storage task created by RVA 0x2fabb40 and consumed
// by RVA 0x2fb4520. Order and duplicate/raw string bytes are preserved. This is
// a supplied username list, not an enumeration of the account's contacts.
struct ContactStorageTaskRequestSnapshot {
  std::vector<std::string> usernames;
};

// Copy only the task's string vector at +0x38 from a stable caller-supplied
// snapshot. The task's other fields are neither followed nor validated. This
// does not construct, retain, submit, wait for, or execute a native task. A
// successful decode says nothing about query completion or result coverage.
// On any error, output is cleared before returning.
ReadError ReadContactStorageTaskRequestSnapshot(
    const MemoryReader&, const BinaryIdentity&, std::uint64_t task_address,
    ContactStorageTaskRequestSnapshot& output, const Limits& = {});

}  // namespace wxhelper::weixin4
