#pragma once

#include <cstdint>

#include "memory_reader.h"
#include "profile.h"

namespace wxhelper::weixin4 {

namespace send_cancel_layout {
constexpr std::uint64_t kContextVtableRva = 0x950A548;
constexpr std::uint64_t kJobVtableRva = 0x8F78568;
constexpr std::uint64_t kJobControlVtableRva = 0x8F784D8;
constexpr std::uint64_t kSendJobOffset = 0x58;
constexpr std::uint64_t kSendCgiJobOffset = 0x68;
constexpr std::uint64_t kStageOffset = 0xBC;
constexpr std::uint64_t kStartedOffset = 0x178;
constexpr std::uint64_t kActiveOffset = 0x179;
constexpr std::uint64_t kCancelRequestedOffset = 0x17B;
}  // namespace send_cancel_layout

// Initial action selected from observed job pointers, not evidence Cancel ran.
// Native job calls may change pointers; a later prepare-show lookup can follow.
enum class SendCancelDispatch { Unknown, PrepareShowLookup, JobCancelAndJoin };

struct SendJobCancelObservation {
  bool present = false;
  std::uint64_t object_address = 0;
  std::uint64_t control_address = 0;
  std::uint8_t started_raw = 0;
  std::uint8_t active_raw = 0;
  std::uint8_t cancel_requested_raw = 0;
  bool started = false;
  bool active = false;
  // Native cancel sets this before scheduling its follow-up. It does not prove
  // join returned, message completion was published, or callbacks were released.
  bool cancel_requested = false;
};

struct SendCancelContextSnapshot {
  std::uint64_t context_address = 0;
  std::uint32_t stage_raw = 0;
  SendCancelDispatch dispatch = SendCancelDispatch::Unknown;
  SendJobCancelObservation send_job;
  SendJobCancelObservation send_cgi_job;
};

// Input is a stable MessageSendContext object, not an owner-pair address.
// Only the proven co_job object/control identities are accepted for non-null
// jobs. This reads observations; it never cancels, joins, or calls native code.
// Errors clear the entire output. A null context address is invalid.
ReadError ReadSendCancelContextSnapshot(const MemoryReader&, const BinaryIdentity&,
                                        std::uint64_t module_base,
                                        std::uint64_t send_context_address,
                                        SendCancelContextSnapshot&);
const char* SendCancelDispatchName(SendCancelDispatch);

}  // namespace wxhelper::weixin4
