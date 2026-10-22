#include "send_cancel_contract.h"

#include <limits>
#include <utility>

namespace wxhelper::weixin4 {
namespace {
ReadError ReadJob(const MemoryReader& memory, std::uint64_t pair_address,
                  std::uint64_t expected_object_vtable,
                  std::uint64_t expected_control_vtable,
                  SendJobCancelObservation& job) {
  auto error = ReadU64(memory, pair_address, job.object_address);
  if (error != ReadError::None) return error;
  std::uint64_t address = 0;
  if (!CheckedAdd(pair_address, 8, address)) return ReadError::AddressOverflow;
  error = ReadU64(memory, address, job.control_address);
  if (error != ReadError::None) return error;
  // Native Cancel branches on the stored object, not the control pointer.
  // An absent object can still have an aliasing owner; do not follow it.
  if (!job.object_address) return ReadError::None;
  if (!job.control_address || job.object_address % 8 || job.control_address % 8)
    return ReadError::InvalidObject;
  if (!CheckedAdd(job.control_address, 0x10, address))
    return ReadError::AddressOverflow;
  if (address != job.object_address) return ReadError::InvalidObject;

  std::uint64_t vtable = 0;
  error = ReadU64(memory, job.object_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != expected_object_vtable) return ReadError::InvalidObject;
  error = ReadU64(memory, job.control_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != expected_control_vtable) return ReadError::InvalidObject;

  std::uint32_t strong = 0;
  std::uint32_t weak = 0;
  if (!CheckedAdd(job.control_address, 8, address))
    return ReadError::AddressOverflow;
  error = ReadU32(memory, address, strong);
  if (error != ReadError::None) return error;
  if (!CheckedAdd(job.control_address, 12, address))
    return ReadError::AddressOverflow;
  error = ReadU32(memory, address, weak);
  if (error != ReadError::None) return error;
  const auto maximum_count = (std::numeric_limits<std::int32_t>::max)();
  if (!strong || !weak || strong > static_cast<std::uint32_t>(maximum_count) ||
      weak > static_cast<std::uint32_t>(maximum_count))
    return ReadError::InvalidObject;

  for (const auto field : {
         std::pair<std::uint64_t, std::uint8_t*>{send_cancel_layout::kStartedOffset,
                                                &job.started_raw},
         {send_cancel_layout::kActiveOffset, &job.active_raw},
         {send_cancel_layout::kCancelRequestedOffset, &job.cancel_requested_raw}}) {
    if (!CheckedAdd(job.object_address, field.first, address))
      return ReadError::AddressOverflow;
    if (!memory.Read(address, field.second, 1)) return ReadError::Unreadable;
  }
  // The original consumers mask the low bit. Preserve high bits as raw data.
  job.started = (job.started_raw & 1) != 0;
  job.active = (job.active_raw & 1) != 0;
  job.cancel_requested = (job.cancel_requested_raw & 1) != 0;
  job.present = true;
  return ReadError::None;
}
}  // namespace

ReadError ReadSendCancelContextSnapshot(const MemoryReader& memory,
                                        const BinaryIdentity& identity,
                                        std::uint64_t module_base,
                                        std::uint64_t send_context_address,
                                        SendCancelContextSnapshot& output) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!module_base || !send_context_address || send_context_address % 8)
    return ReadError::InvalidObject;
  std::uint64_t context_vtable = 0;
  std::uint64_t job_vtable = 0;
  std::uint64_t control_vtable = 0;
  if (!CheckedAdd(module_base, send_cancel_layout::kContextVtableRva, context_vtable) ||
      !CheckedAdd(module_base, send_cancel_layout::kJobVtableRva, job_vtable) ||
      !CheckedAdd(module_base, send_cancel_layout::kJobControlVtableRva, control_vtable))
    return ReadError::AddressOverflow;
  std::uint64_t vtable = 0;
  auto error = ReadU64(memory, send_context_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != context_vtable) return ReadError::InvalidObject;

  SendCancelContextSnapshot value;
  value.context_address = send_context_address;
  std::uint64_t address = 0;
  if (!CheckedAdd(send_context_address, send_cancel_layout::kStageOffset, address))
    return ReadError::AddressOverflow;
  error = ReadU32(memory, address, value.stage_raw);
  if (error != ReadError::None) return error;
  if (!CheckedAdd(send_context_address, send_cancel_layout::kSendJobOffset, address))
    return ReadError::AddressOverflow;
  error = ReadJob(memory, address, job_vtable, control_vtable, value.send_job);
  if (error != ReadError::None) return error;
  if (!CheckedAdd(send_context_address, send_cancel_layout::kSendCgiJobOffset, address))
    return ReadError::AddressOverflow;
  error = ReadJob(memory, address, job_vtable, control_vtable, value.send_cgi_job);
  if (error != ReadError::None) return error;
  value.dispatch = value.send_job.present || value.send_cgi_job.present
      ? SendCancelDispatch::JobCancelAndJoin : SendCancelDispatch::PrepareShowLookup;
  output = value;
  return ReadError::None;
}

const char* SendCancelDispatchName(SendCancelDispatch dispatch) {
  switch (dispatch) {
    case SendCancelDispatch::Unknown: return "unknown";
    case SendCancelDispatch::PrepareShowLookup: return "prepare_show_lookup";
    case SendCancelDispatch::JobCancelAndJoin: return "job_cancel_and_join";
  }
  return "unknown";
}
}  // namespace wxhelper::weixin4
