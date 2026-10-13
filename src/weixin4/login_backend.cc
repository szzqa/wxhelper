#include "login_backend.h"

#include <algorithm>
#include <array>
#include <utility>

namespace wxhelper::weixin4 {
namespace {
ReadError ReadPointerAt(const MemoryReader& memory, std::uint64_t object,
                        std::uint64_t offset, std::uint64_t& pointer) {
  std::uint64_t address = 0;
  if (!CheckedAdd(object, offset, address)) return ReadError::AddressOverflow;
  return ReadU64(memory, address, pointer);
}
}  // namespace

ReadError ReadLoginObservation(const MemoryReader& memory,
                               const BinaryIdentity& identity,
                               std::uint64_t module_base,
                               LoginObservation& output, const Limits& limits) {
  output = {};
  if (!MatchesProfile(identity)) return ReadError::ProfileMismatch;
  if (!module_base) return ReadError::InvalidObject;

  std::uint64_t context_vtable = 0;
  std::uint64_t service_vtable = 0;
  if (!CheckedAdd(module_base, login_layout::kContextVtableRva, context_vtable) ||
      !CheckedAdd(module_base, login_layout::kServiceVtableRva, service_vtable))
    return ReadError::AddressOverflow;

  LoginObservation observation;
  auto error = ReadPointerAt(memory, module_base, login_layout::kContextPointerRva,
                             observation.context_address);
  if (error != ReadError::None) return error;
  if (!observation.context_address) return ReadError::None;

  std::uint64_t vtable = 0;
  error = ReadU64(memory, observation.context_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != context_vtable) return ReadError::InvalidObject;
  observation.context_present = true;

  error = ReadPointerAt(memory, observation.context_address,
                        login_layout::kServiceOffset, observation.service_address);
  if (error != ReadError::None) return error;
  error = ReadPointerAt(memory, observation.context_address,
                        login_layout::kServiceControlOffset,
                        observation.service_control_address);
  if (error != ReadError::None) return error;
  if (!observation.service_address) {
    output = std::move(observation);
    return ReadError::None;
  }

  error = ReadU64(memory, observation.service_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != service_vtable) return ReadError::InvalidObject;

  std::uint64_t address = 0;
  std::uint64_t last = 0;
  if (!CheckedAdd(observation.service_address, login_layout::kFlag38Offset, address) ||
      !CheckedAdd(address, 1, last)) return ReadError::AddressOverflow;
  std::array<unsigned char, 2> flags{};
  if (!memory.Read(address, flags.data(), flags.size())) return ReadError::Unreadable;
  observation.service_flag38 = flags[0];
  observation.service_flag39 = flags[1];
  observation.service_slot0_value = (flags[0] & 1) != 0;
  observation.service_field39_low_bit = (flags[1] & 1) != 0;
  observation.has_service_flags = true;

  if (!CheckedAdd(observation.service_address, login_layout::kAccountLookupKeyOffset,
                  address)) return ReadError::AddressOverflow;
  auto string_limits = limits;
  string_limits.max_string_bytes = (std::min)(limits.max_string_bytes,
                                             limits.max_total_string_bytes);
  error = ReadString(memory, address, observation.account_lookup_key, string_limits);
  if (error != ReadError::None) return error;
  observation.service_present = true;
  output = std::move(observation);
  return ReadError::None;
}

const char* LoginStateName(LoginState state) {
  switch (state) {
    case LoginState::Unknown: return "unknown";
    case LoginState::LoggedOut: return "logged_out";
    case LoginState::LoggedIn: return "logged_in";
  }
  return "unknown";
}

}  // namespace wxhelper::weixin4
