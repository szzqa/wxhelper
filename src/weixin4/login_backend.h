#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "memory_reader.h"
#include "profile.h"

namespace wxhelper::weixin4 {

namespace login_layout {
constexpr std::uint64_t kContextPointerRva = 0xB912690;
constexpr std::uint64_t kContextVtableRva = 0x8D804E8;
constexpr std::uint64_t kServiceVtableRva = 0x8DFE2F8;
constexpr std::uint64_t kServiceOffset = 0x68;
constexpr std::uint64_t kServiceControlOffset = 0x70;
constexpr std::uint64_t kKernelStageOffset = 0x330;
constexpr std::uint64_t kFlag38Offset = 0x38;
constexpr std::uint64_t kAccountLookupKeyOffset = 0x48;
}  // namespace login_layout

enum class LoginState { Unknown, LoggedOut, LoggedIn };

// Descriptions of observed local lifecycle paths, not recovered enum symbols
// and not server authentication or network connection states.
enum class KernelPhase {
  Unknown, Initialized, LoginFlow, SetupCallbackComplete, LogoutFlow
};

struct LoginObservation {
  // Authentication semantics of the observed flags are not established yet.
  LoginState state = LoginState::Unknown;
  // Root +0x330 is a 32-bit value written by SetKernelStage (RVA 0x45510).
  // A missing root leaves raw disengaged. Unrecognized values remain observable
  // as raw data with phase Unknown; none of these values changes state.
  std::optional<std::uint32_t> kernel_stage_raw;
  KernelPhase kernel_phase = KernelPhase::Unknown;
  bool context_present = false;
  bool service_present = false;
  std::uint64_t context_address = 0;
  std::uint64_t service_address = 0;
  std::uint64_t service_control_address = 0;
  bool has_service_flags = false;
  std::uint8_t service_flag38 = 0;
  std::uint8_t service_flag39 = 0;
  bool service_slot0_value = false;
  bool service_field39_low_bit = false;
  // Service +0x39 is set before the logout coroutine and checked to cancel
  // autoauth. False does not establish login; true does not mean logout has
  // completed. Absent service/failed decoding leaves this disengaged.
  std::optional<bool> logout_started;
  // Key returned through context vtable+0x20 / service vtable+0x18 and
  // consumed by the account-info handler. Presence does not imply login.
  std::string account_lookup_key;
};

// Decode a stable caller-provided snapshot. Neither acquires a live process nor
// invokes the vtable/getters or adjusts the snapshot's shared_ptr reference counts.
// A null context/service is a valid observation; errors clear the whole output.
ReadError ReadLoginObservation(const MemoryReader&, const BinaryIdentity&,
                               std::uint64_t module_base,
                               LoginObservation&, const Limits& = {});
const char* LoginStateName(LoginState);
const char* KernelPhaseName(KernelPhase);

}  // namespace wxhelper::weixin4
