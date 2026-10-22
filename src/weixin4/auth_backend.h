#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "memory_reader.h"
#include "profile.h"

namespace wxhelper::weixin4 {

namespace auth_layout {
constexpr std::uint64_t kMapSentinelOffset = 0x510;
constexpr std::uint64_t kMapCountOffset = 0x518;
constexpr std::uint64_t kBucketsBeginOffset = 0x520;
constexpr std::uint64_t kBucketsEndOffset = 0x528;
constexpr std::uint64_t kBucketsCapacityOffset = 0x530;
constexpr std::uint64_t kBucketMaskOffset = 0x538;
constexpr std::uint64_t kBucketCountOffset = 0x540;
constexpr std::uint64_t kNodeKeyOffset = 0x10;
constexpr std::uint64_t kNodeObjectOffset = 0x30;
constexpr std::uint64_t kNodeControlOffset = 0x38;
constexpr std::uint64_t kControlVtableRva = 0x8DFEAD8;
constexpr std::uint64_t kObjectInControlOffset = 0x10;
constexpr std::uint64_t kStateOffset = 0x100;
}  // namespace auth_layout

// Describes this host's local AxAuthLogic state, never global login/online state.
// Idle also covers initial, stopped and failed attempts; success is a recorded
// callback result, not a guarantee that a session is still valid or connected.
enum class HostAuthState { Unknown, IdleOrRetryable, Authenticating, SuccessRecorded };

struct HostAuthObservation {
  std::string host;
  bool context_present = false;
  bool service_present = false;
  bool host_entry_present = false;
  std::uint64_t context_address = 0;
  std::uint64_t service_address = 0;
  std::uint64_t entry_address = 0;
  std::uint64_t auth_object_address = 0;
  std::uint64_t auth_control_address = 0;
  std::optional<std::uint32_t> state_raw;
  HostAuthState state = HostAuthState::Unknown;
  std::size_t bucket_entries_examined = 0;
};

// Exact byte/case-sensitive host lookup in a stable caller-provided snapshot.
// Validates the selected bucket, shared-object identity and root/service vtables;
// does not acquire a live process/lock, call client code or modify refcounts.
// Missing context/service/entry succeeds with corresponding presence false.
// A present raw 0 remains distinct from a missing entry. Errors clear output.
// String budget includes the query plus every examined key (including neighbors).
ReadError ReadHostAuthObservation(const MemoryReader&, const BinaryIdentity&,
                                  std::uint64_t module_base, std::string_view host,
                                  HostAuthObservation&, const Limits& = {});
const char* HostAuthStateName(HostAuthState);

}  // namespace wxhelper::weixin4
