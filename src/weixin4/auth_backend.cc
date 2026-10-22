#include "auth_backend.h"

#include <algorithm>
#include <limits>
#include <unordered_set>
#include <utility>

#include "login_backend.h"

namespace wxhelper::weixin4 {
namespace {
bool Aligned(std::uint64_t address) {
  return address != 0 && (address & 7) == 0;
}

ReadError PointerAt(const MemoryReader& memory, std::uint64_t object,
                    std::uint64_t offset, std::uint64_t& value) {
  std::uint64_t address = 0;
  if (!CheckedAdd(object, offset, address)) return ReadError::AddressOverflow;
  return ReadU64(memory, address, value);
}

ReadError Links(const MemoryReader& memory, std::uint64_t node,
                std::uint64_t& next, std::uint64_t& previous) {
  if (!Aligned(node)) return ReadError::InvalidObject;
  auto error = ReadU64(memory, node, next);
  if (error != ReadError::None) return error;
  error = PointerAt(memory, node, 8, previous);
  if (error != ReadError::None) return error;
  return Aligned(next) && Aligned(previous) ? ReadError::None : ReadError::InvalidObject;
}

ReadError ReciprocalLinks(const MemoryReader& memory, std::uint64_t node,
                          std::uint64_t next, std::uint64_t previous) {
  std::uint64_t back = 0, forward = 0;
  auto error = PointerAt(memory, next, 8, back);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, previous, forward);
  if (error != ReadError::None) return error;
  return back == node && forward == node ? ReadError::None : ReadError::InvalidObject;
}

// RVA 0x3730c0 uses FNV-1a over unsigned bytes, with no case/URL normalization.
std::uint64_t HostHash(std::string_view host) {
  std::uint64_t hash = 0xcbf29ce484222325ULL;
  for (const unsigned char byte : host) hash = (hash ^ byte) * 0x100000001b3ULL;
  return hash;
}

ReadError Key(const MemoryReader& memory, std::uint64_t node, std::string& key,
              const Limits& limits, std::size_t& remaining) {
  std::uint64_t address = 0;
  if (!CheckedAdd(node, auth_layout::kNodeKeyOffset, address))
    return ReadError::AddressOverflow;
  auto bounded = limits;
  bounded.max_string_bytes = (std::min)(remaining, limits.max_string_bytes);
  auto error = ReadString(memory, address, key, bounded);
  if (error == ReadError::None) remaining -= key.size();
  return error;
}

HostAuthState DecodeState(std::uint32_t raw) {
  switch (raw) {
    case 1: return HostAuthState::IdleOrRetryable;
    case 2: return HostAuthState::Authenticating;
    case 3: return HostAuthState::SuccessRecorded;
    default: return HostAuthState::Unknown;
  }
}

ReadError AuthObject(const MemoryReader& memory, std::uint64_t node,
                     std::uint64_t expected_vtable, std::uint64_t& object,
                     std::uint64_t& control, std::uint32_t& raw) {
  auto error = PointerAt(memory, node, auth_layout::kNodeObjectOffset, object);
  if (error != ReadError::None) return error;
  error = PointerAt(memory, node, auth_layout::kNodeControlOffset, control);
  if (error != ReadError::None) return error;
  if (!Aligned(object) || !Aligned(control)) return ReadError::InvalidObject;
  std::uint64_t expected_object = 0, last = 0;
  if (!CheckedAdd(control, auth_layout::kObjectInControlOffset, expected_object) ||
      !CheckedAdd(control, 0x187, last)) return ReadError::AddressOverflow;
  if (object != expected_object) return ReadError::InvalidObject;
  std::uint64_t vtable = 0;
  error = ReadU64(memory, control, vtable);
  if (error != ReadError::None) return error;
  if (vtable != expected_vtable) return ReadError::InvalidObject;
  std::uint32_t strong = 0, weak = 0;
  error = ReadU32(memory, control + 8, strong);
  if (error != ReadError::None) return error;
  error = ReadU32(memory, control + 12, weak);
  if (error != ReadError::None) return error;
  if (!strong || !weak || strong > 0x7fffffffU || weak > 0x7fffffffU)
    return ReadError::InvalidObject;
  return ReadU32(memory, object + auth_layout::kStateOffset, raw);
}
}  // namespace

ReadError ReadHostAuthObservation(const MemoryReader& memory,
                                  const BinaryIdentity& identity,
                                  std::uint64_t module_base, std::string_view host,
                                  HostAuthObservation& output, const Limits& limits) {
  if (!MatchesProfile(identity)) {
    output = {};
    return ReadError::ProfileMismatch;
  }
  if (host.size() > limits.max_string_bytes ||
      host.size() > limits.max_total_string_bytes) {
    output = {};
    return ReadError::LimitExceeded;
  }
  // The query may refer to output.host from a previous successful observation.
  std::string query(host);
  output = {};
  if (!Aligned(module_base)) return ReadError::InvalidObject;
  std::uint64_t context_vtable = 0, service_vtable = 0, control_vtable = 0;
  if (!CheckedAdd(module_base, login_layout::kContextVtableRva, context_vtable) ||
      !CheckedAdd(module_base, login_layout::kServiceVtableRva, service_vtable) ||
      !CheckedAdd(module_base, auth_layout::kControlVtableRva, control_vtable))
    return ReadError::AddressOverflow;
  HostAuthObservation result;
  result.host = std::move(query);
  std::size_t remaining = limits.max_total_string_bytes - result.host.size();
  auto error = PointerAt(memory, module_base, login_layout::kContextPointerRva,
                         result.context_address);
  if (error != ReadError::None) return error;
  if (!result.context_address) {
    output = std::move(result);
    return ReadError::None;
  }
  if (!Aligned(result.context_address)) return ReadError::InvalidObject;
  std::uint64_t vtable = 0;
  error = ReadU64(memory, result.context_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != context_vtable) return ReadError::InvalidObject;
  result.context_present = true;
  error = PointerAt(memory, result.context_address, login_layout::kServiceOffset,
                    result.service_address);
  if (error != ReadError::None) return error;
  if (!result.service_address) {
    output = std::move(result);
    return ReadError::None;
  }
  if (!Aligned(result.service_address)) return ReadError::InvalidObject;
  error = ReadU64(memory, result.service_address, vtable);
  if (error != ReadError::None) return error;
  if (vtable != service_vtable) return ReadError::InvalidObject;
  result.service_present = true;

  // MSVC unordered_map header published by RVA 0x370c20 under service+0x4b0.
  // Only snapshot bytes are read: no client SRW lock or reference count changes.
  std::uint64_t sentinel = 0, count = 0, begin = 0, end = 0, capacity = 0;
  std::uint64_t mask = 0, bucket_count = 0;
  struct HeaderField { std::uint64_t offset; std::uint64_t* destination; };
  for (auto field : {
         HeaderField{auth_layout::kMapSentinelOffset, &sentinel},
         HeaderField{auth_layout::kMapCountOffset, &count},
         HeaderField{auth_layout::kBucketsBeginOffset, &begin},
         HeaderField{auth_layout::kBucketsEndOffset, &end},
         HeaderField{auth_layout::kBucketsCapacityOffset, &capacity},
         HeaderField{auth_layout::kBucketMaskOffset, &mask},
         HeaderField{auth_layout::kBucketCountOffset, &bucket_count}}) {
    error = PointerAt(memory, result.service_address, field.offset, *field.destination);
    if (error != ReadError::None) return error;
  }
  if (count > limits.max_elements) return ReadError::LimitExceeded;
  if (bucket_count < 8 || (bucket_count & (bucket_count - 1)) ||
      mask != bucket_count - 1) return ReadError::InvalidObject;
  if (bucket_count > (std::numeric_limits<std::uint64_t>::max)() / 16)
    return ReadError::AddressOverflow;
  if (!Aligned(begin) || !Aligned(end) || !Aligned(capacity) ||
      begin > end || end > capacity || (capacity - begin) % 16 ||
      end - begin != bucket_count * 16) return ReadError::InvalidObject;

  std::uint64_t head = 0, tail = 0;
  error = Links(memory, sentinel, head, tail);
  if (error != ReadError::None) return error;
  if ((!count && (head != sentinel || tail != sentinel)) ||
      (count && (head == sentinel || tail == sentinel))) return ReadError::InvalidObject;
  error = ReciprocalLinks(memory, sentinel, head, tail);
  if (error != ReadError::None) return error;

  const auto bucket = HostHash(result.host) & mask;
  // Header validation proves this slot and its 8-byte last pointer are within end.
  const auto bucket_address = begin + bucket * 16;
  std::uint64_t first = 0, last = 0;
  error = ReadU64(memory, bucket_address, first);
  if (error != ReadError::None) return error;
  error = ReadU64(memory, bucket_address + 8, last);
  if (error != ReadError::None) return error;
  if (!Aligned(first) || !Aligned(last) ||
      ((first == sentinel) != (last == sentinel))) return ReadError::InvalidObject;
  if (first == sentinel) {
    output = std::move(result);
    return ReadError::None;
  }
  if (!count) return ReadError::InvalidObject;

  std::unordered_set<std::uint64_t> visited;
  std::unordered_set<std::string> keys;
  std::uint64_t current = last, before_first = 0, after_last = 0;
  for (;;) {
    if (current == sentinel || visited.size() >= count ||
        !visited.insert(current).second) return ReadError::InvalidObject;
    std::uint64_t next = 0, previous = 0;
    error = Links(memory, current, next, previous);
    if (error != ReadError::None) return error;
    error = ReciprocalLinks(memory, current, next, previous);
    if (error != ReadError::None) return error;
    if (current == last) after_last = next;
    std::string key;
    error = Key(memory, current, key, limits, remaining);
    if (error != ReadError::None) return error;
    if ((HostHash(key) & mask) != bucket) return ReadError::InvalidObject;
    const bool matched = key == result.host;
    if (!keys.insert(std::move(key)).second) return ReadError::InvalidObject;
    std::uint64_t object = 0, control = 0;
    std::uint32_t raw = 0;
    error = AuthObject(memory, current, control_vtable, object, control, raw);
    if (error != ReadError::None) return error;
    ++result.bucket_entries_examined;
    if (matched) {
      result.host_entry_present = true;
      result.entry_address = current;
      result.auth_object_address = object;
      result.auth_control_address = control;
      result.state_raw = raw;
      result.state = DecodeState(raw);
    }
    if (current == first) {
      before_first = previous;
      break;
    }
    current = previous;
  }

  // A truncated bucket range must not hide another same-bucket key beside it.
  for (auto neighbor : {before_first, after_last}) {
    if (neighbor == sentinel) continue;
    if (visited.count(neighbor)) return ReadError::InvalidObject;
    std::string key;
    error = Key(memory, neighbor, key, limits, remaining);
    if (error != ReadError::None) return error;
    if ((HostHash(key) & mask) == bucket) return ReadError::InvalidObject;
  }
  const bool entire_list = before_first == sentinel && after_last == sentinel;
  if (entire_list != (visited.size() == count)) return ReadError::InvalidObject;
  if (entire_list && (head != first || tail != last)) return ReadError::InvalidObject;
  output = std::move(result);
  return ReadError::None;
}

const char* HostAuthStateName(HostAuthState state) {
  switch (state) {
    case HostAuthState::Unknown: return "unknown";
    case HostAuthState::IdleOrRetryable: return "idle_or_retryable";
    case HostAuthState::Authenticating: return "authenticating";
    case HostAuthState::SuccessRecorded: return "success_recorded";
  }
  return "unknown";
}
}  // namespace wxhelper::weixin4
