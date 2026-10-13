#include "memory_reader.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace wxhelper::weixin4 {
namespace {
template <typename T>
ReadError ReadScalar(const MemoryReader& memory, std::uint64_t address, T& out) {
  out = 0;
  std::uint64_t last = 0;
  if (!CheckedAdd(address, sizeof(T) - 1, last)) return ReadError::AddressOverflow;
  T value = 0;
  if (!memory.Read(address, &value, sizeof(value))) return ReadError::Unreadable;
  out = value;
  return ReadError::None;
}

std::uint64_t U64(const unsigned char* bytes) {
  std::uint64_t result = 0;
  for (int i = 7; i >= 0; --i) result = (result << 8) | bytes[i];
  return result;
}
}  // namespace

bool CheckedAdd(std::uint64_t address, std::uint64_t offset,
                std::uint64_t& result) {
  if (offset > (std::numeric_limits<std::uint64_t>::max)() - address) return false;
  result = address + offset;
  return true;
}

ReadError ReadU32(const MemoryReader& memory, std::uint64_t address, std::uint32_t& out) {
  return ReadScalar(memory, address, out);
}
ReadError ReadU64(const MemoryReader& memory, std::uint64_t address, std::uint64_t& out) {
  return ReadScalar(memory, address, out);
}

ReadError ReadString(const MemoryReader& memory, std::uint64_t address,
                     std::string& output, const Limits& limits) {
  output.clear();
  std::uint64_t last = 0;
  if (!CheckedAdd(address, 31, last)) return ReadError::AddressOverflow;
  std::array<unsigned char, 32> storage{};
  if (!memory.Read(address, storage.data(), storage.size())) return ReadError::Unreadable;
  const auto size = U64(storage.data() + 16);
  const auto capacity = U64(storage.data() + 24);
  if (size > capacity || (capacity < 16 && capacity != 15)) return ReadError::InvalidString;
  if (size > limits.max_string_bytes || size >= (std::numeric_limits<std::size_t>::max)())
    return ReadError::LimitExceeded;
  if (capacity < 16) {
    if (storage[static_cast<std::size_t>(size)] != 0) return ReadError::InvalidString;
    output.assign(reinterpret_cast<const char*>(storage.data()), static_cast<std::size_t>(size));
    return ReadError::None;
  }
  const auto pointer = U64(storage.data());
  if (!pointer) return ReadError::InvalidString;
  if (!CheckedAdd(pointer, size, last)) return ReadError::AddressOverflow;
  std::string value(static_cast<std::size_t>(size) + 1, '\0');
  if (!memory.Read(pointer, value.data(), value.size())) return ReadError::Unreadable;
  if (value.back() != '\0') return ReadError::InvalidString;
  value.pop_back();
  output = std::move(value);
  return ReadError::None;
}

ReadError ReadVectorRange(const MemoryReader& memory, std::uint64_t address,
                          std::size_t stride, VectorRange& output, const Limits& limits) {
  output = {};
  if (!stride) return ReadError::InvalidVector;
  std::uint64_t last = 0;
  if (!CheckedAdd(address, 23, last)) return ReadError::AddressOverflow;
  std::array<unsigned char, 24> storage{};
  if (!memory.Read(address, storage.data(), storage.size())) return ReadError::Unreadable;
  VectorRange range{U64(storage.data()), U64(storage.data() + 8), U64(storage.data() + 16), 0};
  if (range.begin > range.end || range.end > range.capacity_end ||
      (!range.begin && (range.end || range.capacity_end)) ||
      (range.end - range.begin) % stride || (range.capacity_end - range.begin) % stride)
    return ReadError::InvalidVector;
  const auto count = (range.end - range.begin) / stride;
  if (count > limits.max_elements || count > (std::numeric_limits<std::size_t>::max)())
    return ReadError::LimitExceeded;
  range.size = static_cast<std::size_t>(count);
  output = range;
  return ReadError::None;
}

ReadError ReadStringVector(const MemoryReader& memory, std::uint64_t address,
                           std::vector<std::string>& output, const Limits& limits) {
  output.clear();
  VectorRange range;
  const auto status = ReadVectorRange(memory, address, 32, range, limits);
  if (status != ReadError::None) return status;
  std::vector<std::string> result;
  result.reserve(range.size);
  auto remaining = limits.max_total_string_bytes;
  for (std::size_t i = 0; i < range.size; ++i) {
    std::string value;
    auto entry_limits = limits;
    entry_limits.max_string_bytes = (std::min)(remaining, limits.max_string_bytes);
    const auto error = ReadString(memory, range.begin + i * 32, value, entry_limits);
    if (error != ReadError::None) return error;
    remaining -= value.size();
    result.push_back(std::move(value));
  }
  output = std::move(result);
  return ReadError::None;
}

const char* ReadErrorName(ReadError error) {
  switch (error) {
    case ReadError::None: return "ok";
    case ReadError::Unreadable: return "unreadable";
    case ReadError::AddressOverflow: return "address_overflow";
    case ReadError::InvalidString: return "invalid_string";
    case ReadError::LimitExceeded: return "limit_exceeded";
    case ReadError::InvalidVector: return "invalid_vector";
    case ReadError::InvalidObject: return "invalid_object";
    case ReadError::UnsupportedLayout: return "unsupported_layout";
    case ReadError::ProfileMismatch: return "profile_mismatch";
  }
  return "unknown";
}
}  // namespace wxhelper::weixin4
