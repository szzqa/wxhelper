#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wxhelper::weixin4 {

// A caller-supplied, stable address space. This library does not open a process,
// dereference native pointers, install hooks, or invoke client code.
class MemoryReader {
 public:
  virtual ~MemoryReader() = default;
  virtual bool Read(std::uint64_t address, void* destination,
                    std::size_t bytes) const = 0;
};

enum class ReadError {
  None, Unreadable, AddressOverflow, InvalidString, LimitExceeded,
  InvalidVector, InvalidObject, UnsupportedLayout, ProfileMismatch
};

struct Limits {
  std::size_t max_string_bytes = 1024 * 1024;
  std::size_t max_elements = 10000;
  std::size_t max_total_string_bytes = 8 * 1024 * 1024;
};

struct VectorRange {
  std::uint64_t begin = 0;
  std::uint64_t end = 0;
  std::uint64_t capacity_end = 0;
  std::size_t size = 0;
};

bool CheckedAdd(std::uint64_t address, std::uint64_t offset,
                std::uint64_t& result);
ReadError ReadU32(const MemoryReader&, std::uint64_t address, std::uint32_t&);
ReadError ReadU64(const MemoryReader&, std::uint64_t address, std::uint64_t&);

// Observed x64 MSVC narrow-string storage: union[16], size, capacity.
// The caller must establish field identity separately; decoding alone does not.
ReadError ReadString(const MemoryReader&, std::uint64_t address,
                     std::string& output, const Limits& = {});
ReadError ReadVectorRange(const MemoryReader&, std::uint64_t address,
                          std::size_t stride, VectorRange& output,
                          const Limits& = {});
ReadError ReadStringVector(const MemoryReader&, std::uint64_t address,
                           std::vector<std::string>& output,
                           const Limits& = {});
const char* ReadErrorName(ReadError);

}  // namespace wxhelper::weixin4
