#include "weixin4/auth_backend.h"
#include "weixin4/login_backend.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <vector>

using namespace wxhelper::weixin4;

#define CHECK(expression) do { if (!(expression)) { \
  std::cerr << "line " << __LINE__ << ": " #expression "\n"; std::exit(1); \
} } while (false)

namespace {
constexpr std::uint64_t kBase = 0x180000000;
constexpr std::uint64_t kContext = 0x300000000;
constexpr std::uint64_t kService = 0x400000000;
constexpr std::uint64_t kSentinel = 0x500000000;
constexpr std::uint64_t kBuckets = 0x500001000;
constexpr std::uint64_t kNodes = 0x600000000;
constexpr std::uint64_t kControls = 0x700000000;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

class Snapshot final : public MemoryReader {
 public:
  std::map<std::uint64_t, unsigned char> bytes;
  mutable std::set<std::uint64_t> reads;
  std::optional<std::uint64_t> deny_address;
  bool Read(std::uint64_t address, void* destination, std::size_t count) const override {
    reads.insert(address);
    if (deny_address && address == *deny_address) return false;
    auto* out = static_cast<unsigned char*>(destination);
    for (std::size_t i = 0; i < count; ++i) {
      auto found = bytes.find(address + i);
      if (found == bytes.end()) return false;
      out[i] = found->second;
    }
    return true;
  }
  void U64(std::uint64_t address, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) bytes[address + i] = (value >> (i * 8)) & 255;
  }
  void U32(std::uint64_t address, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) bytes[address + i] = (value >> (i * 8)) & 255;
  }
  void String(std::uint64_t address, const std::string& value, std::uint64_t heap) {
    for (int i = 0; i < 32; ++i) bytes[address + i] = 0;
    const bool large = value.size() > 15;
    if (large) U64(address, heap);
    U64(address + 16, value.size());
    U64(address + 24, large ? value.size() : 15);
    const auto storage = large ? heap : address;
    for (std::size_t i = 0; i < value.size(); ++i) bytes[storage + i] = value[i];
    bytes[storage + value.size()] = 0;
  }
};

struct Entry { std::string key; std::uint32_t raw; unsigned bucket; };
std::uint64_t Node(std::size_t index) { return kNodes + 0x1000 * index; }
std::uint64_t Control(std::size_t index) { return kControls + 0x1000 * index; }

// Bucket indices are fixed test vectors rather than obtained from the decoder.
// c -> 2, a/i/A/q -> 4, b/empty -> 5, missing -> 7 (64-bit FNV-1a mask 7).
Snapshot Fixture(std::vector<Entry> entries = {{"c", 1, 2}, {"a", 3, 4},
                                              {"i", 2, 4}, {"b", 1, 5}}) {
  std::stable_sort(entries.begin(), entries.end(),
                   [](const Entry& a, const Entry& b) { return a.bucket < b.bucket; });
  Snapshot memory;
  memory.U64(kBase + login_layout::kContextPointerRva, kContext);
  memory.U64(kContext, kBase + login_layout::kContextVtableRva);
  memory.U64(kContext + login_layout::kServiceOffset, kService);
  memory.U64(kService, kBase + login_layout::kServiceVtableRva);
  memory.U64(kService + 0x510, kSentinel);
  memory.U64(kService + 0x518, entries.size());
  memory.U64(kService + 0x520, kBuckets);
  memory.U64(kService + 0x528, kBuckets + 128);
  memory.U64(kService + 0x530, kBuckets + 128);
  memory.U64(kService + 0x538, 7);
  memory.U64(kService + 0x540, 8);
  memory.U64(kSentinel, entries.empty() ? kSentinel : Node(0));
  memory.U64(kSentinel + 8, entries.empty() ? kSentinel : Node(entries.size() - 1));
  for (unsigned bucket = 0; bucket < 8; ++bucket) {
    auto first = kSentinel, last = kSentinel;
    for (std::size_t i = 0; i < entries.size(); ++i) {
      if (entries[i].bucket != bucket) continue;
      if (first == kSentinel) first = Node(i);
      last = Node(i);
    }
    memory.U64(kBuckets + 16 * bucket, first);
    memory.U64(kBuckets + 16 * bucket + 8, last);
  }
  for (std::size_t i = 0; i < entries.size(); ++i) {
    memory.U64(Node(i), i + 1 == entries.size() ? kSentinel : Node(i + 1));
    memory.U64(Node(i) + 8, i ? Node(i - 1) : kSentinel);
    memory.String(Node(i) + 0x10, entries[i].key, Node(i) + 0x800);
    memory.U64(Node(i) + 0x30, Control(i) + 0x10);
    memory.U64(Node(i) + 0x38, Control(i));
    memory.U64(Control(i), kBase + auth_layout::kControlVtableRva);
    memory.U32(Control(i) + 8, 1);
    memory.U32(Control(i) + 12, 1);
    memory.U32(Control(i) + 0x110, entries[i].raw);
  }
  return memory;
}

void Cleared(const HostAuthObservation& output) {
  CHECK(output.host.empty());
  CHECK(!output.context_present && !output.service_present && !output.host_entry_present);
  CHECK(output.context_address == 0 && output.service_address == 0);
  CHECK(output.entry_address == 0 && output.auth_object_address == 0);
  CHECK(output.auth_control_address == 0 && !output.state_raw);
  CHECK(output.state == HostAuthState::Unknown && output.bucket_entries_examined == 0);
}
void Fails(const Snapshot& memory, ReadError expected, const Limits& limits = {}) {
  HostAuthObservation output;
  output.host = "stale";
  output.host_entry_present = true;
  output.state_raw = 3;
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output, limits) == expected);
  Cleared(output);
}
}  // namespace

int main() {
  auto memory = Fixture();
  HostAuthObservation output;
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output) == ReadError::None);
  CHECK(output.host == "a" && output.context_present && output.service_present);
  CHECK(output.context_address == kContext && output.service_address == kService);
  CHECK(output.host_entry_present && output.state_raw == 3u);
  CHECK(output.state == HostAuthState::SuccessRecorded && output.bucket_entries_examined == 2);
  CHECK(output.entry_address == Node(1));
  CHECK(output.auth_object_address == Control(1) + 0x10);
  CHECK(output.auth_control_address == Control(1));
  // Input may alias the previous owned output string.
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, output.host, output) == ReadError::None);
  CHECK(output.host == "a" && output.host_entry_present);

  struct StateCase { std::uint32_t raw; HostAuthState state; const char* name; };
  for (auto item : {StateCase{0, HostAuthState::Unknown, "unknown"},
                    StateCase{1, HostAuthState::IdleOrRetryable, "idle_or_retryable"},
                    StateCase{2, HostAuthState::Authenticating, "authenticating"},
                    StateCase{3, HostAuthState::SuccessRecorded, "success_recorded"},
                    StateCase{4, HostAuthState::Unknown, "unknown"},
                    StateCase{0xffffffffU, HostAuthState::Unknown, "unknown"}}) {
    memory = Fixture({{"a", item.raw, 4}});
    CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output) == ReadError::None);
    CHECK(output.host_entry_present && output.state_raw == item.raw && output.state == item.state);
    CHECK(std::string(HostAuthStateName(output.state)) == item.name);
  }

  memory = Fixture();
  for (const auto* missing : {"q", "A", "missing"}) {
    CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, missing, output) == ReadError::None);
    CHECK(!output.host_entry_present && !output.state_raw);
    CHECK(output.state == HostAuthState::Unknown && output.service_present);
    CHECK(output.bucket_entries_examined == (std::string(missing) == "missing" ? 0 : 2));
  }
  for (const auto& entry : {Entry{"a-long-host.example", 3, 2}, Entry{"", 1, 5},
                            Entry{std::string("host\0fixture", 12), 2, 2},
                            Entry{std::string("\xff\x80" "a", 3), 3, 1}}) {
    memory = Fixture({entry});
    CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, entry.key, output) == ReadError::None);
    CHECK(output.host == entry.key && output.host_entry_present && output.state_raw == entry.raw);
    memory.bytes.clear();
    CHECK(output.host == entry.key);  // Owned data outlives the snapshot.
  }

  memory = Fixture({});
  Limits limits;
  limits.max_elements = 0;
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output, limits) == ReadError::None);
  CHECK(output.service_present && !output.host_entry_present);
  memory = Fixture();
  memory.U64(kContext + 0x68, 0);
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output) == ReadError::None);
  CHECK(output.context_present && !output.service_present && !output.state_raw);
  memory.U64(kBase + login_layout::kContextPointerRva, 0);
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output) == ReadError::None);
  CHECK(!output.context_present && output.host == "a");

  // Fault every address read by a valid lookup, including its nonmatching keys
  // and shared objects: no truncated snapshot may retain a partial success.
  memory = Fixture();
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output) == ReadError::None);
  const auto required_addresses = memory.reads;
  for (auto address : required_addresses) {
    memory.deny_address = address;
    Fails(memory, ReadError::Unreadable);
  }

  memory = Fixture();
  limits = {};
  limits.max_elements = 3;
  Fails(memory, ReadError::LimitExceeded, limits);
  limits = {};
  limits.max_total_string_bytes = 5;  // query + a/i + two adjacent-bucket keys.
  CHECK(ReadHostAuthObservation(memory, kIdentity, kBase, "a", output, limits) == ReadError::None);
  limits.max_total_string_bytes = 4;
  Fails(memory, ReadError::LimitExceeded, limits);
  limits = {};
  limits.max_string_bytes = 0;
  Fails(memory, ReadError::LimitExceeded, limits);

  // Map metadata, bucket boundaries, loops, duplicate keys and bad values.
  struct Corruption { std::uint64_t address, value; };
  for (auto bad : {
         Corruption{kContext, 0}, Corruption{kService, 0},
         Corruption{kService + 0x518, 0}, Corruption{kService + 0x518, 1},
         Corruption{kService + 0x538, 6}, Corruption{kService + 0x540, 7},
         Corruption{kService + 0x520, kBuckets + 1},
         Corruption{kService + 0x528, kBuckets + 112},
         Corruption{kService + 0x530, kBuckets + 120},
         Corruption{kService + 0x510, kSentinel + 1},
         Corruption{kSentinel + 8, Node(2)},
         Corruption{kBuckets + 64, kSentinel},
         Corruption{kBuckets + 64, Node(2)},  // Hides earlier same-bucket node.
         Corruption{kBuckets + 72, Node(1)},  // Hides later same-bucket node.
         Corruption{kBuckets + 64, Node(0)},  // Pulls another bucket into range.
         Corruption{Node(2) + 8, Node(2)}, Corruption{Node(1), Node(1)},
         Corruption{Node(1) + 8, kSentinel},
         Corruption{Node(1) + 0x30, 0}, Corruption{Node(2) + 0x38, 0},
         Corruption{Node(1) + 0x30, Control(1) + 0x18},
         Corruption{Control(1), kBase + auth_layout::kControlVtableRva + 8},
         Corruption{Control(1) + 8, 0}}) {
    memory = Fixture();
    memory.U64(bad.address, bad.value);
    Fails(memory, ReadError::InvalidObject);
  }
  memory = Fixture();
  memory.String(Node(2) + 0x10, "a", 0);
  Fails(memory, ReadError::InvalidObject);
  memory = Fixture();
  memory.String(Node(2) + 0x10, "b", 0);
  Fails(memory, ReadError::InvalidObject);
  memory = Fixture();
  memory.U64(Node(1) + 0x28, 0);  // invalid SSO capacity.
  Fails(memory, ReadError::InvalidString);
  memory = Fixture();
  memory.U64(Node(1) + 0x20, 1048577);
  memory.U64(Node(1) + 0x28, 1048577);
  Fails(memory, ReadError::LimitExceeded);
  memory = Fixture({{"a", 3, 4}});
  memory.U64(kService + 0x518, 2);  // Complete list contradicts declared size.
  Fails(memory, ReadError::InvalidObject);

  // Root, service, node, control and bucket arithmetic all remain checked.
  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  memory = Fixture();
  CHECK(ReadHostAuthObservation(memory, kIdentity, maximum - 7, "a", output) == ReadError::AddressOverflow);
  Cleared(output);
  for (bool at_service : {false, true}) {
    memory = Fixture();
    memory.U64(at_service ? kContext + 0x68 : kBase + login_layout::kContextPointerRva,
                maximum - 7);
    memory.U64(maximum - 7, kBase + (at_service ? login_layout::kServiceVtableRva :
                                               login_layout::kContextVtableRva));
    Fails(memory, ReadError::AddressOverflow);
  }
  memory = Fixture();
  memory.U64(kService + 0x540, 1ULL << 63);
  memory.U64(kService + 0x538, (1ULL << 63) - 1);
  Fails(memory, ReadError::AddressOverflow);
  memory = Fixture();
  memory.U64(Node(1) + 0x38, maximum - 0x17);
  memory.U64(Node(1) + 0x30, maximum - 7);
  Fails(memory, ReadError::AddressOverflow);

  memory = Fixture();
  auto wrong = kIdentity;
  wrong.sha256[0] = 'f';
  CHECK(ReadHostAuthObservation(memory, wrong, kBase, "a", output) == ReadError::ProfileMismatch);
  Cleared(output);
  CHECK(memory.reads.empty());
  CHECK(ReadHostAuthObservation(memory, kIdentity, 0, "a", output) == ReadError::InvalidObject);
  CHECK(memory.reads.empty());
  Cleared(output);
  std::cout << "weixin4 host auth snapshot tests passed\n";
}
