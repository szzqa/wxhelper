#include "weixin4/login_backend.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>

using namespace wxhelper::weixin4;

#define CHECK(expression) do { if (!(expression)) { \
  std::cerr << "line " << __LINE__ << ": " #expression "\n"; std::exit(1); \
} } while (false)

namespace {
class Snapshot final : public MemoryReader {
 public:
  mutable std::size_t reads = 0;
  std::map<std::uint64_t, unsigned char> bytes;

  bool Read(std::uint64_t address, void* destination, std::size_t size) const override {
    ++reads;
    auto* out = static_cast<unsigned char*>(destination);
    for (std::size_t i = 0; i < size; ++i) {
      const auto found = bytes.find(address + i);
      if (found == bytes.end()) return false;
      out[i] = found->second;
    }
    return true;
  }
  void U64(std::uint64_t address, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[address + i] = (value >> (i * 8)) & 255;
  }
  void U32(std::uint64_t address, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[address + i] = (value >> (i * 8)) & 255;
  }
  void String(std::uint64_t address, const std::string& value,
              std::uint64_t heap = 0) {
    for (unsigned i = 0; i < 32; ++i) bytes[address + i] = 0;
    if (heap) U64(address, heap);
    U64(address + 16, value.size());
    U64(address + 24, heap ? value.size() : 15);
    const auto storage = heap ? heap : address;
    for (std::size_t i = 0; i < value.size(); ++i) bytes[storage + i] = value[i];
    bytes[storage + value.size()] = 0;
  }
};

constexpr std::uint64_t kBase = 0x180000000;
constexpr std::uint64_t kContext = 0x300000000;
constexpr std::uint64_t kService = 0x400000000;
constexpr std::uint64_t kControl = 0x500000000;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

Snapshot Fixture(std::uint8_t flag38 = 1, std::uint8_t flag39 = 0) {
  Snapshot memory;
  memory.U64(kBase + login_layout::kContextPointerRva, kContext);
  memory.U64(kContext, kBase + login_layout::kContextVtableRva);
  memory.U32(kContext + login_layout::kKernelStageOffset, 3);
  memory.U64(kContext + 0x68, kService);
  memory.U64(kContext + 0x70, kControl);
  memory.U64(kService, kBase + login_layout::kServiceVtableRva);
  memory.bytes[kService + 0x38] = flag38;
  memory.bytes[kService + 0x39] = flag39;
  memory.String(kService + 0x48, "fixture-account");
  return memory;
}

void CheckCleared(const LoginObservation& value) {
  CHECK(value.state == LoginState::Unknown);
  CHECK(!value.kernel_is_login.has_value());
  CHECK(!value.kernel_stage_raw.has_value());
  CHECK(value.kernel_phase == KernelPhase::Unknown);
  CHECK(!value.context_present && !value.service_present && !value.has_service_flags);
  CHECK(value.context_address == 0 && value.service_address == 0);
  CHECK(value.service_control_address == 0 && value.account_lookup_key.empty());
  CHECK(value.service_flag38 == 0 && value.service_flag39 == 0);
  CHECK(!value.service_slot0_value && !value.service_field39_low_bit);
  CHECK(!value.logout_started.has_value());
}
}  // namespace

int main() {
  LoginObservation output;
  auto memory = Fixture();
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CHECK(output.context_present && output.service_present && output.has_service_flags);
  CHECK(output.context_address == kContext && output.service_address == kService);
  CHECK(output.service_control_address == kControl);
  CHECK(output.account_lookup_key == "fixture-account");
  CHECK(output.service_slot0_value && !output.service_field39_low_bit);
  CHECK(output.logout_started.has_value() && !*output.logout_started);
  CHECK(output.state == LoginState::Unknown);
  CHECK(output.kernel_is_login == true);
  CHECK(output.kernel_stage_raw == 3u);
  CHECK(output.kernel_phase == KernelPhase::SetupCallbackComplete);

  // Local stages can be observed with or without a login service. They cannot
  // establish server authentication, including setup-complete stage 3.
  struct StageCase { std::uint32_t raw; KernelPhase phase; const char* name; };
  for (const auto& test : {
         StageCase{0, KernelPhase::Unknown, "unknown"},
         StageCase{1, KernelPhase::Initialized, "initialized"},
         StageCase{2, KernelPhase::LoginFlow, "login_flow"},
         StageCase{3, KernelPhase::SetupCallbackComplete, "setup_callback_complete"},
         StageCase{4, KernelPhase::LogoutFlow, "logout_flow"},
         StageCase{5, KernelPhase::Unknown, "unknown"},
         StageCase{0xffffffffu, KernelPhase::Unknown, "unknown"}}) {
    for (bool service_present : {false, true}) {
      memory = Fixture();
      memory.U32(kContext + login_layout::kKernelStageOffset, test.raw);
      if (!service_present) memory.U64(kContext + 0x68, 0);
      CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
      CHECK(output.kernel_stage_raw == test.raw);
      CHECK(output.kernel_phase == test.phase);
      CHECK(std::string(KernelPhaseName(output.kernel_phase)) == test.name);
      CHECK(output.service_present == service_present);
      CHECK(output.kernel_is_login.has_value());
      CHECK(*output.kernel_is_login == service_present);
      CHECK(output.state == LoginState::Unknown);
    }
  }

  // The local IsLogin predicate masks the low bit, independently of auth state.
  for (auto flags : {0, 1, 2, 255}) {
    memory = Fixture(static_cast<std::uint8_t>(flags), static_cast<std::uint8_t>(flags));
    CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
    CHECK(output.service_flag38 == flags && output.service_flag39 == flags);
    CHECK(output.service_slot0_value == ((flags & 1) != 0));
    CHECK(output.kernel_is_login.has_value());
    CHECK(*output.kernel_is_login == ((flags & 1) != 0));
    CHECK(output.service_field39_low_bit == ((flags & 1) != 0));
    CHECK(output.logout_started.has_value());
    CHECK(*output.logout_started == ((flags & 1) != 0));
    CHECK(output.state == LoginState::Unknown);
  }

  // Logout initiation preserves the account key and active-context byte, but
  // cannot establish that authentication is absent or that logout completed.
  memory = Fixture(1, 1);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CHECK(output.logout_started == true);
  CHECK(output.service_slot0_value && !output.account_lookup_key.empty());
  CHECK(output.kernel_is_login == true);
  CHECK(output.state == LoginState::Unknown);

  // The predicate follows its native getter, not the account key or stage.
  memory = Fixture(0, 0);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CHECK(!output.account_lookup_key.empty());
  CHECK(output.kernel_is_login == false);
  CHECK(output.state == LoginState::Unknown);
  memory = Fixture(1, 0);
  memory.String(kService + 0x48, "");
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CHECK(output.account_lookup_key.empty());
  CHECK(output.kernel_is_login == true);
  CHECK(output.state == LoginState::Unknown);

  memory = Fixture();
  const std::string long_key = "offline-long-account-fixture";
  memory.String(kService + 0x48, long_key, 0x600000000);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CHECK(output.account_lookup_key == long_key && output.state == LoginState::Unknown);
  Limits limits;
  limits.max_string_bytes = 8;
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output, limits) == ReadError::LimitExceeded);
  CheckCleared(output);
  limits.max_string_bytes = 1024;
  limits.max_total_string_bytes = 8;
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output, limits) == ReadError::LimitExceeded);
  CheckCleared(output);

  memory = Fixture();
  memory.U64(kBase + login_layout::kContextPointerRva, 0);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CheckCleared(output);
  memory = Fixture();
  memory.U64(kContext + 0x68, 0);
  // An aliasing shared_ptr can own a control block while its stored pointer is null.
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::None);
  CHECK(output.context_present && !output.service_present && !output.has_service_flags);
  CHECK(output.service_control_address == kControl && output.state == LoginState::Unknown);
  CHECK(output.kernel_is_login == false);
  CHECK(!output.logout_started.has_value());
  CHECK(output.kernel_stage_raw == 3u);

  memory = Fixture();
  auto wrong = kIdentity;
  wrong.sha256[0] = 'f';
  CHECK(ReadLoginObservation(memory, wrong, kBase, output) == ReadError::ProfileMismatch);
  CHECK(memory.reads == 0);
  CheckCleared(output);
  CHECK(ReadLoginObservation(memory, kIdentity, 0, output) == ReadError::InvalidObject);
  CHECK(memory.reads == 0);

  memory = Fixture();
  memory.U64(kContext, kBase + login_layout::kContextVtableRva + 8);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::InvalidObject);
  CheckCleared(output);
  memory = Fixture();
  memory.U64(kService, kBase + login_layout::kServiceVtableRva + 8);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::InvalidObject);
  CheckCleared(output);

  memory = Fixture();
  memory.bytes.erase(kContext + login_layout::kKernelStageOffset + 3);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::Unreadable);
  CheckCleared(output);
  memory = Fixture();
  memory.bytes.erase(kService + 0x39);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::Unreadable);
  CheckCleared(output);
  memory = Fixture();
  memory.bytes[kService + 0x48 + 15] = 'x';
  memory.U64(kService + 0x48 + 16, 15);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::InvalidString);
  CheckCleared(output);
  memory = Snapshot{};
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::Unreadable);
  CheckCleared(output);

  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  CHECK(ReadLoginObservation(memory, kIdentity, maximum, output) == ReadError::AddressOverflow);
  memory = Fixture();
  memory.U64(kBase + login_layout::kContextPointerRva, maximum - 16);
  memory.U64(maximum - 16, kBase + login_layout::kContextVtableRva);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::AddressOverflow);
  CheckCleared(output);
  memory = Fixture();
  memory.U64(kContext + 0x68, maximum - 16);
  memory.U64(maximum - 16, kBase + login_layout::kServiceVtableRva);
  CHECK(ReadLoginObservation(memory, kIdentity, kBase, output) == ReadError::AddressOverflow);
  CheckCleared(output);

  CHECK(std::string(LoginStateName(LoginState::Unknown)) == "unknown");
  std::cout << "weixin4 login snapshot tests passed\n";
}
