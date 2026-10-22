#include "weixin4/send_cancel_contract.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <string>

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
};
constexpr std::uint64_t kBase = 0x180000000;
constexpr std::uint64_t kContext = 0x300000000;
constexpr std::uint64_t kControl = 0x400000000;
constexpr std::uint64_t kCgiControl = 0x500000000;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

void Job(Snapshot& memory, std::uint64_t pair, std::uint64_t control) {
  const auto object = control + 0x10;
  memory.U64(pair, object);
  memory.U64(pair + 8, control);
  memory.U64(control, kBase + send_cancel_layout::kJobControlVtableRva);
  memory.U32(control + 8, 1);
  memory.U32(control + 12, 1);
  memory.U64(object, kBase + send_cancel_layout::kJobVtableRva);
  memory.bytes[object + send_cancel_layout::kStartedOffset] = 1;
  memory.bytes[object + send_cancel_layout::kActiveOffset] = 0;
  memory.bytes[object + send_cancel_layout::kCancelRequestedOffset] = 1;
}

Snapshot Fixture(bool send = true, bool cgi = true) {
  Snapshot memory;
  memory.U64(kContext, kBase + send_cancel_layout::kContextVtableRva);
  memory.U32(kContext + send_cancel_layout::kStageOffset, 0xF123ABCD);
  for (auto offset : {send_cancel_layout::kSendJobOffset,
                      send_cancel_layout::kSendCgiJobOffset}) {
    memory.U64(kContext + offset, 0);
    memory.U64(kContext + offset + 8, 0);
  }
  if (send) Job(memory, kContext + send_cancel_layout::kSendJobOffset, kControl);
  if (cgi) Job(memory, kContext + send_cancel_layout::kSendCgiJobOffset, kCgiControl);
  return memory;
}

void CheckJobCleared(const SendJobCancelObservation& value) {
  CHECK(!value.present && !value.object_address && !value.control_address);
  CHECK(!value.started && !value.active && !value.cancel_requested);
  CHECK(!value.started_raw && !value.active_raw && !value.cancel_requested_raw);
}
void CheckCleared(const SendCancelContextSnapshot& value) {
  CHECK(!value.context_address && !value.stage_raw);
  CHECK(value.dispatch == SendCancelDispatch::Unknown);
  CheckJobCleared(value.send_job);
  CheckJobCleared(value.send_cgi_job);
}
}  // namespace

int main() {
  SendCancelContextSnapshot output;
  for (bool send : {false, true}) for (bool cgi : {false, true}) {
    auto memory = Fixture(send, cgi);
    CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
          == ReadError::None);
    CHECK(output.context_address == kContext && output.stage_raw == 0xF123ABCD);
    CHECK(output.send_job.present == send && output.send_cgi_job.present == cgi);
    CHECK(output.dispatch == (send || cgi ? SendCancelDispatch::JobCancelAndJoin
                                         : SendCancelDispatch::PrepareShowLookup));
    CHECK(std::string(SendCancelDispatchName(output.dispatch)) ==
          (send || cgi ? "job_cancel_and_join" : "prepare_show_lookup"));
  }

  auto memory = Fixture();
  for (auto raw : {0u, 1u, 2u, 255u}) {
    const auto object = kControl + 0x10;
    memory.bytes[object + send_cancel_layout::kStartedOffset] = static_cast<unsigned char>(raw);
    memory.bytes[object + send_cancel_layout::kActiveOffset] = static_cast<unsigned char>(255 - raw);
    memory.bytes[object + send_cancel_layout::kCancelRequestedOffset] = static_cast<unsigned char>(raw);
    CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
          == ReadError::None);
    const auto& job = output.send_job;
    CHECK(job.object_address == object && job.control_address == kControl);
    CHECK(job.started_raw == raw && job.active_raw == 255 - raw);
    CHECK(job.cancel_requested_raw == raw);
    CHECK(job.started == ((raw & 1) != 0));
    CHECK(job.active == (((255 - raw) & 1) != 0));
    CHECK(job.cancel_requested == ((raw & 1) != 0));
    CHECK(output.send_cgi_job.started && !output.send_cgi_job.active);
    CHECK(output.send_cgi_job.cancel_requested);
  }

  // Cancellation can be requested before start. These are independent fields,
  // and neither this combination nor any stage means cancellation completed.
  memory = Fixture();
  memory.bytes[kControl + 0x10 + send_cancel_layout::kStartedOffset] = 0;
  for (auto stage : {0u, 1u, 3u, 6u, 7u, 9u, 10u, 0xFFFFFFFFu}) {
    memory.U32(kContext + send_cancel_layout::kStageOffset, stage);
    CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
          == ReadError::None);
    CHECK(output.stage_raw == stage);
    CHECK(!output.send_job.started && output.send_job.cancel_requested);
  }

  // A stored null object selects the no-job branch even with an opaque owner.
  memory = Fixture(false, false);
  memory.U64(kContext + send_cancel_layout::kSendJobOffset + 8, 0xDEADBEEF);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
        == ReadError::None);
  CHECK(!output.send_job.present && output.send_job.control_address == 0xDEADBEEF);
  CHECK(output.dispatch == SendCancelDispatch::PrepareShowLookup);

  const auto valid = Fixture();
  // Each mapped byte is required, including the second job's last flag. No
  // pointer-chasing beyond the supported object/control identities is needed.
  for (const auto& field : valid.bytes) {
    memory = valid;
    memory.bytes.erase(field.first);
    CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
          == ReadError::Unreadable);
    CheckCleared(output);
  }
  for (const auto address : {kContext, kControl, kControl + 0x10, kCgiControl,
                             kCgiControl + 0x10}) {
    memory = valid;
    memory.U64(address, 0);
    CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
          == ReadError::InvalidObject);
    CheckCleared(output);
  }
  for (const auto count : {0u, 0x80000000u, 0xFFFFFFFFu}) {
    for (auto offset : {8u, 12u}) {
      memory = valid;
      memory.U32(kCgiControl + offset, count);
      CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
            == ReadError::InvalidObject);
      CheckCleared(output);
    }
  }
  memory = valid;
  memory.U64(kContext + send_cancel_layout::kSendJobOffset + 8, 0);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
        == ReadError::InvalidObject);
  CheckCleared(output);
  memory = valid;
  memory.U64(kContext + send_cancel_layout::kSendJobOffset, kControl + 0x18);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
        == ReadError::InvalidObject);
  CheckCleared(output);

  memory = valid;
  auto identity = kIdentity;
  identity.sha256[0] = 'f';
  CHECK(ReadSendCancelContextSnapshot(memory, identity, kBase, kContext, output)
        == ReadError::ProfileMismatch);
  CHECK(memory.reads == 0);
  CheckCleared(output);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, 0, kContext, output)
        == ReadError::InvalidObject);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, 0, output)
        == ReadError::InvalidObject);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext + 1, output)
        == ReadError::InvalidObject);
  CHECK(memory.reads == 0);
  CheckCleared(output);

  const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, maximum, kContext, output)
        == ReadError::AddressOverflow);
  memory = {};
  memory.U64(maximum - 7, kBase + send_cancel_layout::kContextVtableRva);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, maximum - 7, output)
        == ReadError::AddressOverflow);
  CheckCleared(output);
  memory = valid;
  memory.U64(kContext + send_cancel_layout::kSendJobOffset + 8, maximum - 7);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
        == ReadError::AddressOverflow);
  CheckCleared(output);
  memory = valid;
  // Pair identity fits, but the selected job flag address overflows.
  Job(memory, kContext + send_cancel_layout::kSendJobOffset, maximum - 31);
  CHECK(ReadSendCancelContextSnapshot(memory, kIdentity, kBase, kContext, output)
        == ReadError::AddressOverflow);
  CheckCleared(output);
  CHECK(std::string(SendCancelDispatchName(SendCancelDispatch::Unknown)) == "unknown");
  std::cout << "weixin4 send cancellation snapshot tests passed\n";
}
