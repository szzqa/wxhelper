#include "weixin4/message_backend.h"

#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace wxhelper::weixin4;

namespace {
void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

class Snapshot final : public MemoryReader {
 public:
  std::vector<unsigned char> bytes = std::vector<unsigned char>(8192);
  mutable std::size_t reads = 0;

  bool Read(std::uint64_t address, void* out, std::size_t count) const override {
    ++reads;
    if (address > bytes.size() || count > bytes.size() - address) return false;
    std::memcpy(out, bytes.data() + address, count);
    return true;
  }
  void U64(std::size_t at, std::uint64_t value) {
    for (std::size_t i = 0; i != 8; ++i)
      bytes.at(at + i) = static_cast<unsigned char>(value >> (i * 8));
  }
  void U32(std::size_t at, std::uint32_t value) {
    for (std::size_t i = 0; i != 4; ++i)
      bytes.at(at + i) = static_cast<unsigned char>(value >> (i * 8));
  }
  void String(std::size_t at, const std::string& text, std::size_t heap = 0) {
    Require((text.size() < 16) != (heap != 0), "invalid synthetic string");
    std::memset(bytes.data() + at, 0, 32);
    U64(at + 16, text.size());
    U64(at + 24, heap ? text.size() : 15);
    if (heap) U64(at, heap);
    std::memcpy(bytes.data() + (heap ? heap : at), text.c_str(), text.size() + 1);
  }
};

constexpr std::size_t kClosure = 0x100;
constexpr std::size_t kMessage = 0x300;
constexpr std::size_t kControl = 0x500;
constexpr std::size_t kResult = 0x700;
const BinaryIdentity kIdentity{kVersion, kSha256, kMachine};

Snapshot ValidSnapshot() {
  Snapshot memory;
  memory.U64(kClosure + 8, 0x900);
  memory.String(kClosure + 0x18, "call-123");
  memory.U64(kClosure + 0x38, kMessage);
  memory.U64(kClosure + 0x40, kControl);
  memory.U64(kClosure + 0x48, 0xa00);
  memory.U32(kControl + 8, 2);
  memory.U32(kControl + 12, 1);
  memory.String(kMessage + 0xb0, "fixture-chat-xxxxxxxxxxxxxxxxxxxxxxx", 0x1000);
  return memory;
}

void TaskTests() {
  auto memory = ValidSnapshot();
  TextSendTaskSnapshot value;
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::None,
          "valid task should decode");
  Require(value.call_id == "call-123" &&
              value.chat_id == "fixture-chat-xxxxxxxxxxxxxxxxxxxxxxx",
          "inline and heap strings");
  Require(value.callback_context_address == 0x900 && value.manager_context_address == 0xa00 &&
              value.message.object_address == kMessage && value.message.has_control_block &&
              value.message.strong_count == 2 && value.message.weak_count == 1,
          "observed closure and ownership fields");
  memory.bytes.assign(memory.bytes.size(), 0);
  Require(value.call_id == "call-123" && value.chat_id.size() == 36,
          "decoded strings must own their storage");

  memory = ValidSnapshot();
  memory.U64(kClosure + 0x40, 0);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::None &&
              !value.message.has_control_block && value.message.strong_count == 0,
          "observed null control block branch");

  for (const auto count : {0u, 0x80000000u, 0xffffffffu}) {
    memory = ValidSnapshot();
    memory.U32(kControl + 8, count);
    Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::InvalidObject &&
                value.call_id.empty(), "non-live owner count");
  }
  memory = ValidSnapshot();
  memory.U32(kControl + 12, 0);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::InvalidObject,
          "non-live weak owner count");

  memory = ValidSnapshot();
  memory.U64(kClosure + 0x38, 0);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::InvalidObject,
          "missing message object");
  memory = ValidSnapshot();
  memory.U64(kClosure + 0x48, 0);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::InvalidObject,
          "missing manager");
  memory = ValidSnapshot();
  memory.U64(kClosure + 0x40, memory.bytes.size() - 8);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::Unreadable,
          "truncated owner control block");
  memory = ValidSnapshot();
  memory.U64(kClosure + 0x38, (std::numeric_limits<std::uint64_t>::max)() - 0x80);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::AddressOverflow,
          "overflow in object field address");
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, 0, value) == ReadError::InvalidObject,
          "null task");
  Require(ReadTextSendTaskSnapshot(memory, kIdentity,
                                  (std::numeric_limits<std::uint64_t>::max)(), value) ==
              ReadError::AddressOverflow, "overflow in task field address");

  memory = ValidSnapshot();
  memory.U64(kMessage + 0xb0 + 16, 1000);
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value) == ReadError::InvalidString &&
              value.call_id.empty() && value.message.object_address == 0,
          "failure cannot leak partial decoded fields");
  memory = ValidSnapshot();
  Limits limits;
  limits.max_total_string_bytes = 43;
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value, limits) == ReadError::LimitExceeded,
          "aggregate string budget");
  limits.max_total_string_bytes = 44;
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value, limits) == ReadError::None,
          "exact aggregate string budget");
  limits.max_string_bytes = 35;
  Require(ReadTextSendTaskSnapshot(memory, kIdentity, kClosure, value, limits) == ReadError::LimitExceeded,
          "per-field string budget");

  memory = ValidSnapshot();
  for (int mismatch = 0; mismatch != 3; ++mismatch) {
    auto identity = kIdentity;
    if (mismatch == 0) identity.version = "3.9.5.81";
    if (mismatch == 1) identity.sha256[0] = '0';
    if (mismatch == 2) identity.machine = 0x14c;
    const auto reads = memory.reads;
    Require(ReadTextSendTaskSnapshot(memory, identity, kClosure, value) == ReadError::ProfileMismatch &&
                memory.reads == reads, "identity rejection precedes memory reads");
  }
}

void ResultTests() {
  Snapshot memory;
  TextSendResultSnapshot result;
  Require(ReadTextSendResultSnapshot(memory, kIdentity, kResult, result) == ReadError::None &&
              result.call_succeeded, "two zero status words");
  for (const auto offset : {0u, 4u}) {
    memory.U64(kResult, 0);
    memory.U32(kResult + offset, 1);
    Require(ReadTextSendResultSnapshot(memory, kIdentity, kResult, result) == ReadError::None &&
                !result.call_succeeded, "either nonzero status word reports failure");
  }
  Require(ReadTextSendResultSnapshot(memory, kIdentity, memory.bytes.size() - 4, result) ==
              ReadError::Unreadable && !result.call_succeeded && result.status_word1 == 0,
          "truncated result resets output");
  Require(ReadTextSendResultSnapshot(memory, kIdentity, 0, result) == ReadError::InvalidObject,
          "null result");
  Require(ReadTextSendResultSnapshot(memory, kIdentity,
                                    (std::numeric_limits<std::uint64_t>::max)(), result) ==
              ReadError::AddressOverflow, "result address overflow");
  auto identity = kIdentity;
  identity.version = "4.1.15.14";
  const auto reads = memory.reads;
  Require(ReadTextSendResultSnapshot(memory, identity, kResult, result) == ReadError::ProfileMismatch &&
              memory.reads == reads, "result identity guard");
}

void ReceiveTests() {
  Snapshot memory;
  constexpr std::size_t batch = 0x80;
  constexpr std::size_t record0 = 0x400;
  constexpr std::size_t record1 = record0 + 0x2e8;
  constexpr std::uint64_t large_id = 0xfedcba9876543210ull;
  const std::string content = u8"仅用于离线测试的消息正文";
  memory.U64(batch, record0);
  memory.U64(batch + 8, record1 + 0x2e8);
  memory.U64(batch + 16, record1 + 2 * 0x2e8);
  memory.U32(record0 + 0x0c, 10000);
  memory.U64(record0 + 0x148, large_id);
  // A nearby field is not the server ID; the test must catch an 8-byte mistake.
  memory.U64(record0 + 0x150, 123);
  memory.U32(record0 + 0x164, 0xf1234567);
  memory.U32(record0 + 0x168, 0x80123456);
  memory.U32(record0 + 0x16c, 0x91234567);
  memory.U32(record0 + 0x170, 0xa2345678);
  memory.U32(record0 + 0x174, 0xdeadbeef);  // Not origin_source.
  memory.U32(record0 + 0x178, 0xb3456789);
  memory.String(record0 + 0x18, "alice");
  memory.String(record0 + 0x38, "bob");
  memory.String(record0 + 0x58, "member-a");
  memory.String(record0 + 0x180, content, 0x1800);
  memory.U32(record1 + 0x0c, 1);
  memory.U64(record1 + 0x148, 42);
  memory.U64(record1 + 0x150, large_id);
  memory.String(record1 + 0x18, "long_endpoint_string", 0x1400);
  memory.String(record1 + 0x38, std::string("x\0y", 3));
  memory.String(record1 + 0x58, "long_sender_identifier", 0x1600);
  memory.String(record1 + 0x180, std::string("body\0tail", 9));

  ReceiveRecordSnapshot record;
  Require(ReadReceiveRecordSnapshot(memory, kIdentity, record0, record) == ReadError::None &&
              record.server_id == large_id && record.message_type == 10000 &&
              record.sort_sequence == 123 && record.time_raw == 0xf1234567 &&
              record.sender == "member-a" && record.content == content &&
              record.message_status == 0x80123456 &&
              record.upload_status == 0x91234567 && record.download_status == 0xa2345678 &&
              record.origin_source == 0xb3456789,
          "proven message fields preserve unsigned widths and adjacent offsets");
  std::vector<ReceiveRecordSnapshot> values;
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::None &&
              values.size() == 2 && values[1].server_id == 42 &&
              values[1].from_username == "long_endpoint_string" &&
              values[1].to_username == std::string("x\0y", 3) &&
              values[1].sender == "long_sender_identifier" && values[1].sort_sequence == large_id &&
              values[1].content == std::string("body\0tail", 9),
          "744-byte stride and capacity excluded from live rows");
  memory.bytes[0x1400] = 'z';
  memory.bytes[0x1600] = 'z';
  const auto first_content_byte = memory.bytes[0x1800];
  memory.bytes[0x1800] = 'z';
  Require(values[1].from_username == "long_endpoint_string" &&
              values[1].sender == "long_sender_identifier" && values[0].content == content,
          "receive strings and UTF-8 content are owned");
  memory.bytes[0x1400] = 'l';
  memory.bytes[0x1600] = 'l';
  memory.bytes[0x1800] = first_content_byte;

  Limits limits;
  limits.max_elements = 1;
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values, limits) == ReadError::LimitExceeded &&
              values.empty(), "receive batch element limit");
  limits.max_elements = 100;
  limits.max_total_string_bytes = 61 + content.size() + 9 - 1;
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values, limits) == ReadError::LimitExceeded &&
              values.empty(), "receive total budget shared across records");
  limits.max_total_string_bytes = 61 + content.size() + 9;
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values, limits) == ReadError::None,
          "receive exact budget");

  memory.U64(record1 + 0x58 + 16, 1000);
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::InvalidString &&
              values.empty(), "invalid sender discards the whole batch");
  memory.String(record1 + 0x58, "long_sender_identifier", 0x1600);

  memory.U64(record1 + 0x180 + 16, 16);
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::InvalidString &&
              values.empty(), "invalid content discards the whole batch");
  memory.String(record1 + 0x180, std::string("body\0tail", 9));
  memory.U64(record0 + 0x180, memory.bytes.size() - 1);
  Require(ReadReceiveRecordSnapshot(memory, kIdentity, record0, record) == ReadError::Unreadable &&
              record.server_id == 0 && record.sender.empty() && record.content.empty(),
          "unreadable heap content clears scalar and string outputs");
  memory.String(record0 + 0x180, content, 0x1800);
  limits.max_string_bytes = content.size() - 1;
  Require(ReadReceiveRecordSnapshot(memory, kIdentity, record0, record, limits) == ReadError::LimitExceeded,
          "content obeys the per-field string limit");

  memory.U64(record1 + 0x38 + 16, 16);
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::InvalidString &&
              values.empty(), "second record failure discards prior records");
  memory.String(record1 + 0x38, "xyz");
  memory.U64(batch + 8, record1 + 0x2e8 - 1);
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::InvalidVector,
          "partial record rejected");
  memory.U64(batch + 8, record0 - 1);
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::InvalidVector,
          "reversed batch bounds");
  memory.U64(batch, 0); memory.U64(batch + 8, 0); memory.U64(batch + 16, 0);
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, batch, values) == ReadError::None && values.empty(),
          "empty batch");
  Require(ReadReceiveBatchSnapshot(memory, kIdentity, 0, values) == ReadError::InvalidObject,
          "null batch header");
  Require(ReadReceiveRecordSnapshot(memory, kIdentity, 0, record) == ReadError::InvalidObject &&
              record.server_id == 0, "null record resets output");
  Require(ReadReceiveRecordSnapshot(memory, kIdentity,
                                   (std::numeric_limits<std::uint64_t>::max)() - 8, record) ==
              ReadError::AddressOverflow, "receive field address overflow");
  Require(ReadReceiveRecordSnapshot(memory, kIdentity, memory.bytes.size(), record) == ReadError::Unreadable,
          "unreadable receive record");
  auto identity = kIdentity;
  identity.sha256.clear();
  const auto reads = memory.reads;
  Require(ReadReceiveRecordSnapshot(memory, identity, record0, record) == ReadError::ProfileMismatch &&
              ReadReceiveBatchSnapshot(memory, identity, batch, values) == ReadError::ProfileMismatch &&
              memory.reads == reads, "receive identity guards precede reads");
}
}  // namespace

int main() {
  try {
    TaskTests();
    ResultTests();
    ReceiveTests();
    std::cout << "Weixin 4 offline message task, result and receive snapshots: PASS\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
