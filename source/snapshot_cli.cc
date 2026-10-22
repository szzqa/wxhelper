#include "weixin4/contact_backend.h"
#include "weixin4/login_backend.h"
#include "weixin4/message_backend.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using nlohmann::json;
using namespace wxhelper::weixin4;

std::uint64_t Address(const json& input) {
  if (input.is_number_unsigned()) return input.get<std::uint64_t>();
  if (!input.is_string()) throw std::runtime_error("address must be an unsigned integer or hexadecimal string");
  const auto value = input.get<std::string>();
  const auto prefix = value.compare(0, 2, "0x") == 0 ? 2U : 0U;
  std::uint64_t result = 0;
  const auto parsed = std::from_chars(value.data() + prefix, value.data() + value.size(), result, prefix ? 16 : 10);
  if (parsed.ec != std::errc() || parsed.ptr != value.data() + value.size())
    throw std::runtime_error("invalid address");
  return result;
}

unsigned Nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  throw std::runtime_error("invalid segment hex data");
}

class Snapshot final : public MemoryReader {
  struct Segment { std::uint64_t address; std::vector<unsigned char> bytes; };
  std::vector<Segment> segments_;
 public:
  explicit Snapshot(const json& segments) {
    if (!segments.is_array() || segments.size() > 10000)
      throw std::runtime_error("invalid segment list");
    std::size_t total = 0;
    for (const auto& item : segments) {
      Segment segment{Address(item.at("address")), {}};
      const auto hex = item.at("hex").get<std::string>();
      if (hex.empty() || hex.size() % 2 || hex.size() / 2 > 32 * 1024 * 1024 - total)
        throw std::runtime_error("empty, unaligned, or oversized segment");
      std::uint64_t last = 0;
      if (!CheckedAdd(segment.address, hex.size() / 2, last))
        throw std::runtime_error("segment address overflow");
      segment.bytes.reserve(hex.size() / 2);
      for (std::size_t i = 0; i < hex.size(); i += 2)
        segment.bytes.push_back(static_cast<unsigned char>((Nibble(hex[i]) << 4) | Nibble(hex[i + 1])));
      total += segment.bytes.size();
      segments_.push_back(std::move(segment));
    }
    std::sort(segments_.begin(), segments_.end(), [](const auto& a, const auto& b) { return a.address < b.address; });
    for (std::size_t i = 1; i < segments_.size(); ++i)
      if (segments_[i - 1].address + segments_[i - 1].bytes.size() > segments_[i].address)
        throw std::runtime_error("overlapping segments");
  }
  bool Read(std::uint64_t address, void* out, std::size_t size) const override {
    auto it = std::upper_bound(segments_.begin(), segments_.end(), address,
        [](auto at, const auto& segment) { return at < segment.address; });
    if (it == segments_.begin()) return false;
    --it;
    const auto offset = address - it->address;
    if (offset > it->bytes.size() || size > it->bytes.size() - offset) return false;
    std::memcpy(out, it->bytes.data() + offset, size);
    return true;
  }
};

json Contact(const ContactRecord& c) {
  return {{"id", c.id}, {"username", c.username}, {"alias", c.alias},
          {"encrypt_username", c.encrypt_username}, {"remark", c.remark},
          {"nick_name", c.nick_name}, {"remark_quan_pin", c.remark_quan_pin},
          {"remark_pin_yin_initial", c.remark_pin_yin_initial},
          {"pin_yin_initial", c.pin_yin_initial}, {"quan_pin", c.quan_pin},
          {"big_head_url", c.big_head_url}, {"small_head_url", c.small_head_url},
          {"head_img_md5", c.head_img_md5}, {"description", c.description},
          {"local_type", c.local_type}, {"delete_flag", c.delete_flag},
          {"flag", c.flag}, {"verify_flag", c.verify_flag},
          {"chat_room_notify", c.chat_room_notify}, {"is_in_chat_room", c.is_in_chat_room},
          {"chat_room_type", c.chat_room_type}};
}

json Decode(const Snapshot& memory, const BinaryIdentity& identity, const json& request) {
  const auto feature = request.at("feature").get<std::string>();
  const auto address = Address(request.at("address"));
  ReadError status = ReadError::UnsupportedLayout;
  json data;
  if (feature == "login") {
    LoginObservation value;
    status = ReadLoginObservation(memory, identity, address, value);
    data = {{"state", LoginStateName(value.state)}, {"context_present", value.context_present},
            {"service_present", value.service_present}, {"context_address", value.context_address},
            {"service_address", value.service_address}, {"has_service_flags", value.has_service_flags},
            {"service_flag38", value.service_flag38}, {"service_flag39", value.service_flag39},
            {"service_slot0_value", value.service_slot0_value}, {"account_lookup_key", value.account_lookup_key}};
    data["logout_started"] = value.logout_started.has_value() ? json(*value.logout_started) : json(nullptr);
  } else if (feature == "contacts") {
    ContactQuerySnapshot value;
    status = ReadContactQuerySnapshot(memory, identity, address, value);
    data = {{"query_succeeded", value.query_succeeded}, {"contacts", json::array()}, {"all_contacts_verified", false}};
    for (const auto& c : value.contacts) data["contacts"].push_back(Contact(c));
  } else if (feature == "send_task") {
    TextSendTaskSnapshot value;
    status = ReadTextSendTaskSnapshot(memory, identity, address, value);
    data = {{"call_id", value.call_id}, {"chat_id", value.chat_id},
            {"manager_context_address", value.manager_context_address},
            {"callback_context_address", value.callback_context_address},
            {"message_object_address", value.message.object_address},
            {"message_control_address", value.message.control_block_address},
            {"strong_count", value.message.strong_count}, {"weak_count", value.message.weak_count},
            {"has_control_block", value.message.has_control_block}};
  } else if (feature == "send_result") {
    TextSendResultSnapshot value;
    status = ReadTextSendResultSnapshot(memory, identity, address, value);
    data = {{"status_word0", value.status_word0}, {"status_word1", value.status_word1},
            {"call_succeeded", value.call_succeeded}, {"delivery_verified", false}};
  } else if (feature == "receive_batch") {
    std::vector<ReceiveRecordSnapshot> values;
    status = ReadReceiveBatchSnapshot(memory, identity, address, values);
    data = {{"messages", json::array()}, {"content_decoded", true},
            {"content_semantics", "raw_native_string"}, {"direction_verified", false}};
    for (const auto& value : values)
      data["messages"].push_back({{"server_id", std::to_string(value.server_id)},
          {"message_type", value.message_type}, {"sort_sequence", std::to_string(value.sort_sequence)},
          {"time_raw", value.time_raw}, {"message_status", value.message_status},
          {"upload_status", value.upload_status}, {"download_status", value.download_status},
          {"origin_source", value.origin_source}, {"sender", value.sender},
          {"from_username", value.from_username}, {"to_username", value.to_username},
          {"content", value.content}});
  }
  json result = {{"feature", feature}, {"error", ReadErrorName(status)}};
  if (status == ReadError::None) result["data"] = std::move(data);
  return result;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2 || std::strcmp(argv[1], "--help") == 0) {
    std::cout << "Usage: weixin4_snapshot_cli <snapshot.json>\n"
              << "Offline only. No process access, injection, native calls, or message sending.\n";
    return argc == 2 ? 0 : 1;
  }
  try {
    const std::filesystem::path path(argv[1]);
    if (std::filesystem::file_size(path) > 80 * 1024 * 1024)
      throw std::runtime_error("snapshot JSON exceeds 80 MiB");
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("cannot open snapshot JSON");
    const auto input = json::parse(stream, [](int depth, json::parse_event_t, json&) {
      if (depth > 64) throw std::runtime_error("snapshot JSON nesting exceeds 64");
      return true;
    });
    if (input.at("format") != "weixin4_snapshot_v1") throw std::runtime_error("unknown snapshot format");
    const auto& source = input.at("identity");
    const auto machine = Address(source.at("machine"));
    if (machine > 0xffff) throw std::runtime_error("invalid machine value");
    BinaryIdentity identity{source.at("version").get<std::string>(), source.at("sha256").get<std::string>(), static_cast<std::uint16_t>(machine)};
    const auto& requests = input.at("requests");
    if (!requests.is_array() || requests.empty() || requests.size() > 32)
      throw std::runtime_error("expected 1 to 32 requests");
    const Snapshot memory(input.at("segments"));
    json output = {{"mode", "offline_snapshot"}, {"runtime_supported", false},
                   {"snapshot_provenance_verified", false}, {"results", json::array()}};
    bool failed = false;
    for (const auto& request : requests) {
      auto result = Decode(memory, identity, request);
      failed |= result["error"] != "ok";
      output["results"].push_back(std::move(result));
    }
    std::cout << output.dump(2, ' ', false, json::error_handler_t::replace) << '\n';
    return failed ? 2 : 0;
  } catch (const std::exception& error) {
    std::cerr << json({{"error", "invalid_snapshot"}, {"detail", error.what()}}).dump() << '\n';
    return 1;
  }
}
