#pragma once

#include "memory_reader.h"
#include "profile.h"

namespace wxhelper::weixin4 {

// Names follow the observed WCDB binding. Integer values are kept as raw bits;
// flag meanings, enum members and the distinction between contact kinds are
// not established. Strings are owned bytes, not pointers into the snapshot.
struct ContactRecord {
  std::uint32_t id = 0;
  std::uint32_t local_type = 0;
  std::uint32_t delete_flag = 0;
  std::uint32_t flag = 0;
  std::uint32_t verify_flag = 0;
  std::uint32_t chat_room_notify = 0;
  std::uint32_t is_in_chat_room = 0;
  std::uint32_t chat_room_type = 0;
  std::string username;
  std::string alias;
  std::string encrypt_username;
  std::string remark;
  std::string remark_quan_pin;
  std::string remark_pin_yin_initial;
  std::string nick_name;
  std::string pin_yin_initial;
  std::string quan_pin;
  std::string big_head_url;
  std::string small_head_url;
  std::string head_img_md5;
  std::string description;
};

struct ContactQuerySnapshot {
  // False represents a disengaged query result, not an empty successful query.
  bool query_succeeded = false;
  std::vector<ContactRecord> contacts;
};

// Decode the stable output of RVA 0x26e8250 (optional map<int, record>).
// The caller must supply a completed, stable result and its original binary
// identity. This does not find the result, invoke the query, or enumerate all
// contacts. Unknown extra_buffer and derived record fields are not decoded.
// On error, output is reset. A disengaged result returns None with success=false.
ReadError ReadContactQuerySnapshot(const MemoryReader&, const BinaryIdentity&,
                                   std::uint64_t result_address,
                                   ContactQuerySnapshot& output,
                                   const Limits& = {});

}  // namespace wxhelper::weixin4
