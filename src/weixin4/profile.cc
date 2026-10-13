#include "profile.h"

namespace wxhelper::weixin4 {
bool MatchesProfile(const BinaryIdentity& identity) {
  if (identity.version != kVersion || identity.machine != kMachine ||
      identity.sha256.size() != 64) return false;
  for (std::size_t i = 0; i < 64; ++i) {
    char c = identity.sha256[i];
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    if (c != kSha256[i]) return false;
  }
  return true;
}
}  // namespace wxhelper::weixin4
