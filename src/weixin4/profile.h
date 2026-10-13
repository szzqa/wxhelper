#pragma once

#include <cstdint>
#include <string>

namespace wxhelper::weixin4 {

inline constexpr char kVersion[] = "4.1.15.13";
inline constexpr char kSha256[] =
    "10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5";
inline constexpr std::uint16_t kMachine = 0x8664;

// Provenance supplied by the snapshot owner, not a runtime compatibility claim.
// The analysis-only PE copy has a different hash and must not match this profile.
struct BinaryIdentity {
  std::string version;
  std::string sha256;
  std::uint16_t machine = 0;
};

bool MatchesProfile(const BinaryIdentity&);

// This library has no live process reader, native calls, or injection adapter.
inline constexpr bool kRuntimeSupported = false;

}  // namespace wxhelper::weixin4
