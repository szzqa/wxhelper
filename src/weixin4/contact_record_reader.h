#pragma once

#include "contact_backend.h"

namespace wxhelper::weixin4::detail {

// Internal field decoder shared by the two observed result containers. The
// enclosing public reader checks provenance, ownership of its output and bounds.
ReadError ReadContactRecord(const MemoryReader&, std::uint64_t address,
                            ContactRecord&, const Limits&,
                            std::size_t& remaining_string_bytes);

}  // namespace wxhelper::weixin4::detail
