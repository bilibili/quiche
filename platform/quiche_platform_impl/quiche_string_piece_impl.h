#pragma once

#include "platform/quiche_platform_impl/quiche_logging_impl.h"

#include "absl/hash/hash.h"
#include "absl/strings/string_view.h"

// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

namespace quiche {

using QuicheStringPieceImpl = absl::string_view;

using QuicheStringPieceHashImpl = absl::Hash<QuicheStringPieceImpl>;

inline size_t QuicheHashStringPairImpl(QuicheStringPieceImpl a, QuicheStringPieceImpl b) {
  return absl::Hash<QuicheStringPieceImpl>()(a) ^ absl::Hash<QuicheStringPieceImpl>()(b);
}

} // namespace quiche
