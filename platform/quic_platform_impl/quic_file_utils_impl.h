#pragma once

// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include <vector>

#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"

namespace quic {

/**
 * Traverses the directory |dirname| and returns all of the files it contains.
 * @param dirname full path without trailing '/'.
 */
std::vector<std::string> ReadFileContentsImpl(const std::string& dirname);

/**
 * Reads the contents of |filename| as a string into |contents|.
 *  @param filename the full path to the file.
 *  @param contents output location of the file content.
 */
void ReadFileContentsImpl(quiche::QuicheStringPiece filename, std::string* contents);

} // namespace quic
