// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "platform/quic_platform_impl/quic_file_utils_impl.h"

#include "absl/strings/str_cat.h"

namespace quic {
namespace {

void depthFirstTraverseDirectory(const std::string& dirname, std::vector<std::string>& files) {
}

} // namespace

// Traverses the directory |dirname| and returns all of the files it contains.
std::vector<std::string> ReadFileContentsImpl(const std::string& dirname) {
  std::vector<std::string> files;
  depthFirstTraverseDirectory(dirname, files);
  return files;
}

// Reads the contents of |filename| as a string into |contents|.
void ReadFileContentsImpl(quiche::QuicheStringPiece filename, std::string* contents) {
}

} // namespace quic
