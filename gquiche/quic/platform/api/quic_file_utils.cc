// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/platform/api/quic_file_utils.h"

#include "absl/strings/string_view.h"
#include "platform/quic_platform_impl/quic_file_utils_impl.h"

namespace quic {

// Traverses the directory |dirname| and retuns all of the files
// it contains.
std::vector<std::string> ReadFileContents(const std::string& dirname) {
  return ReadFileContentsImpl(dirname);
}

// Reads the contents of |filename| as a string into |contents|.
void ReadFileContents(absl::string_view filename, std::string* contents) {
  ReadFileContentsImpl(filename, contents);
}

}  // namespace quic
