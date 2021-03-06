// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_PLATFORM_API_QUIC_FILE_UTILS_H_
#define QUICHE_QUIC_PLATFORM_API_QUIC_FILE_UTILS_H_

#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "gquiche/quic/platform/api/quic_export.h"

namespace quic {

// Traverses the directory |dirname| and returns all of the files it contains.
QUIC_EXPORT_PRIVATE std::vector<std::string> ReadFileContents(
    const std::string& dirname);

// Reads the contents of |filename| as a string into |contents|.
QUIC_EXPORT_PRIVATE void ReadFileContents(absl::string_view filename,
                                          std::string* contents);

}  // namespace quic

#endif  // QUICHE_QUIC_PLATFORM_API_QUIC_FILE_UTILS_H_
