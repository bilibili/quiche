// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_HTTP2_PLATFORM_API_HTTP2_STRING_UTILS_H_
#define QUICHE_HTTP2_PLATFORM_API_HTTP2_STRING_UTILS_H_

#include <string>
#include <type_traits>
#include <utility>

#include "absl/strings/string_view.h"
#include "platform/http2_platform_impl/http2_string_utils_impl.h"

namespace http2 {

inline std::string Http2HexDump(absl::string_view data) {
  return Http2HexDumpImpl(data);
}

}  // namespace http2

#endif  // QUICHE_HTTP2_PLATFORM_API_HTTP2_STRING_UTILS_H_
