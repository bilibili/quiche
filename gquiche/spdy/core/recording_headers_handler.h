// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_SPDY_CORE_RECORDING_HEADERS_HANDLER_H_
#define QUICHE_SPDY_CORE_RECORDING_HEADERS_HANDLER_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"
#include "gquiche/common/platform/api/quiche_export.h"
#include "gquiche/spdy/core/http2_header_block.h"
#include "gquiche/spdy/core/spdy_headers_handler_interface.h"

namespace spdy {

// RecordingHeadersHandler copies the headers emitted from the deframer, and
// when needed can forward events to another wrapped handler.
class QUICHE_EXPORT_PRIVATE RecordingHeadersHandler
    : public SpdyHeadersHandlerInterface {
 public:
  explicit RecordingHeadersHandler(
      SpdyHeadersHandlerInterface* wrapped = nullptr);
  RecordingHeadersHandler(const RecordingHeadersHandler&) = delete;
  RecordingHeadersHandler& operator=(const RecordingHeadersHandler&) = delete;

  void OnHeaderBlockStart() override;

  void OnHeader(absl::string_view key, absl::string_view value) override;

  void OnHeaderBlockEnd(size_t uncompressed_header_bytes,
                        size_t compressed_header_bytes) override;

  const Http2HeaderBlock& decoded_block() const { return block_; }
  size_t uncompressed_header_bytes() const {
    return uncompressed_header_bytes_;
  }
  size_t compressed_header_bytes() const { return compressed_header_bytes_; }

 private:
  SpdyHeadersHandlerInterface* wrapped_ = nullptr;
  Http2HeaderBlock block_;
  size_t uncompressed_header_bytes_ = 0;
  size_t compressed_header_bytes_ = 0;
};

}  // namespace spdy

#endif  // QUICHE_SPDY_CORE_RECORDING_HEADERS_HANDLER_H_
