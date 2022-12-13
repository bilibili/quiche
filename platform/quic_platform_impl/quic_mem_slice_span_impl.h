#pragma once

// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "gquiche/common/platform/api/quiche_reference_counted.h"
#include "net/base/io_buffer.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/common/platform/api/quiche_mem_slice.h"

using namespace quiche;
namespace quic {
// QuicMemSliceSpanImpl wraps a MemSlice span.
class QUIC_EXPORT_PRIVATE QuicMemSliceSpanImpl {
 public:
  QuicMemSliceSpanImpl(const QuicheMemSliceImpl* buffers,
                       size_t num_buffers);                   
  explicit QuicMemSliceSpanImpl(QuicheMemSliceImpl* slice);
  QuicMemSliceSpanImpl(const QuicMemSliceSpanImpl& other);
  QuicMemSliceSpanImpl& operator=(const QuicMemSliceSpanImpl& other);
  QuicMemSliceSpanImpl(QuicMemSliceSpanImpl&& other);
  QuicMemSliceSpanImpl& operator=(QuicMemSliceSpanImpl&& other);
  ~QuicMemSliceSpanImpl();
  quiche::QuicheStringPiece GetData(size_t index) {
    return quiche::QuicheStringPiece(buffers_[index].data(), buffers_[index].length());
  }
  template <typename ConsumeFunction>
  QuicByteCount ConsumeAll(ConsumeFunction consume) {
    size_t saved_length = 0;
    for (size_t i = 0; i < num_buffers_; ++i) {
      if (buffers_[i].length() == 0) {
        // Skip empty buffer.
        continue;
      }
      saved_length += buffers_[i].length();
      consume(QuicheMemSlice(QuicheMemSliceImpl(buffers_[i], buffers_[i].length())));
    }
    return saved_length;
  }
  QuicByteCount total_length();
  size_t NumSlices() { return num_buffers_; }
  bool empty() const { return num_buffers_ == 0; }
 private:
  const QuicheMemSliceImpl* buffers_;
  // Not const so that the move operator can work properly.
  size_t num_buffers_;
};
}  // namespace quic
