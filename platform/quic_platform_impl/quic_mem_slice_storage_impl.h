#pragma once

// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/platform/api/quic_reference_counted.h"
#include "net/base/io_buffer.h"
#include "platform/quic_platform_impl/quic_iovec_impl.h"
#include "gquiche/quic/core/quic_buffer_allocator.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/platform/api/quic_mem_slice_span.h"
namespace quic {
class QUIC_EXPORT_PRIVATE QuicMemSliceStorageImpl {
 public:
  QuicMemSliceStorageImpl(const struct iovec* iov,
                          int iov_count,
                          QuicBufferAllocator* allocator,
                          const QuicByteCount max_slice_len);
  QuicMemSliceStorageImpl(const QuicMemSliceStorageImpl& other);
  QuicMemSliceStorageImpl& operator=(const QuicMemSliceStorageImpl& other);
  QuicMemSliceStorageImpl(QuicMemSliceStorageImpl&& other);
  QuicMemSliceStorageImpl& operator=(QuicMemSliceStorageImpl&& other);
  ~QuicMemSliceStorageImpl();
  QuicMemSliceSpan ToSpan() {
    return QuicMemSliceSpan(QuicMemSliceSpanImpl(
        buffers_.data(), lengths_.data(), buffers_.size()));
  }
  void Append(QuicMemSliceImpl mem_slice);
 private:
  std::vector<QuicReferenceCountedPointer<net::IOBuffer>> buffers_;
  std::vector<size_t> lengths_;
};
}  // namespace quic
