// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "platform/quic_platform_impl/quic_mem_slice_span_impl.h"

using namespace quiche;
namespace quic {
QuicMemSliceSpanImpl::QuicMemSliceSpanImpl(
    const QuicheMemSliceImpl* buffers,
    size_t num_buffers)
    : buffers_(buffers), num_buffers_(num_buffers) {}

QuicMemSliceSpanImpl::QuicMemSliceSpanImpl(QuicheMemSliceImpl* slice)
    : QuicMemSliceSpanImpl(slice, 1) {}
QuicMemSliceSpanImpl::QuicMemSliceSpanImpl(const QuicMemSliceSpanImpl& other) =
    default;
QuicMemSliceSpanImpl& QuicMemSliceSpanImpl::operator=(
    const QuicMemSliceSpanImpl& other) = default;
QuicMemSliceSpanImpl::QuicMemSliceSpanImpl(QuicMemSliceSpanImpl&& other) =
    default;
QuicMemSliceSpanImpl& QuicMemSliceSpanImpl::operator=(
    QuicMemSliceSpanImpl&& other) = default;
QuicMemSliceSpanImpl::~QuicMemSliceSpanImpl() = default;
QuicByteCount QuicMemSliceSpanImpl::total_length() {
  QuicByteCount length = 0;
  for (size_t i = 0; i < num_buffers_; ++i) {
    length += buffers_[i].length();
  }
  return length;
}
}  // namespace quic
