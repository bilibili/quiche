#pragma once

// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/platform/api/quic_reference_counted.h"
#include "net/base/io_buffer.h"
#include "gquiche/quic/core/quic_buffer_allocator.h"

namespace quic {
// QuicMemSliceImpl TODO(fayang)
class QuicMemSliceImpl {
 public:
  // Constructs an empty QuicMemSliceImpl.
  QuicMemSliceImpl();

  // Constructs a QuicMemSliceImp by let |allocator| allocate a data buffer of
  // |length|.
  QuicMemSliceImpl(QuicUniqueBufferPtr buffer, size_t length);
  QuicMemSliceImpl(std::unique_ptr<char[]> buffer, size_t length);
  QuicMemSliceImpl(QuicReferenceCountedPointer<net::IOBuffer> io_buffer, size_t length);
  QuicMemSliceImpl(const QuicMemSliceImpl& other) = delete;
  QuicMemSliceImpl& operator=(const QuicMemSliceImpl& other) = delete;
  // Move constructors. |other| will not hold a reference to the data buffer
  // after this call completes.
  QuicMemSliceImpl(QuicMemSliceImpl&& other);
  QuicMemSliceImpl& operator=(QuicMemSliceImpl&& other);
  ~QuicMemSliceImpl();

  // Release the underlying reference. Further access the memory will result in
  // undefined behavior.
  void Reset();
  // Returns a char pointer to underlying data buffer.

  const char* data() const;
  // Returns the length of underlying data buffer.
  size_t length() const { return length_; }
  bool empty() const { return length_ == 0; }
  QuicReferenceCountedPointer<net::IOBuffer>* impl() { return &io_buffer_; }
  size_t* impl_length() { return &length_; }

 private:
  QuicReferenceCountedPointer<net::IOBuffer> io_buffer_;
  // Length of io_buffer_.
  size_t length_ = 0;
};

}  // namespace quic
