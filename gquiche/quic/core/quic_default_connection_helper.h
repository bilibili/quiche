// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_DEFAULT_CONNECTION_HELPER_H_
#define QUICHE_QUIC_CORE_QUIC_DEFAULT_CONNECTION_HELPER_H_

#include "gquiche/quic/core/crypto/quic_random.h"
#include "gquiche/quic/core/quic_connection.h"
#include "gquiche/quic/core/quic_default_clock.h"
#include "gquiche/common/simple_buffer_allocator.h"

namespace quic {

// A default implementation of QuicConnectionHelperInterface.  Thread-safe.
class QUIC_EXPORT_PRIVATE QuicDefaultConnectionHelper
    : public QuicConnectionHelperInterface {
 public:
  static QuicDefaultConnectionHelper* Get() {
    static QuicDefaultConnectionHelper* helper =
        new QuicDefaultConnectionHelper();
    return helper;
  }

  // Creates a helper that uses the default allocator.
  QuicDefaultConnectionHelper() : QuicDefaultConnectionHelper(nullptr) {}
  // If |allocator| is nullptr, the default one is used.
  QuicDefaultConnectionHelper(
      std::unique_ptr<quiche::QuicheBufferAllocator> allocator)
      : allocator_(std::move(allocator)) {}

  QuicDefaultConnectionHelper(const QuicDefaultConnectionHelper&) = delete;
  QuicDefaultConnectionHelper& operator=(const QuicDefaultConnectionHelper&) =
      delete;

  const QuicClock* GetClock() const override { return QuicDefaultClock::Get(); }
  QuicRandom* GetRandomGenerator() override {
    return QuicRandom::GetInstance();
  }
  quiche::QuicheBufferAllocator* GetStreamSendBufferAllocator() override {
    return allocator_ ? allocator_.get() : quiche::SimpleBufferAllocator::Get();
  }

 private:
  std::unique_ptr<quiche::QuicheBufferAllocator> allocator_;
};
}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_DEFAULT_CONNECTION_HELPER_H_
