// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_CRYPTO_QUIC_RANDOM_H_
#define QUICHE_QUIC_CORE_CRYPTO_QUIC_RANDOM_H_

#include <cstddef>
#include <cstdint>

#include "gquiche/quic/platform/api/quic_export.h"

namespace quic {

// The interface for a random number generator.
class QUIC_EXPORT_PRIVATE QuicRandom {
 public:
  virtual ~QuicRandom() {}

  // Returns the default random number generator, which is cryptographically
  // secure and thread-safe.
  static QuicRandom* GetInstance();

  // Generates |len| random bytes in the |data| buffer.
  virtual void RandBytes(void* data, size_t len) = 0;

  // Returns a random number in the range [0, kuint64max].
  virtual uint64_t RandUint64() = 0;

  // Generates |len| random bytes in the |data| buffer. This MUST NOT be used
  // for any application that requires cryptographically-secure randomness.
  virtual void InsecureRandBytes(void* data, size_t len) = 0;

  // Returns a random number in the range [0, kuint64max]. This MUST NOT be used
  // for any application that requires cryptographically-secure randomness.
  virtual uint64_t InsecureRandUint64() = 0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CRYPTO_QUIC_RANDOM_H_
