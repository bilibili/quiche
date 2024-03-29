// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_CONNECTION_ID_GENERATOR_H_
#define QUICHE_QUIC_CORE_CONNECTION_ID_GENERATOR_H_

#include "gquiche/quic/core/quic_connection_id.h"
#include "gquiche/quic/core/quic_versions.h"

namespace quic {

class QUIC_EXPORT_PRIVATE ConnectionIdGeneratorInterface {
  // Interface which is responsible for generating new connection IDs from an
  // existing connection ID.
 public:
  // Generate a new connection ID for a given connection ID. Returns the new
  // connection ID. If it cannot be generated for some reason, returns
  // empty.
  virtual absl::optional<QuicConnectionId> GenerateNextConnectionId(
      const QuicConnectionId& original) = 0;
  // Consider the client-generated server connection ID in the quic handshake
  // and consider replacing it. Returns empty if not replaced.
  virtual absl::optional<QuicConnectionId> MaybeReplaceConnectionId(
      const QuicConnectionId& original, const ParsedQuicVersion& version) = 0;
  virtual ~ConnectionIdGeneratorInterface() = default;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CONNECTION_ID_GENERATOR_H_
