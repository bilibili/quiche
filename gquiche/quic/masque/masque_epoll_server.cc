// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/masque/masque_epoll_server.h"

#include "gquiche/quic/core/quic_default_connection_helper.h"
#include "gquiche/quic/masque/masque_dispatcher.h"
#include "gquiche/quic/masque/masque_utils.h"
#include "gquiche/quic/platform/api/quic_default_proof_providers.h"
#include "gquiche/quic/tools/quic_simple_crypto_server_stream_helper.h"

namespace quic {

MasqueEpollServer::MasqueEpollServer(MasqueMode masque_mode,
                                     MasqueServerBackend* masque_server_backend)
    : QuicServer(CreateDefaultProofSource(), masque_server_backend,
                 MasqueSupportedVersions()),
      masque_mode_(masque_mode),
      masque_server_backend_(masque_server_backend) {}

QuicDispatcher* MasqueEpollServer::CreateQuicDispatcher() {
  return new MasqueDispatcher(
      masque_mode_, &config(), &crypto_config(), version_manager(),
      event_loop(), std::make_unique<QuicDefaultConnectionHelper>(),
      std::make_unique<QuicSimpleCryptoServerStreamHelper>(),
      event_loop()->CreateAlarmFactory(), masque_server_backend_,
      expected_server_connection_id_length(), connection_id_generator());
}

}  // namespace quic
