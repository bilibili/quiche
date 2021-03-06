// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_EPOLL_SERVER_H_
#define QUICHE_QUIC_MASQUE_MASQUE_EPOLL_SERVER_H_

#include "gquiche/quic/masque/masque_server_backend.h"
#include "gquiche/quic/masque/masque_utils.h"
#include "gquiche/quic/platform/api/quic_export.h"
#include "gquiche/quic/tools/quic_server.h"

namespace quic {

// QUIC server that implements MASQUE.
class QUIC_NO_EXPORT MasqueEpollServer : public QuicServer {
 public:
  explicit MasqueEpollServer(MasqueMode masque_mode,
                             MasqueServerBackend* masque_server_backend);

  // Disallow copy and assign.
  MasqueEpollServer(const MasqueEpollServer&) = delete;
  MasqueEpollServer& operator=(const MasqueEpollServer&) = delete;

  // From QuicServer.
  QuicDispatcher* CreateQuicDispatcher() override;

 private:
  MasqueMode masque_mode_;
  MasqueServerBackend* masque_server_backend_;  // Unowned.
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_EPOLL_SERVER_H_
