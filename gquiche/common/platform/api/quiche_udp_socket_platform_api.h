// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_PLATFORM_API_QUICHE_UDP_SOCKET_PLATFORM_API_H_
#define QUICHE_COMMON_PLATFORM_API_QUICHE_UDP_SOCKET_PLATFORM_API_H_

#include "platform/quic_platform_impl/quic_udp_socket_platform_impl.h"

namespace quiche {

const size_t kCmsgSpaceForGooglePacketHeader =
    quic::kCmsgSpaceForGooglePacketHeaderImpl;

inline bool GetGooglePacketHeadersFromControlMessage(
    struct ::cmsghdr* cmsg, char** packet_headers, size_t* packet_headers_len) {
  return quic::GetGooglePacketHeadersFromControlMessageImpl(cmsg, packet_headers,
                                                      packet_headers_len);
}

inline void SetGoogleSocketOptions(int fd) { quic::SetGoogleSocketOptionsImpl(fd); }

}  // namespace quiche

#endif  // QUICHE_COMMON_PLATFORM_API_QUICHE_UDP_SOCKET_PLATFORM_API_H_
