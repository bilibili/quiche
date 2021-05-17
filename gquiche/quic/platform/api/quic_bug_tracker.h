// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_PLATFORM_API_QUIC_BUG_TRACKER_H_
#define QUICHE_QUIC_PLATFORM_API_QUIC_BUG_TRACKER_H_

#include "platform/quic_platform_impl/quic_bug_tracker_impl.h"

#define QUIC_BUG(x)           QUICHE_BUG_IMPL(x)
#define QUIC_BUG_IF(x,y)      QUICHE_BUG_IF_IMPL(x,y)
#define QUIC_PEER_BUG(x)      QUICHE_PEER_BUG_IMPL(x)
#define QUIC_PEER_BUG_IF(x,y) QUICHE_PEER_BUG_IF_IMPL(x,y)

#endif  // QUICHE_QUIC_PLATFORM_API_QUIC_BUG_TRACKER_H_
