// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_PLATFORM_API_QUIC_EXPECT_BUG_H_
#define QUICHE_QUIC_PLATFORM_API_QUIC_EXPECT_BUG_H_

#include "platform/quic_platform_impl/quic_expect_bug_impl.h"

#define EXPECT_QUIC_BUG EXPECT_QUIC_BUG_IMPL
#define EXPECT_QUIC_PEER_BUG(statement, regex) \
  EXPECT_QUIC_PEER_BUG_IMPL(statement, regex)

#endif  // QUICHE_QUIC_PLATFORM_API_QUIC_EXPECT_BUG_H_
