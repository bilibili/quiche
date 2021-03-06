// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_PLATFORM_API_QUIC_FLAG_UTILS_H_
#define QUICHE_QUIC_PLATFORM_API_QUIC_FLAG_UTILS_H_

#include "platform/quiche_platform_impl/quiche_flag_utils_impl.h"

#define QUIC_RELOADABLE_FLAG_COUNT QUIC_RELOADABLE_FLAG_COUNT_IMPL
#define QUIC_RELOADABLE_FLAG_COUNT_N QUIC_RELOADABLE_FLAG_COUNT_N_IMPL

#define QUIC_RESTART_FLAG_COUNT QUIC_RESTART_FLAG_COUNT_IMPL
#define QUIC_RESTART_FLAG_COUNT_N QUIC_RESTART_FLAG_COUNT_N_IMPL

#define QUIC_CODE_COUNT QUIC_CODE_COUNT_IMPL
#define QUIC_CODE_COUNT_N QUIC_CODE_COUNT_N_IMPL

#endif  // QUICHE_QUIC_PLATFORM_API_QUIC_FLAG_UTILS_H_
