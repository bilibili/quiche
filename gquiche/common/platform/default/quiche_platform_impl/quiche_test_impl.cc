// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "platform/quiche_platform_impl/quiche_test_impl.h"

#include "gquiche/common/platform/api/quiche_flags.h"

QuicheFlagSaverImpl::QuicheFlagSaverImpl() {
#define QUIC_FLAG(flag, value) saved_##flag##_ = FLAGS_##flag;
#include "gquiche/quic/core/quic_flags_list.h"
#undef QUIC_FLAG
#define QUIC_PROTOCOL_FLAG(type, flag, ...) saved_##flag##_ = FLAGS_##flag;
#include "gquiche/quic/core/quic_protocol_flags_list.h"
#undef QUIC_PROTOCOL_FLAG
}

QuicheFlagSaverImpl::~QuicheFlagSaverImpl() {
#define QUIC_FLAG(flag, value) FLAGS_##flag = saved_##flag##_;
#include "gquiche/quic/core/quic_flags_list.h"  // NOLINT
#undef QUIC_FLAG
#define QUIC_PROTOCOL_FLAG(type, flag, ...) FLAGS_##flag = saved_##flag##_;
#include "gquiche/quic/core/quic_protocol_flags_list.h"  // NOLINT
#undef QUIC_PROTOCOL_FLAG
}
