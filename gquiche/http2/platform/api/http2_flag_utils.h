// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_HTTP2_PLATFORM_API_HTTP2_FLAG_UTILS_H_
#define QUICHE_HTTP2_PLATFORM_API_HTTP2_FLAG_UTILS_H_

#include "platform/http2_platform_impl/http2_flag_utils_impl.h"

#define HTTP2_RELOADABLE_FLAG_COUNT HTTP2_RELOADABLE_FLAG_COUNT_IMPL
#define HTTP2_RELOADABLE_FLAG_COUNT_N(x,y,z) HTTP2_RELOADABLE_FLAG_COUNT_N_IMPL(x,y,z)

#define HTTP2_RESTART_FLAG_COUNT HTTP2_RESTART_FLAG_COUNT_IMPL
#define HTTP2_RESTART_FLAG_COUNT_N HTTP2_RESTART_FLAG_COUNT_N_IMPL

#define HTTP2_CODE_COUNT HTTP2_CODE_COUNT_IMPL
#define HTTP2_CODE_COUNT_N(x,y,z) HTTP2_CODE_COUNT_N_IMPL(x,y,z)

#endif  // QUICHE_HTTP2_PLATFORM_API_HTTP2_FLAG_UTILS_H_
