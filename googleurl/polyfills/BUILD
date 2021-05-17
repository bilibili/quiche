# Copyright 2019 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
load("//build_config:build_config.bzl", "build_config")

cc_library(
    name = "polyfills",
    hdrs = [
        "base/base_export.h",
        "base/check.h",
        "base/check_op.h",
        "base/component_export.h",
        "base/debug/alias.h",
        "base/export_template.h",
        "base/logging.h",
        "base/notreached.h",
        "base/trace_event/memory_usage_estimator.h",
    ],
    copts = build_config.default_copts,
    visibility = ["//visibility:public"],
)
