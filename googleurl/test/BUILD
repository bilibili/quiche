# Copyright 2019 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
load("//build_config:build_config.bzl", "build_config")
load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "basic_test",
    srcs = ["basic_test.cc"],
    copts = build_config.default_copts,
    deps = ["//url"],
)
