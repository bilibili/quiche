# Copyright 2019 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
load("//build_config:build_config.bzl", "build_config")
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "strings",
    srcs = [
        "string_piece.cc",
        "string_util.cc",
        "string_util_constants.cc",
        "utf_string_conversion_utils.cc",
        "utf_string_conversions.cc",
    ] + build_config.strings_srcs,
    hdrs = [
        "char_traits.h",
        "string16.h",
        "string_piece.h",
        "string_piece_forward.h",
        "string_util.h",
        "string_util_internal.h",
        "utf_string_conversion_utils.h",
        "utf_string_conversions.h",
    ] + build_config.strings_hdrs,
    copts = build_config.default_copts,
    visibility = ["//visibility:public"],
    deps = [
        "//base",
        "//base/third_party/icu",
        "//build:build_config",
        "//polyfills",
    ],
)
