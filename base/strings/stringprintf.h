// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_STRINGS_STRINGPRINTF_H_
#define QUICHE_STRINGS_STRINGPRINTF_H_

#include <errno.h>
#include <stdarg.h>   // va_list

#include <string>

#include "googleurl/polyfills/base/base_export.h"
#include "googleurl/base/compiler_specific.h"
#include "googleurl/base/macros.h"
#include "googleurl/build/build_config.h"

#include "base/strings/stringprintf.h"

namespace base {

// Return a C++ string given vprintf-like input.
std::string StringPrintV(const char* format, va_list ap)
    PRINTF_FORMAT(1, 0) WARN_UNUSED_RESULT;

// Store result into a supplied string and return it.
const std::string& SStringPrintf(std::string* dst,
                                             const char* format,
                                             ...) PRINTF_FORMAT(2, 3);

// Append result to a supplied string.
void StringAppendF(std::string* dst, const char* format, ...)
    PRINTF_FORMAT(2, 3);

// Lower-level routine that takes a va_list and appends to a specified
// string.  All other routines are just convenience wrappers around it.
void StringAppendV(std::string* dst, const char* format, va_list ap)
    PRINTF_FORMAT(2, 0);

}  // namespace base

#endif  // QUICHE_STRINGS_STRINGPRINTF_H_
