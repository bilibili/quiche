// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/strings/stringprintf.h"

#include <errno.h>
#include <stddef.h>

#include <vector>

#include "polyfills/base/logging.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"

namespace base {

namespace {

class ScopedClearLastError {
 public:
  ScopedClearLastError() : last_errno_(errno) { errno = 0; }
  ~ScopedClearLastError() { errno = last_errno_; }

 private:
  const int last_errno_;

  DISALLOW_COPY_AND_ASSIGN(ScopedClearLastError);
};

// Overloaded wrappers around vsnprintf and vswprintf. The buf_size parameter
// is the size of the buffer. These return the number of characters in the
// formatted string excluding the NUL terminator. If the buffer is not
// large enough to accommodate the formatted string without truncation, they
// return the number of characters that would be in the fully-formatted string
// (vsnprintf, and vswprintf on Windows), or -1 (vswprintf on POSIX platforms).
inline int vsnprintfT(char* buffer,
                      size_t buf_size,
                      const char* format,
                      va_list argptr) {
  return gurl_base::vsnprintf(buffer, buf_size, format, argptr);
}

// Templatized backend for StringPrintF/StringAppendF. This does not finalize
// the va_list, the caller is expected to do that.
template <class CharT>
static void StringAppendVT(std::basic_string<CharT>* dst,
                           const CharT* format,
                           va_list ap) {
  // First try with a small fixed size buffer.
  // This buffer size should be kept in sync with StringUtilTest.GrowBoundary
  // and StringUtilTest.StringPrintfBounds.
  CharT stack_buf[1024];

  va_list ap_copy;
  va_copy(ap_copy, ap);

  ScopedClearLastError last_error;
  int result = vsnprintfT(stack_buf, gurl_base::size(stack_buf), format, ap_copy);
  va_end(ap_copy);

  if (result >= 0 && result < static_cast<int>(gurl_base::size(stack_buf))) {
    // It fit.
    dst->append(stack_buf, result);
    return;
  }

  // Repeatedly increase buffer size until it fits.
  int mem_length = gurl_base::size(stack_buf);
  while (true) {
    if (result < 0) {
      if (errno != 0 && errno != EOVERFLOW)
        return;
      // Try doubling the buffer size.
      mem_length *= 2;
    } else {
      // We need exactly "result + 1" characters.
      mem_length = result + 1;
    }

    if (mem_length > 32 * 1024 * 1024) {
      // That should be plenty, don't try anything larger.  This protects
      // against huge allocations when using vsnprintfT implementations that
      // return -1 for reasons other than overflow without setting errno.
      GURL_DLOG(WARNING) << "Unable to printf the requested string due to size.";
      return;
    }

    std::vector<CharT> mem_buf(mem_length);

    // NOTE: You can only use a va_list once.  Since we're in a while loop, we
    // need to make a new copy each time so we don't use up the original.
    va_copy(ap_copy, ap);
    result = vsnprintfT(&mem_buf[0], mem_length, format, ap_copy);
    va_end(ap_copy);

    if ((result >= 0) && (result < mem_length)) {
      // It fit.
      dst->append(&mem_buf[0], result);
      return;
    }
  }
}

}  // namespace

std::string StringPrintV(const char* format, va_list ap) {
  std::string result;
  StringAppendV(&result, format, ap);
  return result;
}

const std::string& SStringPrintf(std::string* dst, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  dst->clear();
  StringAppendV(dst, format, ap);
  va_end(ap);
  return *dst;
}

void StringAppendF(std::string* dst, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  StringAppendV(dst, format, ap);
  va_end(ap);
}

void StringAppendV(std::string* dst, const char* format, va_list ap) {
  StringAppendVT(dst, format, ap);
}

}  // namespace base
