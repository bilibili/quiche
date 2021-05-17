#ifndef QUICHE_HTTP2_PLATFORM_API_HTTP2_TEST_HELPERS_H_
#define QUICHE_HTTP2_PLATFORM_API_HTTP2_TEST_HELPERS_H_

// Provides VERIFY_* macros, similar to EXPECT_* and ASSERT_*, but they return
// an AssertionResult if the condition is not satisfied.
#include "platform/http2_platform_impl/http2_test_helpers_impl.h"

#include "gquiche/common/platform/api/quiche_test.h"

#define VERIFY_AND_RETURN_SUCCESS(expression) \
  {                                           \
    VERIFY_SUCCESS(expression);               \
    return ::testing::AssertionSuccess();     \
  }

#endif  // QUICHE_HTTP2_PLATFORM_API_HTTP2_TEST_HELPERS_H_
