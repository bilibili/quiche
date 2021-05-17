#pragma once

// NOLINT(namespace-quiche)
//
// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include <iostream>

#define HTTP2_BUG_IMPL(x)   std::cout
#define HTTP2_BUG_IF_IMPL

// V2 macros are the same as all the HTTP2_BUG flavor above, but they take a
// bug_id parameter.
#define HTTP2_BUG_V2_IMPL
#define HTTP2_BUG_IF_V2_IMPL

#define FLAGS_http2_always_log_bugs_for_tests_IMPL true
