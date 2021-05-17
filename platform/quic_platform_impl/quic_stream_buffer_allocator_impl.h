#pragma once

// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "gquiche/quic/core/quic_simple_buffer_allocator.h"

namespace quic {

// Implements the interface required by
// https://quiche.googlesource.com/quiche/+/refs/heads/master/quic/platform/api/quic_stream_buffer_allocator.h
// with the default implementation provided by QUICHE.
using QuicStreamBufferAllocatorImpl = SimpleBufferAllocator;

} // namespace quic
