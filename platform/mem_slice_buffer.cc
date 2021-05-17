// NOLINT(namespace-quic)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "platform/mem_slice_buffer.h"

#include <set>

#include "absl/strings/ascii.h"
#include "absl/strings/numbers.h"

namespace quic {

MemSliceBuffer::MemSliceBuffer(char* data, size_t size)
  : owned_(false),
    data_(data),
    size_(size)
{
  if (data_ == nullptr && size_ > 0) {
    owned_ = true;
    data_ = new char[size_];
  }
}

MemSliceBuffer::~MemSliceBuffer()
{
  if (data_) {
    delete [] data_;
  }
  data_ = nullptr;
}

} // namespace quic
