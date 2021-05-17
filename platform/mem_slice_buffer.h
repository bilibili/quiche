#pragma once

// NOLINT(namespace-quic)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include <cstddef>
#include <iostream>
#include <memory>
#include <vector>

namespace quic {

class MemSliceBuffer {
public:
  MemSliceBuffer(char* data, size_t size);

  char* data() const { return data_; }

  size_t size() const { return size_; }

  virtual ~MemSliceBuffer();

private:
  bool   owned_;
  char*  data_;
  size_t size_;

};

using MemSliceBufferSharedPtr = std::shared_ptr<MemSliceBuffer>;
using MemSliceBuffersVec = std::vector<MemSliceBufferSharedPtr>;

} // namespace quic
