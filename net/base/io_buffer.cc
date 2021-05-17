//copy from chromium/net/base/io_buffer.cc

#include "net/base/io_buffer.h"

#include "gquiche/common/platform/api/quiche_logging.h"

using namespace quic;

namespace net {

// TODO(eroman): IOBuffer is being converted to require buffer sizes and offsets
// be specified as "size_t" rather than "int" (crbug.com/488553). To facilitate
// this move (since LOTS of code needs to be updated), both "size_t" and "int
// are being accepted. When using "size_t" this function ensures that it can be
// safely converted to an "int" without truncation.

IOBuffer::IOBuffer() : data_(nullptr) {}

IOBuffer::IOBuffer(size_t buffer_size) {
  data_ = new char[buffer_size];
}

IOBuffer::IOBuffer(char* data)
    : data_(data) {
}

IOBuffer::~IOBuffer() {
  delete[] data_;
  data_ = nullptr;
}

IOBufferWithSize::IOBufferWithSize(size_t size) : IOBuffer(size), size_(size) {
  // Note: Size check is done in superclass' constructor.
}

IOBufferWithSize::IOBufferWithSize(char* data, size_t size)
    : IOBuffer(data), size_(size) {
}

IOBufferWithSize::~IOBufferWithSize() = default;


DrainableIOBuffer::DrainableIOBuffer(
    QuicReferenceCountedPointer<IOBuffer> base, int size)
    : IOBuffer(base->data()), base_(std::move(base)), size_(size), used_(0) {
}

DrainableIOBuffer::DrainableIOBuffer(
    QuicReferenceCountedPointer<IOBuffer> base, size_t size)
    : IOBuffer(base->data()), base_(std::move(base)), size_(size), used_(0) {
}

void DrainableIOBuffer::DidConsume(int bytes) {
  SetOffset(used_ + bytes);
}

int DrainableIOBuffer::BytesRemaining() const {
  return size_ - used_;
}

// Returns the number of consumed bytes.
int DrainableIOBuffer::BytesConsumed() const {
  return used_;
}

void DrainableIOBuffer::SetOffset(int bytes) {
  QUICHE_DCHECK_GE(bytes, 0);
  QUICHE_DCHECK_LE(bytes, size_);
  used_ = bytes;
  data_ = base_->data() + used_;
}

DrainableIOBuffer::~DrainableIOBuffer() {
  // The buffer is owned by the |base_| instance.
  data_ = nullptr;
}

} // namespace net
