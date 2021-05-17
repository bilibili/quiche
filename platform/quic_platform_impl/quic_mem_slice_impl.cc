#include "platform/quic_platform_impl/quic_mem_slice_impl.h"
#include "gquiche/quic/core/quic_buffer_allocator.h"

namespace quic {

namespace {

template <typename UniqueBufferPtr>
class QuicIOBuffer : public net::IOBuffer {
 public:
  QuicIOBuffer(UniqueBufferPtr buffer, size_t size)
    : buffer_(std::move(buffer)) {
    data_ = buffer_.get();
  }

 private:
  ~QuicIOBuffer() override { data_ = nullptr; }
  UniqueBufferPtr buffer_;
};

}

QuicMemSliceImpl::QuicMemSliceImpl() = default;

QuicMemSliceImpl::QuicMemSliceImpl(QuicUniqueBufferPtr buffer, size_t length) {
  QuicReferenceCountedPointer<QuicIOBuffer<QuicUniqueBufferPtr>> buf(new QuicIOBuffer<QuicUniqueBufferPtr>(std::move(buffer), length));
  io_buffer_ = std::move(buf);
  length_ = length;
}

QuicMemSliceImpl::QuicMemSliceImpl(std::unique_ptr<char[]> buffer, size_t length) {
  QuicReferenceCountedPointer<QuicIOBuffer<std::unique_ptr<char[]>>> buf(new QuicIOBuffer<std::unique_ptr<char[]>>(std::move(buffer), length));
  io_buffer_ = std::move(buf);
  length_ = length;
}

QuicMemSliceImpl::QuicMemSliceImpl(QuicReferenceCountedPointer<net::IOBuffer> io_buffer,
                                   size_t length)
    : io_buffer_(std::move(io_buffer)), length_(length) {}

QuicMemSliceImpl::QuicMemSliceImpl(QuicMemSliceImpl&& other)
    : io_buffer_(std::move(other.io_buffer_)), length_(other.length_) {
  other.length_ = 0;
}

QuicMemSliceImpl& QuicMemSliceImpl::operator=(QuicMemSliceImpl&& other) {
  io_buffer_ = std::move(other.io_buffer_);
  length_ = other.length_;
  other.length_ = 0;
  return *this;
}

QuicMemSliceImpl::~QuicMemSliceImpl() = default;

void QuicMemSliceImpl::Reset() {
  io_buffer_ = nullptr;
  length_ = 0;
}

const char* QuicMemSliceImpl::data() const {
  if (io_buffer_ == nullptr) {
    return nullptr;
  }
  return io_buffer_->data();
}

}  // namespace quic
