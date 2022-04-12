// io_buffer is derived from chromium/net/base/io_buffer

#ifndef QUICHE_NET_BASE_IO_BUFFER_H_
#define QUICHE_NET_BASE_IO_BUFFER_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "gquiche/quic/platform/api/quic_reference_counted.h"

namespace net{

// This is a simplified version of chromium net::IOBuffer. That is to say, We
//take of reference count of that.
class IOBuffer : public quic::QuicReferenceCounted {
 public:
  IOBuffer();

  explicit IOBuffer(size_t buffer_size);

  char* data() const { return data_; }

 protected:

  // Only allow derived classes to specify data_.
  // In all other cases, we own data_, and must delete it at destruction time.
  explicit IOBuffer(char* data);

  virtual ~IOBuffer();

  char* data_;
};

// This version stores the size of the buffer so that the creator of the object
// doesn't have to keep track of that value.
// NOTE: This doesn't mean that we want to stop sending the size as an explicit
// argument to IO functions. Please keep using IOBuffer* for API declarations.
class IOBufferWithSize : public IOBuffer {
 public:
  explicit IOBufferWithSize(size_t size);

  int size() const { return size_; }

 protected:
  // Purpose of this constructor is to give a subclass access to the base class
  // constructor IOBuffer(char*) thus allowing subclass to use underlying
  // memory it does not own.
  IOBufferWithSize(char* data, size_t size);
  ~IOBufferWithSize() override;

  int size_;
};

// This version wraps an existing IOBuffer and provides convenient functions
// to progressively read all the data.
//
// DrainableIOBuffer is useful when you have an IOBuffer that contains data
// to be written progressively, and Write() function takes an IOBuffer rather
// than char*. DrainableIOBuffer can be used as follows:
//
// // payload is the IOBuffer containing the data to be written.
// buf = base::MakeRefCounted<DrainableIOBuffer>(payload, payload_size);
//
// while (buf->BytesRemaining() > 0) {
//   // Write() takes an IOBuffer. If it takes char*, we could
//   // simply use the regular IOBuffer like payload->data() + offset.
//   int bytes_written = Write(buf, buf->BytesRemaining());
//   buf->DidConsume(bytes_written);
// }
//
class DrainableIOBuffer : public IOBuffer {
 public:
  // TODO(eroman): Deprecated. Use the size_t flavor instead. crbug.com/488553
  DrainableIOBuffer(quic::QuicReferenceCountedPointer<IOBuffer> base, int size);
  DrainableIOBuffer(quic::QuicReferenceCountedPointer<IOBuffer> base, size_t size);

  // DidConsume() changes the |data_| pointer so that |data_| always points
  // to the first unconsumed byte.
  void DidConsume(int bytes);

  // Returns the number of unconsumed bytes.
  int BytesRemaining() const;

  // Returns the number of consumed bytes.
  int BytesConsumed() const;

  // Seeks to an arbitrary point in the buffer. The notion of bytes consumed
  // and remaining are updated appropriately.
  void SetOffset(int bytes);

  int size() const { return size_; }

 private:
  ~DrainableIOBuffer() override;

  quic::QuicReferenceCountedPointer<IOBuffer> base_;
  int size_;
  int used_;
};

} // namespace net
#endif // QUICHE_NET_BASE_IO_BUFFER_H_
