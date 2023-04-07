#ifndef QUICHE_QUIC_CORE_QUIC_XSK_BATCH_WRITER_BUFFER_H_
#define QUICHE_QUIC_CORE_QUIC_XSK_BATCH_WRITER_BUFFER_H_

#include "absl/base/optimization.h"
#include "gquiche/quic/core/quic_packet_writer.h"
#include "gquiche/quic/platform/api/quic_ip_address.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/common/quiche_circular_deque.h"
#include "gquiche/quic/core/batch_writer/xsk/quic_xdp_socket_utils.h"

namespace quic {

class QuicXskBatchWriterBuffer {
 public:
  QuicXskBatchWriterBuffer(xsk_socket_info* xsk);

  // Clear all buffered writes, but leave the internal buffer intact.
  void Clear();

  char* GetNextWriteLocation(const QuicIpAddress& self_address, uint64_t* addr_ptr);

  // Push a buffered write to the back.
  struct PushResult {
    bool succeeded;
    bool buffer_copied;
  };

  PushResult PushBufferedWrite(const char* buffer,
                               size_t buf_len,
                               const QuicIpAddress& self_address,
                               const QuicSocketAddress& peer_address,
                               const PerPacketOptions* options,
                               uint64_t release_time);

  void UndoLastPush();

  // Pop |num_buffered_writes| buffered writes from the front.
  // |num_buffered_writes| will be capped to [0, buffered_writes().size()]
  // before it is used.
  struct PopResult {
    int32_t num_buffers_popped;
    // True if after |num_buffers_popped| buffers are popped from front, the
    // remaining buffers are moved to the beginning of the internal buffer.
    // This should normally be false.
    bool moved_remaining_buffers;
  };
  PopResult PopBufferedWrite(int32_t num_buffered_writes);

  const quiche::QuicheCircularDeque<XskBufferedWrite>& buffered_writes() const {
    return buffered_writes_;
  }

  // Number of bytes used in |buffer_|.
  // PushBufferedWrite() increases this; PopBufferedWrite decreases this.
  size_t SizeInUse() const;

  // Rounded up from |kMaxGsoPacketSize|, which is the maximum allowed
  // size of a GSO packet.
  static const size_t kBufferSize = 64 * 1024;

  std::string DebugString() const;

 protected:
  // Whether the invariants of the buffer are upheld. For debug & test only.
  bool Invariants() const;
  //not owned.
  xsk_socket_info*                              xsk_;
  quiche::QuicheCircularDeque<XskBufferedWrite> buffered_writes_;
  uint64_t                                      next_write_umem_frame_;
  char*                                         next_write_location_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_XSK_BATCH_WRITER_BUFFER_H_