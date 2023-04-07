#ifndef QUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_BATCH_WRITER_H_
#define QUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_BATCH_WRITER_H_

#include "gquiche/quic/core/batch_writer/xsk/quic_xdp_socket_utils.h"
#include "gquiche/quic/core/batch_writer/xsk/quic_xsk_batch_writer_base.h"

namespace quic {

class QuicXskBatchWriter : public QuicXskUdpBatchWriter {
 public:
  QuicXskBatchWriter(std::unique_ptr<QuicXskBatchWriterBuffer> batch_buffer,
                        int fd, int port, xsk_socket_info* xsk,
                        unsigned char* self_mac_addr,
                        unsigned char* peer_mac_addr);

  CanBatchResult CanBatch(const char* buffer,
                          size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          const PerPacketOptions* options,
                          uint64_t release_time) const override;

  FlushImplResult FlushImpl() override;

 protected:
  FlushImplResult InternalFlushImpl();

 private:
  uint16_t self_udp_port_;
  unsigned char* self_mac_addr_;
  unsigned char* peer_mac_addr_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_BATCH_WRITER_H_
