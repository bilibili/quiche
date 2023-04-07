#ifndef QUICHE_QUIC_CORE_BATCH_WRITER_QUIC_XSK_PACKET_WRITER_H_
#define QUICHE_QUIC_CORE_BATCH_WRITER_QUIC_XSK_PACKET_WRITER_H_

#include <cstddef>

#include "gquiche/quic/core/quic_packet_writer.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/platform/api/quic_export.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"

#include "gquiche/quic/core/batch_writer/xsk/quic_xsk_types.h"

namespace quic {

// AF_XDP packet writer which wraps QuicXdpSocketUtils WritePacket.
class QuicXskPacketWriter : public QuicPacketWriter
{
 public:
  explicit QuicXskPacketWriter(int fd, int port, xsk_socket_info* xsk,
                                  unsigned char* self_mac_addr,
                                  unsigned char* peer_mac_addr);
  QuicXskPacketWriter(const QuicXskPacketWriter&) = delete;
  QuicXskPacketWriter& operator=(const QuicXskPacketWriter&) = delete;
  ~QuicXskPacketWriter() override;

  // QuicPacketWriter
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options) override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  QuicByteCount GetMaxPacketSize(
      const QuicSocketAddress& peer_address) const override;
  bool SupportsReleaseTime() const override;
  bool IsBatchMode() const override;
  QuicPacketBuffer GetNextWriteLocation(
      const QuicIpAddress& self_address,
      const QuicSocketAddress& peer_address) override;
  WriteResult Flush() override;

  //void set_fd(int fd) { fd_ = fd; }

 protected:
  void set_write_blocked(bool is_blocked);
  int fd() { return fd_; }

 private:
  int fd_;
  xsk_socket_info* xsk_;
  uint16_t self_udp_port_;
  unsigned char* self_mac_addr_;
  unsigned char* peer_mac_addr_;
  bool write_blocked_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_BATCH_WRITER_QUIC_XSK_PACKET_WRITER_H_
