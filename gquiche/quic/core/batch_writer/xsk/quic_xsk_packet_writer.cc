#include "gquiche/quic/core/quic_udp_socket.h"
#include "gquiche/quic/core/batch_writer/xsk/quic_xdp_socket_utils.h"
#include "gquiche/quic/core/batch_writer/xsk/quic_xsk_packet_writer.h"

namespace quic {

QuicXskPacketWriter::QuicXskPacketWriter(
    int fd,
    int port,
    xsk_socket_info* xsk,
    unsigned char* self_mac_addr,
    unsigned char* peer_mac_addr)
    :fd_(fd),
     self_udp_port_(port),
     xsk_(xsk),
     self_mac_addr_(self_mac_addr),
     peer_mac_addr_(peer_mac_addr),
     write_blocked_(false) {}

QuicXskPacketWriter::~QuicXskPacketWriter() = default;

WriteResult QuicXskPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address,
    PerPacketOptions* options) {
  QUICHE_DCHECK(!write_blocked_);
  QUICHE_DCHECK(nullptr == options)
      << "QuicXskPacketWriter does not accept any options.";
  QuicUdpPacketInfo packet_info;
  packet_info.SetPeerAddress(peer_address);
  packet_info.SetSelfIp(self_address);

  WriteResult result =
      QuicXdpSocketUtils().WritePacket(xsk_, buffer, buf_len, packet_info, self_udp_port_,
                                     self_mac_addr_, peer_mac_addr_);
  if (IsWriteBlockedStatus(result.status)) {
    write_blocked_ = true;
  }

  return result;
}

bool QuicXskPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void QuicXskPacketWriter::SetWritable() {
  write_blocked_ = false;
}

QuicByteCount QuicXskPacketWriter::GetMaxPacketSize(
    const QuicSocketAddress& /*peer_address*/) const {
  return kMaxOutgoingPacketSize;
}

bool QuicXskPacketWriter::SupportsReleaseTime() const {
  return false;
}

bool QuicXskPacketWriter::IsBatchMode() const {
  return false;
}

QuicPacketBuffer QuicXskPacketWriter::GetNextWriteLocation(
    const QuicIpAddress& /*self_address*/,
    const QuicSocketAddress& /*peer_address*/) {
  return {nullptr, nullptr};
}

WriteResult QuicXskPacketWriter::Flush() {
  return WriteResult(WRITE_STATUS_OK, 0);
}

void QuicXskPacketWriter::set_write_blocked(bool is_blocked) {
  write_blocked_ = is_blocked;
}

}  // namespace quic
