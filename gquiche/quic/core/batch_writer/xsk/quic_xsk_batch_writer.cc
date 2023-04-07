#include "gquiche/quic/core/batch_writer/xsk/quic_xsk_batch_writer.h"


namespace quic {
QuicXskBatchWriter::QuicXskBatchWriter(
    std::unique_ptr<QuicXskBatchWriterBuffer> batch_buffer,
    int fd, int port, xsk_socket_info* xsk,
    unsigned char* self_mac_addr,
    unsigned char* peer_mac_addr)
    : QuicXskUdpBatchWriter(std::move(batch_buffer), xsk, fd),
      self_udp_port_(port),
      self_mac_addr_(self_mac_addr),
      peer_mac_addr_(peer_mac_addr) {}

QuicXskBatchWriter::CanBatchResult QuicXskBatchWriter::CanBatch(
    const char* /*buffer*/,
    size_t /*buf_len*/,
    const QuicIpAddress& /*self_address*/,
    const QuicSocketAddress& /*peer_address*/,
    const PerPacketOptions* /*options*/,
    uint64_t /*release_time*/) const {
  return CanBatchResult(/*can_batch=*/true, /*must_flush=*/false);
}

QuicXskBatchWriter::FlushImplResult QuicXskBatchWriter::FlushImpl() {
  return InternalFlushImpl();
}

QuicXskBatchWriter::FlushImplResult
QuicXskBatchWriter::InternalFlushImpl() {
  QUICHE_DCHECK(!IsWriteBlocked());
  QUICHE_DCHECK(!buffered_writes().empty());

  FlushImplResult result = {WriteResult(WRITE_STATUS_OK, 0),
                            /*num_packets_sent=*/0, /*bytes_written=*/0};
  WriteResult& write_result = result.write_result;

  auto first = buffered_writes().cbegin();
  const auto last = buffered_writes().cend();
  int nums_to_flush = buffered_writes().size();
  while (first != last) {
    int num_packets_sent = 0;
    write_result = QuicXdpSocketUtils().WriteMultiplePackets(
         xsk(), first, last, self_udp_port_,
         self_mac_addr_, peer_mac_addr_, &num_packets_sent);
    QUIC_DVLOG(1) << "WriteMultiplePackets sent " << num_packets_sent
                  << " out of " << nums_to_flush
                  << " packets. WriteResult=" << write_result;

    if (write_result.status != WRITE_STATUS_OK) {
      QUICHE_DCHECK_EQ(0, num_packets_sent);
      break;
    } else if (num_packets_sent == 0) {
      QUIC_BUG(quic_bug_10825_1)
          << "WriteMultiplePackets returned OK, but no packets were sent.";
      write_result = WriteResult(WRITE_STATUS_ERROR, EIO);
      break;
    }

    first += num_packets_sent;

    result.num_packets_sent += num_packets_sent;
    result.bytes_written += write_result.bytes_written;
  }

  // Call PopBufferedWrite() even if write_result.status is not WRITE_STATUS_OK,
  // to deal with partial writes.
  batch_buffer().PopBufferedWrite(result.num_packets_sent);

  if (write_result.status != WRITE_STATUS_OK) {
    return result;
  }

  QUIC_BUG_IF(quic_bug_12537_1, !buffered_writes().empty())
      << "All packets should have been written on a successful return";
  write_result.bytes_written = result.bytes_written;
  return result;
}

} // namespace quic