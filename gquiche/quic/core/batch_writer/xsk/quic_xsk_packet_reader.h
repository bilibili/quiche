#ifndef GQUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_PACKET_READER_H_
#define GQUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_PACKET_READER_H_

#include "gquiche/quic/core/quic_clock.h"
#include "gquiche/quic/core/quic_constants.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/quic_process_packet_interface.h"
#include "gquiche/quic/core/quic_udp_socket.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"

#include "gquiche/quic/core/batch_writer/xsk/quic_xdp_socket_utils.h"

namespace quic {

// Read in larger batches to minimize recvmmsg overhead.
const int kNumPacketsPerXskReadCall = 16;

class QuicXskPacketReader {
 public:
  QuicXskPacketReader(QuicXdpSocketUtils::Visitor* xsk_socket_visitor);
  QuicXskPacketReader(const QuicXskPacketReader&) = delete;
  QuicXskPacketReader& operator=(const QuicXskPacketReader&) = delete;

  virtual ~QuicXskPacketReader();


  // Reads a number of packets from the given fd, and then passes them off to
  // the PacketProcessInterface.  Returns true if there may be additional
  // packets available on the socket.
  // Populates |packets_dropped| if it is non-null and the socket is configured
  // to track dropped packets and some packets are read.
  // If the socket has timestamping enabled, the per packet timestamps will be
  // passed to the processor. Otherwise, |clock| will be used.
  virtual bool ReadAndDispatchPackets(xsk_socket_info* xsk_,
                                      int port,
                                      const QuicClock& clock,
                                      ProcessPacketInterface* processor,
                                      QuicPacketCount* packets_dropped);


 private:

  // Return the self ip from |packet_info|.
  // For dual stack sockets, |packet_info| may contain both a v4 and a v6 ip, in
  // that case, |prefer_v6_ip| is used to determine which one is used as the
  // return value. If neither v4 nor v6 ip exists, return an uninitialized ip.
  static QuicIpAddress GetSelfIpFromPacketInfo(
      const QuicUdpPacketInfo& packet_info,
      bool prefer_v6_ip);

  QuicXdpSocketUtils socket_api_;
  QuicXdpSocketUtils::XskReadPacketResults read_results_;
};

} // namespace quic

#endif //GQUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_PACKET_READER_H_