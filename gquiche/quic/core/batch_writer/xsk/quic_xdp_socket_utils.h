#ifndef QUICHE_QUIC_CORE_BATCH_WRITER_QUIC_XDP_SOCKET_UTILS_H_
#define QUICHE_QUIC_CORE_BATCH_WRITER_QUIC_XDP_SOCKET_UTILS_H_

#define MIN_PKT_SIZE 64

#include <poll.h>
#include <string>
#include <vector>
#include <limits>

#include <arpa/inet.h>
#include <cstdint>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/udp.h>

#include "gquiche/common/quiche_circular_deque.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/core/quic_udp_socket.h"
#include "gquiche/quic/core/quic_utils.h"
#include "gquiche/quic/core/quic_packet_writer.h"
#include "gquiche/quic/core/batch_writer/xsk/quic_xsk_types.h"
#include "gquiche/quic/platform/api/quic_bug_tracker.h"

#define ETH_FCS_SIZE 4

#define PKT_HDR_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
          sizeof(struct udphdr))
#define PKT_SIZE             (DEFAULT_PACKET_SIZE - ETH_FCS_SIZE)
#define IP_PKT_SIZE          (PKT_SIZE - sizeof(struct ethhdr))
#define UDP_PKT_SIZE         (IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE    (UDP_PKT_SIZE - sizeof(struct udphdr))

#define PKT6_HDR_SIZE (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
          sizeof(struct udphdr))
#define UDP6_PKT_SIZE        (IP_PKT_SIZE - sizeof(struct ipv6hdr))
#define UDP6_PKT_DATA_SIZE   (UDP6_PKT_SIZE - sizeof(struct udphdr))

#ifndef __packed
#define __packed __attribute__ ((packed))
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
namespace quic {

__sum16 ip_fast_csum(const void *iph, unsigned int ihl);

uint16_t udp_csum(uint32_t saddr, uint32_t daddr, uint32_t len,
			   uint8_t proto, uint16_t *udp_pkt);

uint64_t xsk_alloc_umem_frame(xsk_socket_info *xsk);
void xsk_free_umem_frame(xsk_socket_info *xsk, uint64_t frame);
uint64_t xsk_umem_free_frames(xsk_socket_info *xsk);

void kick_tx(xsk_socket_info *xsk);
void complete_tx(xsk_socket_info *xsk);

uint16_t udp_csum_new(in_addr_t src_addr, in_addr_t dest_addr, size_t len, const uint16_t *buff);

/* Calculates TCP, UDP, or ICMP checksum for IPv6 (in network byte order). */
extern __be16 tcp_udp_v6_checksum(
    const struct in6_addr *src_ip,
		const struct in6_addr *dst_ip,
		u8 protocol, const void *payload, u32 len);

// class derived from class BufferedWrite
struct XskBufferedWrite {
  XskBufferedWrite(const char* umem_area,
                   const uint64_t addr,
                   size_t payload_buf_len,
                   const QuicIpAddress& self_address,
                   const QuicSocketAddress& peer_address)
      : XskBufferedWrite(umem_area,
                         addr,
                         payload_buf_len,
                         self_address,
                         peer_address,
                         std::unique_ptr<PerPacketOptions>(),
                         /*release_time=*/0) {}

  XskBufferedWrite(const char* umem_area,
                   const uint64_t addr,
                   size_t payload_buf_len,
                   const QuicIpAddress& self_address,
                   const QuicSocketAddress& peer_address,
                   std::unique_ptr<PerPacketOptions> options,
                   uint64_t release_time)
      : umem_area(umem_area),
        addr(addr),
        payload_buf_len(payload_buf_len),
        self_address(self_address),
        peer_address(peer_address),
        options(std::move(options)),
        release_time(release_time) {}

  const char* umem_area;
  const uint64_t addr;
  size_t payload_buf_len;
  QuicIpAddress self_address;
  QuicSocketAddress peer_address;
  std::unique_ptr<PerPacketOptions> options;

  // The release time according to the owning packet writer's clock, which is
  // often not a QuicClock. Calculated from packet writer's Now() and the
  // release time delay in |options|.
  // 0 means it can be sent at the same time as the previous packet in a batch,
  // or can be sent Now() if this is the first packet of a batch.
  uint64_t release_time;
};


using ConstIteratorT = quiche::QuicheCircularDeque<XskBufferedWrite>::const_iterator;

class QuicXdpSocketUtils {
 public:
  class Visitor {
   public:
    virtual ~Visitor() {}
    virtual unsigned char* self_mac_addr() = 0;
    virtual unsigned char* peer_mac_addr() = 0;
    virtual void OnSelfMacAddrUpdate(unsigned char* self_mac_addr) = 0;
    virtual void OnPeerMacAddrUpdate(unsigned char* peer_mac_addr) = 0;
  };

  struct XskReadPacketResult {
    bool ok = false;
    uint64_t uframe_addr = std::numeric_limits<uint64_t>::max();
    QuicUdpPacketInfo packet_info;
    BufferSpan packet_buffer;
    BufferSpan control_buffer;

    void Reset(size_t packet_buffer_length) {
      ok = false;
      uframe_addr = std::numeric_limits<uint64_t>::max();
      packet_info.Reset();
      packet_buffer.buffer = nullptr;
      packet_buffer.buffer_len = packet_buffer_length;
    }
  };

  using XskReadPacketResults = std::vector<XskReadPacketResult>;

  size_t ReadMultiplePackets(
    xsk_socket_info *xsk,
    BitMask64 packet_info_interested,
    XskReadPacketResults* results,
    uint32_t* idx_fq);

  void ReleaseRxRing(
    xsk_socket_info* xsk, 
    int nums,
    XskReadPacketResults* results,
    uint32_t idx_fq);

  WriteResult WritePacket(
    xsk_socket_info *xsk,
    const char* packet_buffer,
    size_t packet_buffer_len,
    const QuicUdpPacketInfo& packet_info,
    const uint16_t self_udp_port,
    const unsigned char* self_mac_addr,
    const unsigned char* peer_mac_addr);

  WriteResult WriteMultiplePackets(
    xsk_socket_info        *xsk,
    const ConstIteratorT&  first,
    const ConstIteratorT&  last,
    const uint16_t         self_udp_port,
    const unsigned char*   self_mac_addr,
    const unsigned char*   peer_mac_addr,
    int*                   num_packets_sent);
  
  void AssemblePktHdr(
    char* eth_pkt_data,
    size_t packet_buffer_len,
    const QuicUdpPacketInfo& packet_info,
    const uint16_t self_udp_port,
    const unsigned char* self_mac_addr,
    const unsigned char* peer_mac_addr);

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

 protected:

  void HandleRecvEthPkt(
    char *pkt, BitMask64& packet_info_interested,
    XskReadPacketResult* result);

 private:
  Visitor*       visitor_;
};

} //namespace quic

#endif //QUICHE_QUIC_CORE_BATCH_WRITER_QUIC_AF_XDP_SOCKET_UTILS_H_
