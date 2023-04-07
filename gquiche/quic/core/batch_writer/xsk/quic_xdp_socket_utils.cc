#include <cstring>
#include <errno.h>
#include <linux/if_xdp.h>
#include <memory>
#include <bpf/xsk.h>

#include "gquiche/quic/platform/api/quic_logging.h"
#include "gquiche/quic/core/batch_writer/xsk/quic_xdp_socket_utils.h"

#define DEFAULT_PACKET_SIZE    1518

using namespace quiche;

namespace quic {

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}


/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline uint32_t from64to32(uint64_t x)
{
    /* add up 32-bit and 32-bit for 32+c bit */
    x = (x & 0xffffffff) + (x >> 32);
    /* add up carry.. */
    x = (x & 0xffffffff) + (x >> 32);
    return (uint32_t)x;
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
    uint32_t sum = (uint32_t)csum;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
              __u32 len, __u8 proto, __wsum sum)
{
    unsigned long long s = (uint32_t)sum;

    s += (uint32_t)saddr;
    s += (uint32_t)daddr;
#ifdef __BIG_ENDIAN__
    s += proto + len;
#else
    s += (proto + len) << 8;
#endif
    return (__wsum)from64to32(s);
}


/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
          __u8 proto, __wsum sum)
{
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}


uint16_t udp_csum(uint32_t saddr, uint32_t daddr, uint32_t len,
               uint8_t proto, uint16_t *udp_pkt)
{
    uint32_t csum = 0;
    uint32_t cnt = 0;

    /* udp hdr and data */
    for (; cnt < len; cnt += 2)
        csum += udp_pkt[cnt >> 1];

    return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
__sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum((const unsigned char*)iph, ihl * 4);
}


uint16_t udp_csum_new(in_addr_t src_addr, in_addr_t dest_addr, size_t len, const uint16_t *buff)
{
        const uint16_t *buf=buff;
        uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
        uint32_t sum;
        size_t length=len;

        // Calculate the sum                                            //
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }

        if ( len & 1 )
                // Add the padding if the packet lenght is odd          //
                sum += *((uint8_t *)buf);

        // Add the pseudo-header                                        //
        sum += *(ip_src++);
        sum += *ip_src;

        sum += *(ip_dst++);
        sum += *ip_dst;

        sum += htons(IPPROTO_UDP);
        sum += htons(length);

        // Add the carries                                              //
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        // Return the one's complement of sum                           //
        return ( (uint16_t)(~sum)  );
}

/* Add bytes in buffer to a running checksum. Returns the new
 * intermediate checksum. Use ip_checksum_fold() to convert the
 * intermediate checksum to final form.
 */
static u64 ip_checksum_partial(const void *p, size_t len, u64 sum)
{
	/* Main loop: 32 bits at a time.
	 * We take advantage of intel's ability to do unaligned memory
	 * accesses with minimal additional cost. Other architectures
	 * probably want to be more careful here.
	 */
	const u32 *p32 = (const u32 *)(p);
	for (; len >= sizeof(*p32); len -= sizeof(*p32))
		sum += *p32++;

	/* Handle un-32bit-aligned trailing bytes */
	const u16 *p16 = (const u16 *)(p32);
	if (len >= 2) {
		sum += *p16++;
		len -= sizeof(*p16);
	}
	if (len > 0) {
		const u8 *p8 = (const u8 *)(p16);
		sum += ntohs(*p8 << 8);	/* RFC says pad last byte */
	}

	return sum;
}

static __be16 ip_checksum_fold(u64 sum)
{
	while (sum & ~0xffffffffULL)
		sum = (sum >> 32) + (sum & 0xffffffffULL);
	while (sum & 0xffff0000ULL)
		sum = (sum >> 16) + (sum & 0xffffULL);

	return ~sum;
}


static u64 tcp_udp_v6_header_checksum_partial(
	const struct in6_addr *src_ip,
	const struct in6_addr *dst_ip,
	u8 protocol, u32 len)
{
	/* The IPv6 pseudo-header is defined in RFC 2460, Section 8.1. */
	struct ipv6_pseudo_header_t {
		/* We use a union here to avoid aliasing issues with gcc -O2 */
		union {
			struct {
				struct in6_addr src_ip;
				struct in6_addr dst_ip;
				__be32 length;
				__u8 mbz[3];
				__u8 next_header;
			} __packed fields;
			u32 words[10];
		};
	};
	struct ipv6_pseudo_header_t pseudo_header;
	assert(sizeof(pseudo_header) == 40);

	/* Fill in the pseudo-header. */
	pseudo_header.fields.src_ip = *src_ip;
	pseudo_header.fields.dst_ip = *dst_ip;
	pseudo_header.fields.length = htonl(len);
	memset(pseudo_header.fields.mbz, 0, sizeof(pseudo_header.fields.mbz));
	pseudo_header.fields.next_header = protocol;
	return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}



__be16 tcp_udp_v6_checksum(const struct in6_addr *src_ip,
			   const struct in6_addr *dst_ip,
			   u8 protocol, const void *payload, u32 len)
{
	u64 sum = tcp_udp_v6_header_checksum_partial(
		src_ip, dst_ip, protocol, len);
	sum = ip_checksum_partial(payload, len, sum);
	return ip_checksum_fold(sum);
}


uint64_t xsk_alloc_umem_frame(xsk_socket_info *xsk)
{
  uint64_t frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

void xsk_free_umem_frame(xsk_socket_info *xsk, uint64_t frame)
{
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

uint64_t xsk_umem_free_frames(xsk_socket_info *xsk)
{
  return xsk->umem_frame_free;
}

void kick_tx(xsk_socket_info *xsk)
{
  int ret;

  ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
  if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
      errno == EBUSY || errno == ENETDOWN)
    return;
  QUIC_LOG(ERROR) << "kick_tx error:  " << strerror(errno);
  return;
}

void complete_tx(xsk_socket_info *xsk)
{
  unsigned int completed;
  uint32_t idx;

  if (!xsk->outstanding_tx) {
    return;
  }

  bool need_wakeup = 
       xsk->socket_config.bind_flags & XDP_USE_NEED_WAKEUP ? true : false;

  if (!need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
    kick_tx(xsk);
  }
  // from bpf/xsk.h, XSK_RING_CONS__DEFAULT_NUM_DESCS : 2048
  completed = xsk_ring_cons__peek(&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx);
  if (completed > 0) {
    for (int i = 0; i < completed; i++) {
      xsk_free_umem_frame(xsk,
              *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx++));
    }
    xsk_ring_cons__release(&xsk->umem->cq, completed);
    xsk->outstanding_tx -= completed;
  }
}


// private
void QuicXdpSocketUtils::HandleRecvEthPkt(
    char *pkt, BitMask64& packet_info_interested,
    XskReadPacketResult* result)
{
  unsigned char* self_mac_addr = visitor_->self_mac_addr();
  unsigned char* peer_mac_addr = visitor_->peer_mac_addr();
  result->ok = false;
  struct ethhdr *eth_hdr = (struct ethhdr *)pkt;
  if (strncmp((const char*)self_mac_addr, (const char*)eth_hdr->h_dest, ETH_ALEN) != 0) {
    visitor_->OnSelfMacAddrUpdate(eth_hdr->h_dest);
  }

  if (strncmp((const char*)peer_mac_addr, (const char*)eth_hdr->h_source, ETH_ALEN) != 0) {
    visitor_->OnPeerMacAddrUpdate(eth_hdr->h_source);
  }

  char* recv_udp_payload_ptr = nullptr;
  struct udphdr *udp_hdr = nullptr;
  QuicUdpPacketInfo* packet_info = &(result->packet_info);
  if (eth_hdr->h_proto == htons(ETH_P_IP)) {
    struct iphdr *ip_hdr = (struct iphdr *)(pkt + sizeof(struct ethhdr));

    if (ip_hdr->protocol != IPPROTO_UDP) {
      QUIC_LOG(ERROR) << "[HandleRecvEthPkt] recv packet is not based UDP protocol";
      return;
    }
    udp_hdr = (struct udphdr *) (pkt + 
        sizeof(struct ethhdr) + sizeof(struct iphdr));

    struct in_addr saddr_v4, daddr_v4;
    saddr_v4.s_addr = ip_hdr->saddr;
    daddr_v4.s_addr = ip_hdr->daddr;
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::PEER_ADDRESS)) {
      packet_info->SetPeerAddress(QuicSocketAddress(QuicheIpAddress(saddr_v4),
                                                    ntohs(udp_hdr->source)));
    }
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::V4_SELF_IP)) {
      packet_info->SetSelfV4Ip(QuicheIpAddress(daddr_v4));
    }
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::TTL)) {
      packet_info->SetTtl(ip_hdr->ttl);
    }
    recv_udp_payload_ptr = pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(udphdr);
  } else if (eth_hdr->h_proto == htons(ETH_P_IPV6)) {
    struct ipv6hdr *ipv6_hdr = (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));

    if (ipv6_hdr->nexthdr != IPPROTO_UDP) {
      QUIC_LOG(ERROR) << "[HandleRecvEthPkt] recv packet is not based UDP(IPV6) protocol";
      return;
    }
    udp_hdr = (struct udphdr *) (pkt + 
        sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

    struct in6_addr saddr_v6, daddr_v6;
    saddr_v6 = ipv6_hdr->saddr;
    daddr_v6 = ipv6_hdr->daddr;
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::PEER_ADDRESS)) {
      packet_info->SetPeerAddress(QuicSocketAddress(QuicheIpAddress(saddr_v6),
                                                    ntohs(udp_hdr->source)));
    }
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::V6_SELF_IP)) {
      packet_info->SetSelfV6Ip(QuicheIpAddress(daddr_v6));
    }
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::TTL)) {
      packet_info->SetTtl(ipv6_hdr->hop_limit);
    }
  
    recv_udp_payload_ptr = pkt + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(udphdr);
  }
  if (recv_udp_payload_ptr == nullptr) {
    QUIC_LOG(ERROR) << "[HandleRecvEthPkt] recv packet is not based on IP(V6)";
    return;
  }
  result->ok = true;
  int recv_udp_payload_len = ntohs(udp_hdr->len) - sizeof(struct udphdr);

  result->packet_buffer.buffer_len = recv_udp_payload_len;
  result->packet_buffer.buffer = recv_udp_payload_ptr;
  return;
}

size_t QuicXdpSocketUtils::ReadMultiplePackets(
    xsk_socket_info *xsk,
    BitMask64 packet_info_interested,
    XskReadPacketResults* results,
    uint32_t* idx_fq)
{
  struct pollfd fds[1] = {};
  fds[0].fd = xsk_socket__fd(xsk->xsk);
  fds[0].events = POLLOUT | POLLIN;

  uint32_t idx_rx = 0;
  int rcvd, ret;

  rcvd = xsk_ring_cons__peek(&xsk->rx, results->size(), &idx_rx);

  if (!rcvd) {
    return 0;
  }

  ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, idx_fq);
  ret = std::min(rcvd, ret);
  for (int i = 0; i < ret; i++) {
    uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
    /* because we do not apply unaligned, so no need to switch addr
    uint64_t orig = xsk_umem__extract_addr(addr);
    addr = xsk_umem__add_offset_to_addr(addr);
    */
    char *pkt = (char*)xsk_umem__get_data(xsk->umem->buffer, addr);

    (*results)[i].ok = false;
    (*results)[i].uframe_addr = addr;
    XskReadPacketResult* read_result = &(*results)[i];
    HandleRecvEthPkt(pkt, packet_info_interested, read_result);

  }
  return ret;
}

void QuicXdpSocketUtils::ReleaseRxRing(
  xsk_socket_info* xsk,
  int nums,
  XskReadPacketResults* results,
  uint32_t idx_fq)
{
  if (xsk == nullptr || results == nullptr || nums <= 0) {
    return;
  }
  for (int i = 0; i < nums; i++) {
    *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = (*results)[i].uframe_addr;
  }
  xsk_ring_prod__submit(&xsk->umem->fq, nums);
  xsk_ring_cons__release(&xsk->rx, nums);
}

WriteResult QuicXdpSocketUtils::WriteMultiplePackets(
    xsk_socket_info*          xsk,
    const ConstIteratorT&     first,
    const ConstIteratorT&     last,
    const uint16_t            self_udp_port,
    const unsigned char*      self_mac_addr,
    const unsigned char*      peer_mac_addr,
    int*                      num_packets_sent)
{
  static_assert(
      std::is_same<typename std::iterator_traits<ConstIteratorT>::value_type,
              XskBufferedWrite>::value,
      "Must iterate over a collection of XskBufferedWrite.");
  int nums_to_write = last - first;

  if (nums_to_write <= 0) {
    QUIC_LOG(ERROR) << "prepare to return WRITE_STATUS_BLOCKED in WriteMultiplePacket.";
    complete_tx(xsk);
    return WriteResult(WRITE_STATUS_BLOCKED, EWOULDBLOCK);
  }

  uint32_t idx;
  int reserved_writes = xsk_ring_prod__reserve(&xsk->tx, nums_to_write, &idx);
  *num_packets_sent = std::min(reserved_writes, nums_to_write);

  int bytes_writen = 0;
  uint32_t i = 0;
  for (auto it = first; it != last; ++it) {
    if (i >= *num_packets_sent) {
      break;
    }
    QuicUdpPacketInfo packet_info;
    packet_info.SetPeerAddress(it->peer_address);
    packet_info.SetSelfIp(it->self_address);
    char* eth_pkt_data = (char*)xsk_umem__get_data(xsk->umem->buffer, it->addr);
    AssemblePktHdr(eth_pkt_data, it->payload_buf_len,
                   packet_info, self_udp_port, self_mac_addr, peer_mac_addr);

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i++);
    tx_desc->addr = it->addr;

    if (packet_info.HasValue(QuicUdpPacketInfoBit::V4_SELF_IP)) {
      tx_desc->len = it->payload_buf_len + PKT_HDR_SIZE;
    } else if (packet_info.HasValue(QuicUdpPacketInfoBit::V6_SELF_IP)) {
      tx_desc->len = it->payload_buf_len + PKT6_HDR_SIZE;
    }

    bytes_writen += it->payload_buf_len;
  }

  xsk_ring_prod__submit(&xsk->tx, *num_packets_sent);
  xsk->outstanding_tx += *num_packets_sent;
  complete_tx(xsk);

  if (*num_packets_sent == 0) {
    return WriteResult(WRITE_STATUS_BLOCKED, EWOULDBLOCK);
  }

  return WriteResult(WRITE_STATUS_OK, bytes_writen);

}


WriteResult QuicXdpSocketUtils::WritePacket(
  xsk_socket_info *xsk,
  const char* packet_buffer,
  size_t packet_buffer_len,
  const QuicUdpPacketInfo& packet_info,
  const uint16_t self_udp_port,
  const unsigned char* self_mac_addr,
  const unsigned char* peer_mac_addr)
{
  if (!packet_info.HasValue(QuicUdpPacketInfoBit::PEER_ADDRESS)) {
    return WriteResult(WRITE_STATUS_ERROR, EINVAL);
  }

  uint64_t addr = xsk_alloc_umem_frame(xsk);
  if (addr == INVALID_UMEM_FRAME) {
    return WriteResult(WRITE_STATUS_BLOCKED, EWOULDBLOCK);
  }

  char* eth_pkt_data = (char*)xsk_umem__get_data(xsk->umem->buffer, addr);
  AssemblePktHdr(eth_pkt_data, packet_buffer_len, 
      packet_info, self_udp_port, self_mac_addr, peer_mac_addr);

  int hdr_size = 0;
  if (packet_info.HasValue(QuicUdpPacketInfoBit::V4_SELF_IP) &&
      packet_info.self_v4_ip().IsInitialized()) {
    hdr_size = PKT_HDR_SIZE;
  } else if (packet_info.HasValue(QuicUdpPacketInfoBit::V6_SELF_IP) &&
      packet_info.self_v6_ip().IsInitialized()) {
    hdr_size = PKT6_HDR_SIZE;
  }

  memcpy(eth_pkt_data + hdr_size, packet_buffer, packet_buffer_len);

  uint32_t idx;
  // batch size equal 1
  while (xsk->outstanding_tx && xsk_ring_prod__reserve(&xsk->tx,1 , &idx) < 1) {
    complete_tx(xsk);
  }

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
  tx_desc->addr = addr;
  tx_desc->len = packet_buffer_len + hdr_size;

  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;
  complete_tx(xsk);

  // status and bytes_writen, refer to QuicDefaultPacketWriter::WriteResult
  return WriteResult(WRITE_STATUS_OK, packet_buffer_len);
}

void QuicXdpSocketUtils::AssemblePktHdr(
    char* eth_pkt_data,
    size_t packet_buffer_len,
    const QuicUdpPacketInfo& packet_info,
    const uint16_t self_udp_port,
    const unsigned char* self_mac_addr,
    const unsigned char* peer_mac_addr)
{
  struct ethhdr *eth_hdr = (struct ethhdr *)eth_pkt_data;
  /* ethernet header */
  memcpy(eth_hdr->h_source, self_mac_addr, ETH_ALEN);
  memcpy(eth_hdr->h_dest, peer_mac_addr, ETH_ALEN);

  if (packet_info.HasValue(QuicUdpPacketInfoBit::V4_SELF_IP) &&
    packet_info.self_v4_ip().IsInitialized()) {

    size_t eth_pkt_size = packet_buffer_len + PKT_HDR_SIZE;
    size_t ip_tot_size = eth_pkt_size - sizeof(struct ethhdr);
    size_t udp_pkt_size = ip_tot_size - sizeof(struct iphdr);

    eth_hdr->h_proto = htons(ETH_P_IP);
    in_addr self_v4_addr = packet_info.self_v4_ip().GetIPv4();
    in_addr peer_v4_addr = packet_info.peer_address().host().GetIPv4();

    uint16_t peer_udp_port = packet_info.peer_address().port();


    struct iphdr *ip_hdr = (struct iphdr *)(eth_pkt_data +
            sizeof(struct ethhdr));
    /* IP header */
    ip_hdr->version = IPVERSION;
    ip_hdr->ihl = 0x5; /* 20 byte header */
    ip_hdr->tos = 0x0;
    ip_hdr->tot_len = htons(ip_tot_size);
    ip_hdr->id = 0;
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = IPDEFTTL;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->saddr = self_v4_addr.s_addr;
    ip_hdr->daddr = peer_v4_addr.s_addr;

    ip_hdr->check = 0;
    ip_hdr->check = ip_fast_csum((const void *)ip_hdr, ip_hdr->ihl);

    struct udphdr *udp_hdr = (struct udphdr *)(eth_pkt_data +
            sizeof(struct ethhdr) +
            sizeof(struct iphdr));

    /* UDP header */
    udp_hdr->source = htons(self_udp_port);
    udp_hdr->dest = htons(peer_udp_port);
    udp_hdr->len = htons(udp_pkt_size);

    /* UDP header checksum*/
    udp_hdr->check = 0;   
  } else if (packet_info.HasValue(QuicUdpPacketInfoBit::V6_SELF_IP) &&
             packet_info.self_v6_ip().IsInitialized()) {
#if 1
    size_t eth_pkt_size = packet_buffer_len + PKT6_HDR_SIZE;
    size_t ipv6_tot_size = eth_pkt_size - sizeof(struct ethhdr);
    size_t udp_pkt_size = ipv6_tot_size - sizeof(struct ipv6hdr);
    
    eth_hdr->h_proto = htons(ETH_P_IPV6);
    in6_addr self_v6_addr = packet_info.self_v6_ip().GetIPv6();
    in6_addr peer_v6_addr = packet_info.peer_address().host().GetIPv6();

    uint16_t peer_udp_port = packet_info.peer_address().port();

    struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)(eth_pkt_data +
            sizeof(struct ethhdr));

    ip6_hdr->version = 6;
    ip6_hdr->payload_len = htons(udp_pkt_size);
    ip6_hdr->nexthdr = IPPROTO_UDP;
    ip6_hdr->hop_limit = IPDEFTTL;
    ip6_hdr->priority = 0;
    memset(ip6_hdr->flow_lbl, 0, sizeof(ip6_hdr->flow_lbl));
    ip6_hdr->saddr = self_v6_addr;
    ip6_hdr->daddr = peer_v6_addr;

    struct udphdr *udp_hdr = (struct udphdr *)(eth_pkt_data +
            sizeof(struct ethhdr) +
            sizeof(struct ipv6hdr));
    /* UDP header */
    udp_hdr->source = htons(self_udp_port);
    udp_hdr->dest = htons(peer_udp_port);
    udp_hdr->len = htons(udp_pkt_size);

    /* UDP header checksum*/
    udp_hdr->check = 0;
    //udp_hdr->check = udp_csum(ip6_hdr->saddr, ip6_hdr->daddr, UDP6_PKT_SIZE,
    //        IPPROTO_UDP, (uint16_t *)ip6_hdr);
    udp_hdr->check = tcp_udp_v6_checksum(&ip6_hdr->saddr, &ip6_hdr->daddr, IPPROTO_UDP, 
                         udp_hdr, ntohs(ip6_hdr->payload_len));
#endif
  }
}

} //namespace quic
