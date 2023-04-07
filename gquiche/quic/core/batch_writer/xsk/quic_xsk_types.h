#ifndef QUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_TYPES_H_
#define QUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_TYPES_H_

#include <cstdint>
#include <bpf/xsk.h>
#include <bpf/libbpf.h>

#define NUM_FRAMES (4 * 1024)
#define INVALID_UMEM_FRAME UINT64_MAX

namespace quic {

struct xsk_app_stats {
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long copy_tx_sendtos;
	unsigned long opt_polls;
	unsigned long prev_rx_empty_polls;
	unsigned long prev_fill_fail_polls;
	unsigned long prev_copy_tx_sendtos;
	unsigned long prev_tx_wakeup_sendtos;
	unsigned long prev_opt_polls;
};

typedef struct xsk_socket_info {
 struct xsk_ring_cons rx;
 struct xsk_ring_prod tx;
 struct xsk_umem_info *umem;
 struct xsk_socket *xsk;
 struct xsk_socket_config socket_config;

 uint64_t umem_frame_addr[NUM_FRAMES];
 uint32_t umem_frame_free;

 uint32_t outstanding_tx;
} xsk_socket_info;

typedef struct xsk_umem_info {
 struct xsk_ring_prod fq;
 struct xsk_ring_cons cq;
 struct xsk_umem *umem;
 void *buffer;
} xsk_umem_info;

typedef struct bpf_object bpf_object;
typedef struct bpf_map    bpf_map;

} // namespace quic
#endif // QUICHE_QUIC_CORE_BATCH_WRITER_XSK_QUIC_XSK_TYPES_H_