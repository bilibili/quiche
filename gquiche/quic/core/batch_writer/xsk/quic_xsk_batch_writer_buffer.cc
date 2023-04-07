#include <sstream>

#include "gquiche/quic/core/batch_writer/xsk/quic_xsk_batch_writer_buffer.h"


namespace quic {

QuicXskBatchWriterBuffer::QuicXskBatchWriterBuffer(xsk_socket_info* xsk)
    : xsk_(xsk),
      next_write_location_(nullptr) {}

void QuicXskBatchWriterBuffer::Clear() {
  while(!buffered_writes_.empty()) {
    //xsk_free_umem_frame(xsk_, buffered_writes_.front().addr);
    buffered_writes_.pop_front();
  }
  buffered_writes_.clear();
}

std::string QuicXskBatchWriterBuffer::DebugString() const {
  std::ostringstream os;
  os << "{ buffered_writes_.size():" << buffered_writes_.size()
     << " SizeInUse: " << SizeInUse() << " }";
  return os.str();
}


bool QuicXskBatchWriterBuffer::Invariants() const {
  return true;
}

char* QuicXskBatchWriterBuffer::GetNextWriteLocation(const QuicIpAddress& self_address, uint64_t* addr_ptr) {
  char *loc = nullptr;
  if (buffered_writes_.size() >= 64) {
    return loc;
  }

  uint64_t addr;
  if (!next_write_location_) {
    addr = xsk_alloc_umem_frame(xsk_);
    if (addr == INVALID_UMEM_FRAME) {
      QUIC_LOG(ERROR) << "[GetNextWriteLocation]xsk_alloc_umem_frame failed.";
	    return nullptr;
    }
    //get loc
    char* eth_pkt_data = (char*)xsk_umem__get_data((char*)xsk_->umem->buffer, addr);
    if (self_address.IsIPv4()) {
      loc = eth_pkt_data + PKT_HDR_SIZE;
    } else if (self_address.IsIPv6()) {
      loc = eth_pkt_data + PKT6_HDR_SIZE;
    }
    next_write_location_ = loc;
    next_write_umem_frame_ = addr;
  } else {
    addr = next_write_umem_frame_;
    loc = next_write_location_;
  }

  if (addr_ptr) {
    *addr_ptr = addr;
  }
  return loc;
}

QuicXskBatchWriterBuffer::PushResult QuicXskBatchWriterBuffer::PushBufferedWrite(
    const char* buffer,
    size_t buf_len,
    const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address,
    const PerPacketOptions* options,
    uint64_t release_time) {
  PushResult result = {/*succeeded=*/false, /*buffer_copied*/false};
  
  // buffered_writes more than 64 or next_write_location alloc failed due to uframe full.
  uint64_t addr;
  char* next_write_location = GetNextWriteLocation(self_address, &addr);
  if (next_write_location == nullptr) {
    return result;
  }

  if (next_write_location != buffer) {
    memcpy(next_write_location, buffer, buf_len);
    result.buffer_copied = true;
  }
  next_write_location_ = nullptr;

  char *umem_buffer = (char*)xsk_->umem->buffer;
  buffered_writes_.emplace_back(
      umem_buffer, addr, buf_len, self_address, peer_address,
      options ? options->Clone() : std::unique_ptr<PerPacketOptions>(),
      release_time);

  QUICHE_DCHECK(Invariants());

  result.succeeded = true;
  return result;
}


void QuicXskBatchWriterBuffer::UndoLastPush() {
//recycle the latest buffered
  if (!buffered_writes_.empty()) {
    buffered_writes_.pop_back();
  }
}

QuicXskBatchWriterBuffer::PopResult QuicXskBatchWriterBuffer::PopBufferedWrite(
    int32_t num_buffered_writes) {
//remove some umem frame from buffered write
  QUICHE_DCHECK(Invariants());
  QUICHE_DCHECK_GE(num_buffered_writes, 0);
  QUICHE_DCHECK_LE(static_cast<size_t>(num_buffered_writes),
                   buffered_writes_.size());

  PopResult result = {/*num_buffers_popped=*/0,
                      /*moved_remaining_buffers=*/false};

  result.num_buffers_popped = std::max<int32_t>(num_buffered_writes, 0);
  result.num_buffers_popped =
  std::min<int32_t>(result.num_buffers_popped, buffered_writes_.size());
  for (int i = 0; i < result.num_buffers_popped; i++) {
    buffered_writes_.pop_front();
  }
  
  QUICHE_DCHECK(Invariants());
  
  return result;
}

size_t QuicXskBatchWriterBuffer::SizeInUse() const {
  //cal size used for all buffered_size
  size_t size_in_used = 0;
  for (auto iter = buffered_writes_.begin(); iter != buffered_writes_.end();
       ++iter) {
    size_in_used += iter->payload_buf_len;
  }
  return size_in_used;
}

} // namespace quic
