#include "base/bvc-qlog/src/qlogger.h"

#include "gquiche/quic/core/quic_stream.h"
#include "gquiche/quic/core/quic_packets.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"

namespace quic {

std::string GetFlowControlEvent(int offset) {
  return "flow control event, new offset: " + std::to_string(offset);
}

std::string GetRxStreamWU(QuicStreamId stream_id, uint64_t packet_num, uint64_t maximumData) {
  return "rx stream, stream_id: " + quiche::QuicheTextUtilsImpl::Uint64ToString(stream_id) +
      ", packet_num: " + quiche::QuicheTextUtilsImpl::Uint64ToString(packet_num) +
      ", maximumData: " + quiche::QuicheTextUtilsImpl::Uint64ToString(maximumData);
}

std::string GetRxConnWU(uint64_t packet_num, uint64_t maximumData) {
  return "rx, packet_num: " + quiche::QuicheTextUtilsImpl::Uint64ToString(packet_num) +
      ", maximumData: " + quiche::QuicheTextUtilsImpl::Uint64ToString(maximumData);
}

std::string GetPeerClose(const std::string& peerCloseReason) {
  return "error message: " + peerCloseReason;
}

std::string GetFlowControlWindowAvailable(uint64_t windowAvailable) {
  return "on flow control, window available: " +
      quiche::QuicheTextUtilsImpl::Uint64ToString(windowAvailable);
}

std::string GetClosingStream(const std::string& stream_id) {
  return "closing stream, stream id: " + stream_id;
}

} // namespace quic
