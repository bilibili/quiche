#include "base/bvc-qlog/src/qlogger.h"

#include "gquiche/quic/core/quic_stream.h"
#include "gquiche/quic/core/quic_packets.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"

namespace quic {

std::string getFlowControlEvent(int offset) {
  return "flow control event, new offset: " + std::to_string(offset);
}

std::string getRxStreamWU(QuicStreamId streamId, uint64_t packetNum, uint64_t maximumData) {
  return "rx stream, streamId: " + quiche::QuicheTextUtilsImpl::Uint64ToString(streamId) +
      ", packetNum: " + quiche::QuicheTextUtilsImpl::Uint64ToString(packetNum) +
      ", maximumData: " + quiche::QuicheTextUtilsImpl::Uint64ToString(maximumData);
}

std::string getRxConnWU(uint64_t packetNum, uint64_t maximumData) {
  return "rx, packetNum: " + quiche::QuicheTextUtilsImpl::Uint64ToString(packetNum) +
      ", maximumData: " + quiche::QuicheTextUtilsImpl::Uint64ToString(maximumData);
}

std::string getPeerClose(const std::string& peerCloseReason) {
  return "error message: " + peerCloseReason;
}

std::string getFlowControlWindowAvailable(uint64_t windowAvailable) {
  return "on flow control, window available: " +
      quiche::QuicheTextUtilsImpl::Uint64ToString(windowAvailable);
}

std::string getClosingStream(const std::string& streamId) {
  return "closing stream, stream id: " + streamId;
}

} // namespace quic
