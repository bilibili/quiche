#include "connection_debug_visitor.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "base/bvc-qlog/src/file_qlogger.h"
#include "gquiche/quic/core/quic_utils.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/quic/core/congestion_control/bbr_sender.h"

namespace quic {

ConnectionDebugVisitor::ConnectionDebugVisitor(
  FileQLogger* qlogger, QuicConnection* connection)
  : qlogger_(qlogger),
    connection_(connection) {
}

void ConnectionDebugVisitor::OnPacketReceived(
  const QuicSocketAddress& self_address,
  const QuicSocketAddress& peer_address,
  const QuicEncryptedPacket& packet) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  packet_length_ = packet.length();
}


void ConnectionDebugVisitor::OnPacketSent(
  QuicPacketNumber packet_number,
  QuicPacketLength packet_length,
  bool has_crypto_handshake,
  TransmissionType transmission_type,
  EncryptionLevel encryption_level,
  const QuicFrames& retransmittable_frames,
  const QuicFrames& nonretransmittable_frames,
  QuicTime sent_time) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  (qlogger_)->AddPacket(packet_number.ToUint64(), packet_length, transmission_type,
                         encryption_level, retransmittable_frames, nonretransmittable_frames, false);
}

void ConnectionDebugVisitor::OnPublicResetPacket(const QuicPublicResetPacket& packet) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  (qlogger_)->AddPacket(packet, packet_length_, true);
}

void ConnectionDebugVisitor::OnVersionNegotiationPacket(const QuicVersionNegotiationPacket& packet) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  (qlogger_)->AddPacket(packet, packet_length_, true);
}

void ConnectionDebugVisitor::OnPacketHeader(
  const QuicPacketHeader& header,
  QuicTime receive_time,
  EncryptionLevel level) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  if (VersionHasIetfQuicFrames(header.version.transport_version)) {
    // packet has IETF quic frames
  } else {
    // packet has google quic frames
  }
  current_event_ = (qlogger_)->CreatePacketEvent(header, packet_length_, true);
}

void ConnectionDebugVisitor::OnPacketComplete() {
  if (qlogger_ == NULL || connection_ == NULL || current_event_.get() == NULL) {
    return;
  }
  (qlogger_)->FinishCreatePacketEvent(std::move(current_event_));
}

void ConnectionDebugVisitor::OnConnectionClosed(
  const QuicConnectionCloseFrame& frame,
  ConnectionCloseSource source) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }

  (qlogger_)->AddConnectionClose(frame.quic_error_code, frame.error_details, source);
}

void ConnectionDebugVisitor::OnStreamFrame(const QuicStreamFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::STREAM_FRAME, const_cast<QuicStreamFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnCryptoFrame(const QuicCryptoFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::CRYPTO_FRAME, const_cast<QuicCryptoFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnStopWaitingFrame(const QuicStopWaitingFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::STOP_WAITING_FRAME, const_cast<QuicStopWaitingFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnPaddingFrame(const QuicPaddingFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::PADDING_FRAME, const_cast<QuicPaddingFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnPingFrame(const QuicPingFrame& frame, QuicTime::Delta) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::PING_FRAME, const_cast<QuicPingFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnGoAwayFrame(const QuicGoAwayFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::GOAWAY_FRAME, const_cast<QuicGoAwayFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::RST_STREAM_FRAME, const_cast<QuicRstStreamFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::CONNECTION_CLOSE_FRAME, const_cast<QuicConnectionCloseFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame, const QuicTime& receive_time) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::WINDOW_UPDATE_FRAME, const_cast<QuicWindowUpdateFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnBlockedFrame(const QuicBlockedFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::BLOCKED_FRAME, const_cast<QuicBlockedFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::HANDSHAKE_DONE_FRAME, const_cast<QuicHandshakeDoneFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnNewConnectionIdFrame(
       const QuicNewConnectionIdFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::NEW_CONNECTION_ID_FRAME, const_cast<QuicNewConnectionIdFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::MAX_STREAMS_FRAME, const_cast<QuicMaxStreamsFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::STREAMS_BLOCKED_FRAME, const_cast<QuicStreamsBlockedFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnPathResponseFrame(const QuicPathResponseFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::PATH_RESPONSE_FRAME, const_cast<QuicPathResponseFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnPathChallengeFrame(const QuicPathChallengeFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::PATH_CHALLENGE_FRAME, const_cast<QuicPathChallengeFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnStopSendingFrame(const QuicStopSendingFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::STOP_SENDING_FRAME, const_cast<QuicStopSendingFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnMessageFrame(const QuicMessageFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::MESSAGE_FRAME, const_cast<QuicMessageFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnNewTokenFrame(const QuicNewTokenFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::NEW_TOKEN_FRAME, const_cast<QuicNewTokenFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnRetireConnectionIdFrame(const QuicRetireConnectionIdFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::RETIRE_CONNECTION_ID_FRAME, const_cast<QuicRetireConnectionIdFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnAckFrequencyFrame(const QuicAckFrequencyFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::ACK_FREQUENCY_FRAME, const_cast<QuicAckFrequencyFrame*>(&frame), true);
}

void ConnectionDebugVisitor::OnAckFrameStart(
    QuicTime::Delta ack_delay_time) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  ack_frame_.reset();
  ack_frame_ = std::make_unique<QuicAckFrame>();
  ack_frame_->ack_delay_time = ack_delay_time;
}

void ConnectionDebugVisitor::OnAckRange(
    QuicPacketNumber start, QuicPacketNumber end) {
  if (qlogger_ == NULL || connection_ == NULL ||
      current_event_ == NULL || ack_frame_ == NULL) {
    return;
  }
  //*: Because the interval uses half-closed range `[)` and causes confusion,
  //*: minus 1 here to make it closed range '[]'
  ack_frame_->packets.AddRange(start, end);
}

void ConnectionDebugVisitor::OnAckFrameEnd(
    QuicPacketNumber start) {
  if (qlogger_ == NULL || connection_ == NULL ||
      current_event_ == NULL || ack_frame_ == NULL) {
    return;
  }
  (qlogger_)->AddPacketFrame(current_event_.get(), QuicFrameType::ACK_FRAME, ack_frame_.get(), true);
}

void ConnectionDebugVisitor::OnIncomingAck(
    QuicPacketNumber /*ack_packet_number*/,
    EncryptionLevel /*ack_decrypted_level*/,
    const QuicAckFrame& /*ack_frame*/,
    QuicTime /*ack_receive_time*/,
    QuicPacketNumber /*largest_observed*/,
    bool /*rtt_updated*/,
    QuicPacketNumber /*least_unacked_sent_packet*/) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }

  SendAlgorithmInterface* send_algorithm =
	  const_cast<SendAlgorithmInterface*>(connection_->sent_packet_manager().GetSendAlgorithm());
    uint64_t bytes_inflight =  connection_->sent_packet_manager().unacked_packets().bytes_in_flight();
    uint64_t current_cwnd = send_algorithm->GetCongestionWindow();
  if (send_algorithm->GetCongestionControlType() == kBBR) {
    BbrSender::DebugState state = static_cast<BbrSender*>(send_algorithm)->ExportDebugState();
    (qlogger_)->AddBBRCongestionMetricUpdate(bytes_inflight, current_cwnd, kCongestionPacketAck, kBBR, &state);
  } else if (send_algorithm->GetCongestionControlType() == kCubicBytes) {
    TcpCubicSenderBytes::DebugState state = static_cast<TcpCubicSenderBytes*>(send_algorithm)->ExportDebugState();
    (qlogger_)->AddCubicCongestionMetricUpdate(bytes_inflight, current_cwnd, kCongestionPacketAck, kCubicBytes, &state);
  } else if (send_algorithm->GetCongestionControlType() == kBBRv2) {
    Bbr2Sender::DebugState state = static_cast<Bbr2Sender*>(send_algorithm)->ExportDebugState();
    (qlogger_)->AddBBR2CongestionMetricUpdate(bytes_inflight, current_cwnd, kCongestionPacketAck, kBBRv2, &state);
  } else {
    // TODO : Other CC Algorithm
  }
}

void ConnectionDebugVisitor::OnPacketLoss(
    QuicPacketNumber lost_packet_number,
    EncryptionLevel encryption_level,
    TransmissionType transmission_type,
    QuicTime detection_time) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }

  (qlogger_)->AddPacketLost(lost_packet_number.ToUint64(), encryption_level, transmission_type);

  SendAlgorithmInterface* send_algorithm =
	  const_cast<SendAlgorithmInterface*>(connection_->sent_packet_manager().GetSendAlgorithm());
  uint64_t bytes_inflight =  connection_->sent_packet_manager().unacked_packets().bytes_in_flight();
  uint64_t current_cwnd = send_algorithm->GetCongestionWindow();
  if (send_algorithm->GetCongestionControlType() == kBBR) {
    BbrSender::DebugState state = static_cast<BbrSender*>(send_algorithm)->ExportDebugState();
    (qlogger_)->AddBBRCongestionMetricUpdate(bytes_inflight, current_cwnd, kCongestionPacketLoss, kBBR, &state);
  } else if (send_algorithm->GetCongestionControlType() == kCubicBytes) {
    TcpCubicSenderBytes::DebugState state = static_cast<TcpCubicSenderBytes*>(send_algorithm)->ExportDebugState();
    (qlogger_)->AddCubicCongestionMetricUpdate(bytes_inflight, current_cwnd, kCongestionPacketAck, kCubicBytes, &state);
  } else if (send_algorithm->GetCongestionControlType() == kBBRv2) {
    Bbr2Sender::DebugState state = static_cast<Bbr2Sender*>(send_algorithm)->ExportDebugState();
    (qlogger_)->AddBBR2CongestionMetricUpdate(bytes_inflight, current_cwnd, kCongestionPacketAck, kBBRv2, &state);
  } else {
    // TODO : Other CC Algorithm
  }
}

} // namespace bvc
