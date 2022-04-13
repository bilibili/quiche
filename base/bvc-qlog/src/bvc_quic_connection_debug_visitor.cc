#include "bvc_quic_connection_debug_visitor.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "base/bvc-qlog/src/file_qlogger.h"
#include "gquiche/quic/core/quic_utils.h"
#include "gquiche/quic/platform/api/quic_socket_address.h"
#include "gquiche/quic/core/congestion_control/bbr_sender.h"

using namespace quic;

namespace bvc {

BvcQuicConnectionDebugVisitor::BvcQuicConnectionDebugVisitor(
  FileQLogger* qlogger, QuicConnection* connection)
  : qlogger_(qlogger),
    connection_(connection) {
}

void BvcQuicConnectionDebugVisitor::OnPacketReceived(
  const QuicSocketAddress& self_address,
  const QuicSocketAddress& peer_address,
  const QuicEncryptedPacket& packet) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  packet_length_ = packet.length();
}


void BvcQuicConnectionDebugVisitor::OnPacketSent(
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
  (qlogger_)->addPacket(packet_number.ToUint64(), packet_length, transmission_type,
                         encryption_level, retransmittable_frames, nonretransmittable_frames, false);
}

void BvcQuicConnectionDebugVisitor::OnPublicResetPacket(const QuicPublicResetPacket& packet) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  (qlogger_)->addPacket(packet, packet_length_, true);
}

void BvcQuicConnectionDebugVisitor::OnVersionNegotiationPacket(const QuicVersionNegotiationPacket& packet) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }
  (qlogger_)->addPacket(packet, packet_length_, true);
}

void BvcQuicConnectionDebugVisitor::OnPacketHeader(
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
  current_event_ = (qlogger_)->createPacketEvent(header, packet_length_, true);
}

void BvcQuicConnectionDebugVisitor::OnPacketComplete() {
  if (qlogger_ == NULL || connection_ == NULL || current_event_.get() == NULL) {
    return;
  }
  (qlogger_)->finishCreatePacketEvent(std::move(current_event_));
}

void BvcQuicConnectionDebugVisitor::OnConnectionClosed(
  const QuicConnectionCloseFrame& frame,
  ConnectionCloseSource source) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }

  (qlogger_)->addConnectionClose(frame.quic_error_code, frame.error_details, source);
}

void BvcQuicConnectionDebugVisitor::OnStreamFrame(const QuicStreamFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::STREAM_FRAME, const_cast<QuicStreamFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnCryptoFrame(const QuicCryptoFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::CRYPTO_FRAME, const_cast<QuicCryptoFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnStopWaitingFrame(const QuicStopWaitingFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::STOP_WAITING_FRAME, const_cast<QuicStopWaitingFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnPaddingFrame(const QuicPaddingFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::PADDING_FRAME, const_cast<QuicPaddingFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnPingFrame(const QuicPingFrame& frame, QuicTime::Delta) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::PING_FRAME, const_cast<QuicPingFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnGoAwayFrame(const QuicGoAwayFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::GOAWAY_FRAME, const_cast<QuicGoAwayFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::RST_STREAM_FRAME, const_cast<QuicRstStreamFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::CONNECTION_CLOSE_FRAME, const_cast<QuicConnectionCloseFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame, const QuicTime& receive_time) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::WINDOW_UPDATE_FRAME, const_cast<QuicWindowUpdateFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnBlockedFrame(const QuicBlockedFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::BLOCKED_FRAME, const_cast<QuicBlockedFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::HANDSHAKE_DONE_FRAME, const_cast<QuicHandshakeDoneFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnNewConnectionIdFrame(
       const QuicNewConnectionIdFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::NEW_CONNECTION_ID_FRAME, const_cast<QuicNewConnectionIdFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::MAX_STREAMS_FRAME, const_cast<QuicMaxStreamsFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::STREAMS_BLOCKED_FRAME, const_cast<QuicStreamsBlockedFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnPathResponseFrame(const QuicPathResponseFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::PATH_RESPONSE_FRAME, const_cast<QuicPathResponseFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnPathChallengeFrame(const QuicPathChallengeFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::PATH_CHALLENGE_FRAME, const_cast<QuicPathChallengeFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnStopSendingFrame(const QuicStopSendingFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::STOP_SENDING_FRAME, const_cast<QuicStopSendingFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnMessageFrame(const QuicMessageFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::MESSAGE_FRAME, const_cast<QuicMessageFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnNewTokenFrame(const QuicNewTokenFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::NEW_TOKEN_FRAME, const_cast<QuicNewTokenFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnRetireConnectionIdFrame(const QuicRetireConnectionIdFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::RETIRE_CONNECTION_ID_FRAME, const_cast<QuicRetireConnectionIdFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnAckFrequencyFrame(const QuicAckFrequencyFrame& frame) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::ACK_FREQUENCY_FRAME, const_cast<QuicAckFrequencyFrame*>(&frame), true);
}

void BvcQuicConnectionDebugVisitor::OnAckFrameStart(
    QuicTime::Delta ack_delay_time) {
  if (qlogger_ == NULL || connection_ == NULL || current_event_ == NULL) {
    return;
  }
  ack_frame_.reset();
  ack_frame_ = std::make_unique<QuicAckFrame>();
  ack_frame_->ack_delay_time = ack_delay_time;
}

void BvcQuicConnectionDebugVisitor::OnAckRange(
    QuicPacketNumber start, QuicPacketNumber end) {
  if (qlogger_ == NULL || connection_ == NULL ||
      current_event_ == NULL || ack_frame_ == NULL) {
    return;
  }
  //*: Because the interval uses half-closed range `[)` and causes confusion,
  //*: minus 1 here to make it closed range '[]'
  ack_frame_->packets.AddRange(start, end);
}

void BvcQuicConnectionDebugVisitor::OnAckFrameEnd(
    QuicPacketNumber start) {
  if (qlogger_ == NULL || connection_ == NULL ||
      current_event_ == NULL || ack_frame_ == NULL) {
    return;
  }
  (qlogger_)->addPacketFrame(current_event_.get(), QuicFrameType::ACK_FRAME, ack_frame_.get(), true);
}

void BvcQuicConnectionDebugVisitor::OnIncomingAck(
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
}

void BvcQuicConnectionDebugVisitor::OnPacketLoss(
    QuicPacketNumber lost_packet_number,
    EncryptionLevel encryption_level,
    TransmissionType transmission_type,
    QuicTime detection_time) {
  if (qlogger_ == NULL || connection_ == NULL) {
    return;
  }

  (qlogger_)->addPacketLost(lost_packet_number.ToUint64(), encryption_level, transmission_type);
}

} // namespace bvc
