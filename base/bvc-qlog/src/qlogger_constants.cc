#include "base/bvc-qlog/src/qlogger_constants.h"

namespace quic {
quiche::QuicheStringPiece vantagePointString(VantagePoint vantagePoint) {
  switch (vantagePoint) {
    case VantagePoint::IS_CLIENT:
      return kQLogClientVantagePoint;
    case VantagePoint::IS_SERVER:
      return kQLogServerVantagePoint;
    default:
      return "unknown_perspective";
  }
}

quiche::QuicheStringPiece toQlogString(QuicFrameType frame) {
  switch (frame) {
    case QuicFrameType::PADDING_FRAME:
      return "padding";
    case QuicFrameType::RST_STREAM_FRAME:
      return "rst_stream";
    case QuicFrameType::CONNECTION_CLOSE_FRAME:
      return "connection_close";
    case QuicFrameType::GOAWAY_FRAME:
      return "go_away";
    case QuicFrameType::WINDOW_UPDATE_FRAME:
      return "window_update";
    case QuicFrameType::BLOCKED_FRAME:
      return "blocked";
    case QuicFrameType::STOP_WAITING_FRAME:
      return "stop_waiting";
    case QuicFrameType::PING_FRAME:
      return "ping";
    case QuicFrameType::ACK_FRAME:
      return "ack";
    case QuicFrameType::STREAM_FRAME:
      return "stream";
    case QuicFrameType::CRYPTO_FRAME:
      return "crypto";
    case QuicFrameType::HANDSHAKE_DONE_FRAME:
      return "handshake_done";
    case QuicFrameType::MTU_DISCOVERY_FRAME:
      return "mtu_discovery";
    case QuicFrameType::NEW_CONNECTION_ID_FRAME:
      return "new_connection_id";
    case QuicFrameType::MAX_STREAMS_FRAME:
      return "max_streams";
    case QuicFrameType::STREAMS_BLOCKED_FRAME:
      return "streams_blocked";
    case QuicFrameType::PATH_RESPONSE_FRAME:
      return "path_response";
    case QuicFrameType::PATH_CHALLENGE_FRAME:
      return "path_challenge";
    case QuicFrameType::STOP_SENDING_FRAME:
      return "stop_sending";
    case QuicFrameType::MESSAGE_FRAME:
      return "message";
    case QuicFrameType::NEW_TOKEN_FRAME:
      return "new_token";
    case QuicFrameType::RETIRE_CONNECTION_ID_FRAME:
      return "retire_connection_id";
    case QuicFrameType::ACK_FREQUENCY_FRAME:
      return "ack_frequency";
    default:
      return "unknown_frame";
  }
}

quiche::QuicheStringPiece toQlogString(QuicLongHeaderType type) {
  switch (type) {
    case QuicLongHeaderType::INITIAL:
      return "initial";
    case QuicLongHeaderType::RETRY:
      return "RETRY";
    case QuicLongHeaderType::HANDSHAKE:
      return "handshake";
    case QuicLongHeaderType::ZERO_RTT_PROTECTED:
      return "0RTT";
    case QuicLongHeaderType::VERSION_NEGOTIATION:
      return "version_negotiation";
    case QuicLongHeaderType::INVALID_PACKET_TYPE:
      return "invalid";
    default:
      return "unknown_header_type";
  }
}

quiche::QuicheStringPiece toQlogString(EncryptionLevel level) {
  switch (level) {
    case EncryptionLevel::ENCRYPTION_INITIAL:
      return "initial";
    case EncryptionLevel::ENCRYPTION_HANDSHAKE:
      return "handshake";
    case EncryptionLevel::ENCRYPTION_ZERO_RTT:
      return "zero_rtt";
    case EncryptionLevel::ENCRYPTION_FORWARD_SECURE:
      return "forward_secure";
    case EncryptionLevel::NUM_ENCRYPTION_LEVELS:
    default:
      return "invalid_encryption_level";
 }
}

QuicLongHeaderType encryptionLevelToLongHeaderType(EncryptionLevel level) {
  switch (level) {
    case EncryptionLevel::ENCRYPTION_INITIAL:
      return QuicLongHeaderType::INITIAL;
    case EncryptionLevel::ENCRYPTION_HANDSHAKE:
      return QuicLongHeaderType::HANDSHAKE;
    case EncryptionLevel::ENCRYPTION_ZERO_RTT:
      return QuicLongHeaderType::ZERO_RTT_PROTECTED;
    case EncryptionLevel::ENCRYPTION_FORWARD_SECURE:
    default:
      return QuicLongHeaderType::INVALID_PACKET_TYPE;
  }
}

quiche::QuicheStringPiece toQlogString(TransmissionType type) {
  switch (type) {
    case TransmissionType::NOT_RETRANSMISSION:
      return "not_retransmission";
    case TransmissionType::HANDSHAKE_RETRANSMISSION:
      return "handshake_retransmission";
    case TransmissionType::ALL_ZERO_RTT_RETRANSMISSION:
      return "all_zero_rtt_retransmission";
    case TransmissionType::LOSS_RETRANSMISSION:
      return "loss_retransmission";
    case TransmissionType::RTO_RETRANSMISSION:
      return "rto_retransmission";
    case TransmissionType::TLP_RETRANSMISSION:
      return "tlp_retransmission";
    case TransmissionType::PTO_RETRANSMISSION:
      return "pto_retransmission";
    case TransmissionType::PROBING_RETRANSMISSION:
      return "probing_retransmission";
    default:
      return "invalid_retransmission";
  }
}

quiche::QuicheStringPiece toQlogString(CongestionControlType type) {
  switch (type) {
    case kCubicBytes:
      return "Cubic";
    case kRenoBytes:
      return "Reno";
    case kBBR:
      return "BBR";
    case kPCC:
      return "PCC";
    case kGoogCC:
      return "GoogCC";
    case kBBRv2:
      return "BBRv2";
  }
  return "invalid_type";
}

quiche::QuicheStringPiece toQlogString(BbrSender::Mode mode) {
  switch (mode) {
    case BbrSender::STARTUP:
      return "STARTUP";
    case BbrSender::DRAIN:
      return "DRAIN";
    case BbrSender::PROBE_BW:
      return "PROBE_BW";
    case BbrSender::PROBE_RTT:
      return "PROBE_RTT";
  }
  return "invalid_mode";
}

quiche::QuicheStringPiece toQlogString(Bbr2Mode mode) {
  switch (mode) {
    case Bbr2Mode::STARTUP:
      return "STARTUP";
    case Bbr2Mode::DRAIN:
      return "DRAIN";
    case Bbr2Mode::PROBE_BW:
      return "PROBE_BW";
    case Bbr2Mode::PROBE_RTT:
      return "PROBE_RTT";
  }
  return "InvalidMode";
}

quiche::QuicheStringPiece toQlogString(BbrSender::RecoveryState recovery_state) {
  switch (recovery_state) {
    case BbrSender::NOT_IN_RECOVERY:
      return "NOT_IN_RECOVERY";
    case BbrSender::CONSERVATION:
      return "CONSERVATION";
    case BbrSender::GROWTH:
      return "GROWTH";
  }
  return "invalid_state";
}

quiche::QuicheStringPiece toQlogString(QuicConnectionCloseType close_type) {
  switch (close_type) {
    case GOOGLE_QUIC_CONNECTION_CLOSE:
      return "GOOGLE_QUIC_CONNECTION_CLOSE";
    case IETF_QUIC_TRANSPORT_CONNECTION_CLOSE:
      return "IETF_QUIC_TRANSPORT_CONNECTION_CLOSE";
    case IETF_QUIC_APPLICATION_CONNECTION_CLOSE:
      return "IETF_APPLICATION_CONNECTION_CLOSE";
  }
  return "invalid_type";
}

}// namespace quic
