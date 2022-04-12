// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

#include "base/bvc-qlog/src/base_qlogger.h"
#include "gquiche/quic/core/quic_types.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "platform/spdy_platform_impl/spdy_string_utils_impl.h"

namespace quic {

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    const QuicPacketHeader& packetHeader,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packetNum = packetHeader.packet_number.ToUint64();
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketReceived;
  summary_.totalPacketsRecvd++;
  summary_.totalBytesRecvd += packetSize;

  if (packetHeader.form == IETF_QUIC_SHORT_HEADER_PACKET) {
    event->packetType = std::string(kShortHeaderPacketType);
  } else if (packetHeader.form == GOOGLE_QUIC_PACKET) {
    event->packetType = std::string(kGooglePacketType);
  } else {
    event->packetType =
        std::string(toQlogString(packetHeader.long_packet_type));
  }
  return event;
}

void BaseQLogger::addPacketFrameImpl(
    QLogPacketEvent* event,
    QuicFrameType frame_type,
    void* frame,
    bool isPacketRecvd) {
  switch (frame_type) {
    // Stream Frame
    case QuicFrameType::STREAM_FRAME: {
      QuicStreamFrame* f = static_cast<QuicStreamFrame*>(frame);
      event->frames.push_back(std::make_unique<StreamFrameLog>(
          f->stream_id, f->offset, f->data_length, f->fin));
      break;
    }
    // Ack Frame
    case QuicFrameType::ACK_FRAME: {
      QuicAckFrame* f = static_cast<QuicAckFrame*>(frame);
      event->frames.push_back(std::make_unique<AckFrameLog>(
          f->packets, f->ack_delay_time.ToMicroseconds()));
      break;
    }
    // Padding Frame
    case QuicFrameType::PADDING_FRAME: {
      event->frames.push_back(std::make_unique<PaddingFrameLog>());
      break;
    }
    //Reset Stream Frame
    case QuicFrameType::RST_STREAM_FRAME: {
      QuicRstStreamFrame* f = static_cast<QuicRstStreamFrame*>(frame);
      event->frames.push_back(std::make_unique<RstStreamFrameLog>(
          f->stream_id, f->error_code, f->byte_offset));
      break;
    }
    // Connection Close Frame
    case QuicFrameType::CONNECTION_CLOSE_FRAME: {
      QuicConnectionCloseFrame* f = static_cast<QuicConnectionCloseFrame*>(frame);
      event->frames.push_back(std::make_unique<ConnectionCloseFrameLog>(
        f->close_type, f->wire_error_code, f->quic_error_code, f->error_details, f->transport_close_frame_type));
      break;
    }
    // Goaway Frame
    case QuicFrameType::GOAWAY_FRAME: {
      QuicGoAwayFrame* f = static_cast<QuicGoAwayFrame*>(frame);
      event->frames.push_back(std::make_unique<GoAwayFrameLog>(
          f->error_code, f->last_good_stream_id, f->reason_phrase));
      break;
    }
    // Window Update Frame
    case QuicFrameType::WINDOW_UPDATE_FRAME: {
      QuicWindowUpdateFrame* f = static_cast<QuicWindowUpdateFrame*>(frame);
      event->frames.push_back(std::make_unique<WindowUpdateFrameLog>(
          f->stream_id, f->max_data));
      break;
    }
    // Blocked Frame
    case QuicFrameType::BLOCKED_FRAME: {
      QuicBlockedFrame* f = static_cast<QuicBlockedFrame*>(frame);
      event->frames.push_back(std::make_unique<BlockedFrameLog>(
          f->stream_id));
      break;
    }
    // Stop Waiting Frame
    case QuicFrameType::STOP_WAITING_FRAME: {
      event->frames.push_back(std::make_unique<StopWaitingFrameLog>());
      break;
    }
    // Ping Frame
    case QuicFrameType::PING_FRAME: {
      event->frames.push_back(std::make_unique<PingFrameLog>());
      break;
    }
    // Crypto Frame
    case QuicFrameType::CRYPTO_FRAME: {
      QuicCryptoFrame* f = static_cast<QuicCryptoFrame*>(frame);
      event->frames.push_back(std::make_unique<CryptoFrameLog>(
          f->level, f->offset, f->data_length));
      break;
    }
    // Handshake Done Frame
    case QuicFrameType::HANDSHAKE_DONE_FRAME: {
      event->frames.push_back(std::make_unique<HandshakeDoneFrameLog>());
      break;
    }
    // MTU Discovery Frame
    case QuicFrameType::MTU_DISCOVERY_FRAME: {
      event->frames.push_back(std::make_unique<MTUDiscoveryFrameLog>());
      break;
    }
    // New Connection ID Frame
    case QuicFrameType::NEW_CONNECTION_ID_FRAME: {
      QuicNewConnectionIdFrame* f = static_cast<QuicNewConnectionIdFrame*>(frame);
      event->frames.push_back(std::make_unique<NewConnectionIdFrameLog>(
          f->connection_id.ToString(), f->sequence_number));
      break;
    }
    // Max Streams Frame
    case QuicFrameType::MAX_STREAMS_FRAME: {
      QuicMaxStreamsFrame* f = static_cast<QuicMaxStreamsFrame*>(frame);
      event->frames.push_back(std::make_unique<MaxStreamsFrameLog>(
          f->stream_count, f->unidirectional));
      break;
    }
    // Streams Blocked Frame
    case QuicFrameType::STREAMS_BLOCKED_FRAME: {
      QuicStreamsBlockedFrame* f = static_cast<QuicStreamsBlockedFrame*>(frame);
      event->frames.push_back(std::make_unique<StreamsBlockedFrameLog>(
          f->stream_count, f->unidirectional));
      break;
    }
    // Path Response Frame
    case QuicFrameType::PATH_RESPONSE_FRAME: {
      QuicPathResponseFrame* f = static_cast<QuicPathResponseFrame*>(frame);
      event->frames.push_back(std::make_unique<PathResponseFrameLog>(
          spdy::SpdyHexEncodeImpl(reinterpret_cast<const char*>(f->data_buffer.data()), f->data_buffer.size())));
      break;
    }
    // Path Challenge Frame
    case QuicFrameType::PATH_CHALLENGE_FRAME: {
      QuicPathChallengeFrame* f = static_cast<QuicPathChallengeFrame*>(frame);
      event->frames.push_back(std::make_unique<PathChallengeFrameLog>(spdy::SpdyHexEncodeImpl(
          reinterpret_cast<const char*>(f->data_buffer.data()),
          f->data_buffer.size())));
      break;
    }
    // Stop Sending Frame
    case QuicFrameType::STOP_SENDING_FRAME: {
      QuicStopSendingFrame* f = static_cast<QuicStopSendingFrame*>(frame);
      event->frames.push_back(std::make_unique<StopSendingFrameLog>(f->stream_id, f->error_code));
      break;
    }
    // Message Frame
    case QuicFrameType::MESSAGE_FRAME: {
      QuicMessageFrame* f = static_cast<QuicMessageFrame*>(frame);
      event->frames.push_back(
          std::make_unique<MessageFrameLog>(f->message_id, f->message_length));
      break;
    }
    // New Token Frame
    case QuicFrameType::NEW_TOKEN_FRAME: {
      event->frames.push_back(std::make_unique<NewTokenFrameLog>());
      break;
    }
    // Retire Connection ID Frame
    case QuicFrameType::RETIRE_CONNECTION_ID_FRAME: {
      QuicRetireConnectionIdFrame* f = static_cast<QuicRetireConnectionIdFrame*>(frame);
      event->frames.push_back(
          std::make_unique<RetireConnectionIdFrameLog>(f->sequence_number));
      break;
    }
    // Ack Frequency Frame
    case QuicFrameType::ACK_FREQUENCY_FRAME: {
      QuicAckFrequencyFrame* f = static_cast<QuicAckFrequencyFrame*>(frame);
      event->frames.push_back(std::make_unique<AckFrequencyFrameLog>(
          f->sequence_number, f->packet_tolerance,
          f->max_ack_delay.ToMilliseconds(), f->ignore_order));
      break;
    }
    // Num Frame Types
    case QuicFrameType::NUM_FRAME_TYPES:
    default: {
      break;
    }
  }
}

std::unique_ptr<QLogVersionNegotiationEvent> BaseQLogger::createPacketEventImpl(
    const QuicVersionNegotiationPacket& versionNegotiationPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogVersionNegotiationEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packetSize = packetSize;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = kVersionNegotiationPacketType;
  event->versionLog = std::make_unique<VersionNegotiationLog>(
      VersionNegotiationLog(versionNegotiationPacket.versions));
  summary_.totalPacketsRecvd++;
  summary_.totalBytesRecvd += packetSize;
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    const std::string newConnectionId,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packetSize = packetSize;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = kQuicPublicResetPacketType;
  summary_.totalPacketsRecvd++;
  summary_.totalBytesRecvd += packetSize;
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    const QuicPublicResetPacket& publicResetPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packetSize = packetSize;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = kQuicPublicResetPacketType;
  summary_.totalPacketsRecvd++;
  summary_.totalBytesRecvd += packetSize;
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    uint64_t packet_number,
    uint64_t packet_length,
    TransmissionType transmission_type,
    EncryptionLevel encryption_level,
    const QuicFrames& retransmittable_frames,
    const QuicFrames& nonretransmittable_frames,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packetNum = packet_number;
  event->packetSize = packet_length;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  if (encryption_level >= ENCRYPTION_FORWARD_SECURE) {
    event->packetType = std::string(kShortHeaderPacketType);
  } else {
    event->packetType =
        std::string(toQlogString(encryptionLevelToLongHeaderType(encryption_level)));
  }
  event->transmissionType =
      std::string(toQlogString(transmission_type));

  summary_.totalPacketsSent++;
  summary_.totalBytesSent += packet_length;

  for (const QuicFrame& frame : retransmittable_frames) {
    void* fv = getFrameType(frame);
    if (fv != NULL) {
      addPacketFrameImpl(event.get(), frame.type, fv, isPacketRecvd);
    }
  }
  for (const QuicFrame& frame : nonretransmittable_frames) {
    void* fv = getFrameType(frame);
    if (fv != NULL) {
      addPacketFrameImpl(event.get(), frame.type, fv, isPacketRecvd);
    }
  }
  return event;
}

void* BaseQLogger::getFrameType(const QuicFrame& frame) {
    void* fv;
    switch (frame.type) {
      case QuicFrameType::STREAM_FRAME:
          fv = (void*)&frame.stream_frame;
          break;
      case QuicFrameType::RST_STREAM_FRAME:
          fv = (void*)frame.rst_stream_frame;
          break;
      case QuicFrameType::CONNECTION_CLOSE_FRAME:
          fv = (void*)frame.connection_close_frame;
          break;
      case QuicFrameType::WINDOW_UPDATE_FRAME:
          fv = (void*)frame.window_update_frame;
          break;
      case QuicFrameType::BLOCKED_FRAME:
          fv = (void*)frame.blocked_frame;
          break;
      case QuicFrameType::PING_FRAME:
          fv = (void*)&frame.ping_frame;
          break;
      case QuicFrameType::HANDSHAKE_DONE_FRAME:
          fv = (void*)&frame.handshake_done_frame;
          break;
      case QuicFrameType::ACK_FREQUENCY_FRAME:
          fv = (void*)frame.ack_frequency_frame;
          break;
      case QuicFrameType::PADDING_FRAME:
          fv = (void*)&frame.padding_frame;
          break;
      case QuicFrameType::MTU_DISCOVERY_FRAME:
          fv = (void*)&frame.mtu_discovery_frame;
          break;
      case QuicFrameType::STOP_WAITING_FRAME:
          fv = (void*)&frame.stop_waiting_frame;
          break;
      case QuicFrameType::ACK_FRAME:
          fv = (void*)frame.ack_frame;
          break;

      // New IETF frames, not used in current gQUIC version.
      case QuicFrameType::NEW_CONNECTION_ID_FRAME:
          fv = (void*)frame.new_connection_id_frame;
          break;
      case QuicFrameType::RETIRE_CONNECTION_ID_FRAME:
          fv = (void*)frame.retire_connection_id_frame;
          break;
      case QuicFrameType::MAX_STREAMS_FRAME:
          fv = (void*)&frame.max_streams_frame;
          break;
      case QuicFrameType::STREAMS_BLOCKED_FRAME:
          fv = (void*)&frame.streams_blocked_frame;
          break;
      case QuicFrameType::PATH_RESPONSE_FRAME:
          fv = (void*)frame.path_response_frame;
          break;
      case QuicFrameType::PATH_CHALLENGE_FRAME:
          fv = (void*)frame.path_challenge_frame;
          break;
      case QuicFrameType::STOP_SENDING_FRAME:
          fv = (void*)frame.stop_sending_frame;
          break;
      case QuicFrameType::MESSAGE_FRAME:
          fv = (void*)frame.message_frame;
          break;
      case QuicFrameType::CRYPTO_FRAME:
          fv = (void*)frame.crypto_frame;
          break;
      case QuicFrameType::NEW_TOKEN_FRAME:
          fv = (void*)frame.new_token_frame;
          break;
      // Ignore gQUIC-specific frames.
      case QuicFrameType::GOAWAY_FRAME:
          fv = (void*)frame.goaway_frame;
          break;
      case QuicFrameType::NUM_FRAME_TYPES:
      default:
          fv = NULL;
          break;
    }
    return fv;
}

} // namespace quic
