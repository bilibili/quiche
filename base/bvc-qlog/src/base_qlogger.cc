// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

#include "base/bvc-qlog/src/base_qlogger.h"
#include "gquiche/quic/core/quic_types.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "platform/spdy_platform_impl/spdy_string_utils_impl.h"

namespace quic {

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    const QuicPacketHeader& packet_header,
    uint64_t packet_size,
    bool is_packet_recvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packet_num_ = packet_header.packet_number.ToUint64();
  event->packet_size_ = packet_size;
  event->event_type_ = QLogEventType::PACKET_RECEIVED;
  report_summary_.total_packets_recvd++;
  report_summary_.total_bytes_recvd += packet_size;

  if (packet_header.form == IETF_QUIC_SHORT_HEADER_PACKET) {
    event->packet_type_ = std::string(kShortHeaderPacketType);
  } else if (packet_header.form == GOOGLE_QUIC_PACKET) {
    event->packet_type_ = std::string(kGooglePacketType);
  } else {
    event->packet_type_ =
        std::string(toQlogString(packet_header.long_packet_type));
  }
  return event;
}

// TODO: Maybe remove frame_type? Not needed
void BaseQLogger::addFramesProcessedImpl(
    QLogFramesProcessed* event,
    QuicFrameType frame_type,
    void* frame,
    uint64_t packet_number,
    uint64_t packet_size,
    std::string packet_type,
    std::chrono::microseconds time_dirft) {
  switch (frame_type) {
    case QuicFrameType::STREAM_FRAME: {
      QuicStreamFrame* f = static_cast<QuicStreamFrame*>(frame);
      event->frames_.push_back(std::make_unique<StreamFrameLog>(
          f->stream_id, f->offset, f->data_length, f->fin));
      event->time_drifts_.push_back(time_dirft);
      stream_map_[f->stream_id]++;

      // Get first video frame end time
      getVideoFrameEndTime(f);
      break;					   
    }
    case QuicFrameType::ACK_FRAME: {
      QuicAckFrame* f = static_cast<QuicAckFrame*>(frame);
      event->frames_.push_back(std::make_unique<AckFrameLog>(
      f->packets, f->ack_delay_time.ToMicroseconds()));
      event->time_drifts_.push_back(time_dirft);
      break;
    }
    default:
      break;
  }
  event->packet_type_ = packet_type;
  event->packet_nums_.push_back(packet_number);
  event->packet_sizes_.push_back(packet_size);
}

void BaseQLogger::addPacketFrameImpl(
    QLogPacketEvent* event,
    QuicFrameType frame_type,
    void* frame,
    bool is_packet_recvd) {
  switch (frame_type) {
    // Stream Frame
    case QuicFrameType::STREAM_FRAME: {
      QuicStreamFrame* f = static_cast<QuicStreamFrame*>(frame);
      event->frames_.push_back(std::make_unique<StreamFrameLog>(
          f->stream_id, f->offset, f->data_length, f->fin));
      stream_map_[f->stream_id]++;
      
      // Get first video frame end time
      getVideoFrameEndTime(f);
      break;
    }
    // Ack Frame
    case QuicFrameType::ACK_FRAME: {
      QuicAckFrame* f = static_cast<QuicAckFrame*>(frame);
      event->frames_.push_back(std::make_unique<AckFrameLog>(
          f->packets, f->ack_delay_time.ToMicroseconds()));
      break;
    }
    // Padding Frame
    case QuicFrameType::PADDING_FRAME: {
      event->frames_.push_back(std::make_unique<PaddingFrameLog>());
      break;
    }
    //Reset Stream Frame
    case QuicFrameType::RST_STREAM_FRAME: {
      QuicRstStreamFrame* f = static_cast<QuicRstStreamFrame*>(frame);
      event->frames_.push_back(std::make_unique<RstStreamFrameLog>(
          f->stream_id, f->error_code, f->byte_offset));
      stream_map_[f->stream_id]++;
      break;
    }
    // Connection Close Frame
    case QuicFrameType::CONNECTION_CLOSE_FRAME: {
      QuicConnectionCloseFrame* f = static_cast<QuicConnectionCloseFrame*>(frame);
      event->frames_.push_back(std::make_unique<ConnectionCloseFrameLog>(
        f->close_type, f->wire_error_code, f->quic_error_code, f->error_details, f->transport_close_frame_type));
      break;
    }
    // Goaway Frame
    case QuicFrameType::GOAWAY_FRAME: {
      QuicGoAwayFrame* f = static_cast<QuicGoAwayFrame*>(frame);
      event->frames_.push_back(std::make_unique<GoAwayFrameLog>(
          f->error_code, f->last_good_stream_id, f->reason_phrase));
      break;
    }
    // Window Update Frame
    case QuicFrameType::WINDOW_UPDATE_FRAME: {
      QuicWindowUpdateFrame* f = static_cast<QuicWindowUpdateFrame*>(frame);
      event->frames_.push_back(std::make_unique<WindowUpdateFrameLog>(
          f->stream_id, f->max_data));
      stream_map_[f->stream_id]++;
      break;
    }
    // Blocked Frame
    case QuicFrameType::BLOCKED_FRAME: {
      QuicBlockedFrame* f = static_cast<QuicBlockedFrame*>(frame);
      event->frames_.push_back(std::make_unique<BlockedFrameLog>(
          f->stream_id));
      stream_map_[f->stream_id]++;          
      break;
    }
    // Stop Waiting Frame
    case QuicFrameType::STOP_WAITING_FRAME: {
      event->frames_.push_back(std::make_unique<StopWaitingFrameLog>());
      break;
    }
    // Ping Frame
    case QuicFrameType::PING_FRAME: {
      event->frames_.push_back(std::make_unique<PingFrameLog>());
      break;
    }
    // Crypto Frame
    case QuicFrameType::CRYPTO_FRAME: {
      QuicCryptoFrame* f = static_cast<QuicCryptoFrame*>(frame);
      event->frames_.push_back(std::make_unique<CryptoFrameLog>(
          f->level, f->offset, f->data_length));
      break;
    }
    // Handshake Done Frame
    case QuicFrameType::HANDSHAKE_DONE_FRAME: {
      event->frames_.push_back(std::make_unique<HandshakeDoneFrameLog>());
      break;
    }
    // MTU Discovery Frame
    case QuicFrameType::MTU_DISCOVERY_FRAME: {
      event->frames_.push_back(std::make_unique<MTUDiscoveryFrameLog>());
      break;
    }
    // New Connection ID Frame
    case QuicFrameType::NEW_CONNECTION_ID_FRAME: {
      QuicNewConnectionIdFrame* f = static_cast<QuicNewConnectionIdFrame*>(frame);
      event->frames_.push_back(std::make_unique<NewConnectionIdFrameLog>(
          f->connection_id.ToString(), f->sequence_number));
      break;
    }
    // Max Streams Frame
    case QuicFrameType::MAX_STREAMS_FRAME: {
      QuicMaxStreamsFrame* f = static_cast<QuicMaxStreamsFrame*>(frame);
      event->frames_.push_back(std::make_unique<MaxStreamsFrameLog>(
          f->stream_count, f->unidirectional));
      break;
    }
    // Streams Blocked Frame
    case QuicFrameType::STREAMS_BLOCKED_FRAME: {
      QuicStreamsBlockedFrame* f = static_cast<QuicStreamsBlockedFrame*>(frame);
      event->frames_.push_back(std::make_unique<StreamsBlockedFrameLog>(
          f->stream_count, f->unidirectional));
      break;
    }
    // Path Response Frame
    case QuicFrameType::PATH_RESPONSE_FRAME: {
      QuicPathResponseFrame* f = static_cast<QuicPathResponseFrame*>(frame);
      event->frames_.push_back(std::make_unique<PathResponseFrameLog>(
          spdy::SpdyHexEncodeImpl(reinterpret_cast<const char*>(f->data_buffer.data()), f->data_buffer.size())));
      break;
    }
    // Path Challenge Frame
    case QuicFrameType::PATH_CHALLENGE_FRAME: {
      QuicPathChallengeFrame* f = static_cast<QuicPathChallengeFrame*>(frame);
      event->frames_.push_back(std::make_unique<PathChallengeFrameLog>(spdy::SpdyHexEncodeImpl(
          reinterpret_cast<const char*>(f->data_buffer.data()),
          f->data_buffer.size())));
      break;
    }
    // Stop Sending Frame
    case QuicFrameType::STOP_SENDING_FRAME: {
      QuicStopSendingFrame* f = static_cast<QuicStopSendingFrame*>(frame);
      event->frames_.push_back(std::make_unique<StopSendingFrameLog>(f->stream_id, f->error_code));
      stream_map_[f->stream_id]++;    
      break;
    }
    // Message Frame
    case QuicFrameType::MESSAGE_FRAME: {
      QuicMessageFrame* f = static_cast<QuicMessageFrame*>(frame);
      event->frames_.push_back(
          std::make_unique<MessageFrameLog>(f->message_id, f->message_length));
      break;
    }
    // New Token Frame
    case QuicFrameType::NEW_TOKEN_FRAME: {
      event->frames_.push_back(std::make_unique<NewTokenFrameLog>());
      break;
    }
    // Retire Connection ID Frame
    case QuicFrameType::RETIRE_CONNECTION_ID_FRAME: {
      QuicRetireConnectionIdFrame* f = static_cast<QuicRetireConnectionIdFrame*>(frame);
      event->frames_.push_back(
          std::make_unique<RetireConnectionIdFrameLog>(f->sequence_number));
      break;
    }
    // Ack Frequency Frame
    case QuicFrameType::ACK_FREQUENCY_FRAME: {
      QuicAckFrequencyFrame* f = static_cast<QuicAckFrequencyFrame*>(frame);
      event->frames_.push_back(std::make_unique<AckFrequencyFrameLog>(
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
    const QuicVersionNegotiationPacket& version_negotiation_packet,
    uint64_t packet_size,
    bool is_packet_recvd) {
  auto event = std::make_unique<QLogVersionNegotiationEvent>();
  event->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packet_size_ = packet_size;
  event->event_type_ =
      is_packet_recvd ? QLogEventType::PACKET_RECEIVED : QLogEventType::PACKET_SENT;
  event->packet_type_ = kVersionNegotiationPacketType;
  event->version_log_ = std::make_unique<VersionNegotiationLog>(
      VersionNegotiationLog(version_negotiation_packet.versions));
  report_summary_.total_packets_recvd++;
  report_summary_.total_bytes_recvd += packet_size;
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    const std::string new_connection_id,
    uint64_t packet_size,
    bool is_packet_recvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packet_size_ = packet_size;
  event->event_type_ =
      is_packet_recvd ? QLogEventType::PACKET_RECEIVED : QLogEventType::PACKET_SENT;
  event->packet_type_ = kQuicPublicResetPacketType;
  report_summary_.total_packets_recvd++;
  report_summary_.total_bytes_recvd += packet_size;
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    const QuicPublicResetPacket& public_reset_packet,
    uint64_t packet_size,
    bool is_packet_recvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packet_size_ = packet_size;
  event->event_type_ =
      is_packet_recvd ? QLogEventType::PACKET_RECEIVED : QLogEventType::PACKET_SENT;
  event->packet_type_ = kQuicPublicResetPacketType;
  report_summary_.total_packets_recvd++;
  report_summary_.total_bytes_recvd += packet_size;
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEventImpl(
    uint64_t packet_number,
    uint64_t packet_length,
    TransmissionType transmission_type,
    EncryptionLevel encryption_level,
    const QuicFrames& retransmittable_frames,
    const QuicFrames& nonretransmittable_frames,
    bool is_packet_recvd) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  event->packet_num_ = packet_number;
  event->packet_size_ = packet_length;
  event->event_type_ =
      is_packet_recvd ? QLogEventType::PACKET_RECEIVED : QLogEventType::PACKET_SENT;
  if (encryption_level >= ENCRYPTION_FORWARD_SECURE) {
    event->packet_type_ = std::string(kShortHeaderPacketType);
  } else {
    event->packet_type_ =
        std::string(toQlogString(encryptionLevelToLongHeaderType(encryption_level)));
  }
  event->transmission_type_ =
      std::string(toQlogString(transmission_type));

  report_summary_.total_packets_sent++;
  report_summary_.total_bytes_sent += packet_length;

  for (const QuicFrame& frame : retransmittable_frames) {
    void* fv = getFrameType(frame);
    if (fv != NULL) {
      addPacketFrameImpl(event.get(), frame.type, fv, is_packet_recvd);
    }
  }
  for (const QuicFrame& frame : nonretransmittable_frames) {
    void* fv = getFrameType(frame);
    if (fv != NULL) {
      addPacketFrameImpl(event.get(), frame.type, fv, is_packet_recvd);
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
          fv = (void*)&frame.window_update_frame;
          break;
      case QuicFrameType::BLOCKED_FRAME:
          fv = (void*)&frame.blocked_frame;
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
          fv = (void*)&frame.path_response_frame;
          break;
      case QuicFrameType::PATH_CHALLENGE_FRAME:
          fv = (void*)&frame.path_challenge_frame;
          break;
      case QuicFrameType::STOP_SENDING_FRAME:
          fv = (void*)&frame.stop_sending_frame;
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

void BaseQLogger::getVideoFrameEndTime(QuicStreamFrame* frame) { 
  auto it = sid_first_frame_msg_map_.find(frame->stream_id);
  if (it == sid_first_frame_msg_map_.end() || it->second.send_frame_end_time != std::chrono::microseconds::zero()) {
    return;
  }
  auto& video_frame = it->second;
  if ((video_frame.size + video_frame.stream_offset) <= frame->offset + frame->data_length &&
      video_frame.send_frame_end_time == std::chrono::microseconds::zero()) {
    video_frame.send_frame_end_time = end_time_;
  }
}

} // namespace quic
