#pragma once

#include <memory>
#include <string>
#include <vector>

#include "base/bvc-qlog/src/qlogger_constants.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "gquiche/quic/core/quic_stream.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/quic_versions.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/core/quic_error_codes.h"
#include "gquiche/quic/core/frames/quic_ack_frame.h"

#include "third_party/rapidjson/include/rapidjson/document.h"
#include "third_party/rapidjson/include/rapidjson/writer.h"
#include "third_party/rapidjson/include/rapidjson/stringbuffer.h"

namespace quic {
/**
 * Application error codes are opaque to QUIC transport.  Each application
 * protocol can define its own error codes.
 */
using namespace rapidjson;

class QLogFrame {
 public:
  QLogFrame() = default;
  virtual ~QLogFrame() = default;
  virtual Document ToJson() const = 0;
  virtual Document toShortJson() const;
};

class PaddingFrameLog : public QLogFrame {
 public:
  PaddingFrameLog() = default;
  ~PaddingFrameLog() override = default;
  Document ToJson() const override;
  Document toShortJson() const override;
};

class RstStreamFrameLog : public QLogFrame {
 public:
  QuicStreamId stream_id_;
  QuicRstStreamErrorCode error_code_;
  uint64_t offset_;

  RstStreamFrameLog(
      QuicStreamId stream_id_in,
      QuicRstStreamErrorCode error_code_in,
      QuicStreamOffset offset_in)
      : stream_id_{stream_id_in}, error_code_{error_code_in}, offset_{offset_in} {}

  ~RstStreamFrameLog() override = default;
  Document ToJson() const override;
};

class ConnectionCloseFrameLog : public QLogFrame {
 public:
  QuicConnectionCloseType close_type_;
  uint64_t wire_error_code_;
  QuicErrorCode quic_error_code_;
  std::string error_details_;
  uint64_t transport_close_frame_type_;

  ConnectionCloseFrameLog(
      QuicConnectionCloseType close_type_in,
      uint64_t wire_error_code_in,
      QuicErrorCode quic_error_code_in,
      std::string error_details_in,
      uint64_t transport_close_frame_type_in)
      : close_type_{close_type_in},
        wire_error_code_{wire_error_code_in},
	      quic_error_code_{quic_error_code_in},
        error_details_(error_details_in),
        transport_close_frame_type_{transport_close_frame_type_in} {}

  ~ConnectionCloseFrameLog() override = default;
  Document ToJson() const override;
};

class GoAwayFrameLog : public QLogFrame {
 public:
  QuicErrorCode error_code_;
  QuicStreamId last_good_streamId_;
  std::string  reason_phrase_;

  GoAwayFrameLog(
      QuicErrorCode error_code_in,
      QuicStreamId last_good_stream_id_in,
      std::string reason_phrase_in)
      : error_code_{error_code_in},
        last_good_streamId_{last_good_stream_id_in},
        reason_phrase_{reason_phrase_in} {}

  ~GoAwayFrameLog() override = default;
  Document ToJson() const override;
};

class WindowUpdateFrameLog : public QLogFrame {
 public:
  QuicStreamId stream_id_;
  uint64_t max_data_;

  WindowUpdateFrameLog(
      QuicStreamId stream_id_in,
      uint64_t maxDataIn)
      : stream_id_{stream_id_in},
	max_data_{maxDataIn} {}

  ~WindowUpdateFrameLog() override = default;
  Document ToJson() const override;
};

class BlockedFrameLog : public QLogFrame {
 public:
  QuicStreamId stream_id_;

  BlockedFrameLog(QuicStreamId stream_id_in)
  : stream_id_{stream_id_in} {}

  ~BlockedFrameLog() override = default;
  Document ToJson() const override;
};

class StopWaitingFrameLog : public QLogFrame {
 public:
  StopWaitingFrameLog() = default;
  ~StopWaitingFrameLog() override = default;
  Document ToJson() const override;
};

class PingFrameLog : public QLogFrame {
 public:
  PingFrameLog() = default;
  ~PingFrameLog() override = default;
  Document ToJson() const override;
};

class AckFrameLog : public QLogFrame {
 public:
  PacketNumberQueue packet_number_queue_;
  std::chrono::microseconds ack_delay_;

  AckFrameLog(
      const PacketNumberQueue packet_number_queue_in,
      uint64_t ack_delay_in)
      : packet_number_queue_{packet_number_queue_in}, ack_delay_{ack_delay_in} {}
  ~AckFrameLog() override = default;
  Document ToJson() const override;
  Document toShortJson() const override;
};

class StreamFrameLog : public QLogFrame {
 public:
  QuicStreamId stream_id_;
  uint64_t offset_;
  uint64_t len_;
  bool fin_;

  StreamFrameLog(
      QuicStreamId stream_id_in,
      uint64_t offset_in,
      uint64_t len_in,
      bool fin_in)
      : stream_id_{stream_id_in}, offset_{offset_in}, len_{len_in}, fin_{fin_in} {}
  ~StreamFrameLog() override = default;

  Document ToJson() const override;
  Document toShortJson() const;
};

class CryptoFrameLog : public QLogFrame {
 public:
  EncryptionLevel level_;
  uint64_t offset_;
  uint64_t data_length_;

  CryptoFrameLog(
      EncryptionLevel level_in,
      uint64_t offset_in,
      uint64_t dataLength_in)
      : level_{level_in}, offset_{offset_in}, data_length_{dataLength_in} {}
  ~CryptoFrameLog() override = default;
  Document ToJson() const override;
};

class HandshakeDoneFrameLog : public QLogFrame {
 public:
  HandshakeDoneFrameLog() = default;
  ~HandshakeDoneFrameLog() override = default;
  Document ToJson() const override;
};

class MTUDiscoveryFrameLog : public QLogFrame {
 public:
  MTUDiscoveryFrameLog() = default;
  ~MTUDiscoveryFrameLog() override = default;
  Document ToJson() const override;
};

class NewConnectionIdFrameLog : public QLogFrame {
 public:
  std::string new_connection_id_;
  uint64_t sequence_number_;

  NewConnectionIdFrameLog(
      std::string new_connection_id_in,
      uint64_t sequence_number_in)
      : new_connection_id_{new_connection_id_in}, sequence_number_{sequence_number_in} {}

  ~NewConnectionIdFrameLog() override = default;
  Document ToJson() const override;
};

class MaxStreamsFrameLog : public QLogFrame {
 public:
  uint64_t stream_count_;
  bool unidirectional_;

  MaxStreamsFrameLog(
      uint64_t stream_count_in,
      bool unidirectional_in)
      : stream_count_{stream_count_in}, unidirectional_{unidirectional_in} {}

  ~MaxStreamsFrameLog() override = default;
  Document ToJson() const override;
};

class StreamsBlockedFrameLog : public QLogFrame {
 public:
  uint64_t stream_count_;
  bool unidirectional_;

  StreamsBlockedFrameLog(
      uint64_t stream_count_in,
      bool unidirectional_in)
      : stream_count_{stream_count_in}, unidirectional_{unidirectional_in} {}

  ~StreamsBlockedFrameLog() override = default;
  Document ToJson() const override;
};

class PathResponseFrameLog : public QLogFrame {
 public:
  std::string path_data_;

  explicit PathResponseFrameLog(std::string path_data_in) : path_data_{path_data_in} {}
  ~PathResponseFrameLog() override = default;
  Document ToJson() const override;
};

class PathChallengeFrameLog : public QLogFrame {
 public:
  std::string path_data_;

  explicit PathChallengeFrameLog(std::string path_data_in) : path_data_{path_data_in} {}
  ~PathChallengeFrameLog() override = default;
  Document ToJson() const override;
};

class StopSendingFrameLog : public QLogFrame {
 public:
  QuicStreamId stream_id_;
  QuicRstStreamErrorCode error_code_;

  StopSendingFrameLog(QuicStreamId stream_id_in, QuicRstStreamErrorCode error_code_in)
      : stream_id_{stream_id_in}, error_code_{error_code_in} {}
  ~StopSendingFrameLog() override = default;
  Document ToJson() const override;
};

class MessageFrameLog : public QLogFrame {
 public:
  uint32_t message_id_;
  uint64_t length_;

  MessageFrameLog(uint32_t message_id_in, uint64_t length_in)
      : message_id_{message_id_in}, length_{length_in} {}
  ~MessageFrameLog() override = default;
  Document ToJson() const override;
};

class NewTokenFrameLog : public QLogFrame {
 public:
  NewTokenFrameLog() = default;
  ~NewTokenFrameLog() override = default;
  Document ToJson() const override;
};

class RetireConnectionIdFrameLog : public QLogFrame {
 public:
  uint64_t sequence_number_;

  RetireConnectionIdFrameLog(uint64_t sequence_number_in)
  : sequence_number_(sequence_number_in) {}

  ~RetireConnectionIdFrameLog() override = default;
  Document ToJson() const override;
};

class AckFrequencyFrameLog : public QLogFrame {
 public:
  uint64_t sequence_number_;
  uint64_t packet_tolerance_;
  uint64_t update_max_ack_delay_;
  bool ignore_order_;

  explicit AckFrequencyFrameLog(
      uint64_t sequence_number_in,
      uint64_t packet_tolerance_in,
      uint64_t update_max_ack_delay_in,
      bool ignore_order_in)
      : sequence_number_(sequence_number_in),
        packet_tolerance_(packet_tolerance_in),
        update_max_ack_delay_(update_max_ack_delay_in),
        ignore_order_(ignore_order_in) {}
  ~AckFrequencyFrameLog() override = default;
  Document ToJson() const override;
};

class VersionNegotiationLog {
 public:
  std::vector<ParsedQuicVersion> versions_;

  explicit VersionNegotiationLog(const std::vector<ParsedQuicVersion>& versions_in)
      : versions_{versions_in} {}
  ~VersionNegotiationLog() = default;
  Document ToJson() const;
};

enum class QLogEventType : uint32_t {
  PACKET_RECEIVED,
  PACKET_SENT,
  CONNECTION_CLOSE,
  TRANSPORT_SUMMARY,
  CONGESTION_METRIC_UPDATE,
  PACING_METRIC_UPDATE,
  APPIDLE_UPDATE,
  PACKET_DROP,
  DATAGRAM_RECEIVED,
  LOSS_ALARM,
  PACKET_LOST,
  TRANSPORT_STATE_UPDATE,
  Packet_Buffered,
  PACKET_ACK,
  METRIC_UPDATE,
  STREAM_STATE_UPDATE,
  PACING_OBSERVATION,
  APP_LIMITED_UPDATE,
  BANDWIDTH_ESTUPDATE,
  CONNECTION_MIGRATION,
  PATH_VALIDATION,
  PRIORITY_UPDATE,
  FRAMES_PROCESSED,
  REQUEST_OVER_STREAM
};

quiche::QuicheStringPiece ToString(QLogEventType type_);

class QLogEvent {
 public:
  QLogEvent() = default;
  virtual ~QLogEvent() = default;
  virtual Document ToJson() const = 0;
  std::chrono::microseconds ref_time_;
  QLogEventType event_type_;
};

class QLogFramesProcessed : public QLogEvent {
 public:
  QLogFramesProcessed() = default;
  ~QLogFramesProcessed() override = default;
  quiche::QuicheStringPiece weaver_;
  QuicFrameType frames_type_;
  std::vector<std::unique_ptr<QLogFrame>> frames_;
  std::vector<uint64_t>  packet_sizes_;
  std::vector<uint64_t> packet_nums_;
  std::vector<std::chrono::microseconds> time_drifts_;
  std::string packet_type_;
  Document ToJson() const override;
};

class QLogPacketEvent : public QLogEvent {
 public:
  QLogPacketEvent() = default;
  ~QLogPacketEvent() override = default;
  std::vector<std::unique_ptr<QLogFrame>> frames_;
  std::string packet_type_;
  std::string transmission_type_;
  uint64_t packet_num_{0};
  uint64_t packet_size_{0};
  Document ToJson() const override;
};

class QLogVersionNegotiationEvent : public QLogEvent {
 public:
  QLogVersionNegotiationEvent() = default;
  ~QLogVersionNegotiationEvent() override = default;
  std::unique_ptr<VersionNegotiationLog> version_log_;
  std::string packet_type_;
  uint64_t packet_size_{0};

  Document ToJson() const override;
};

class QLogRetryEvent : public QLogEvent {
 public:
  QLogRetryEvent() = default;
  ~QLogRetryEvent() override = default;

  std::string packet_type_;
  uint64_t packet_size_{0};
  uint64_t token_size_{0};

  Document ToJson() const override;
};

class QLogConnectionCloseEvent : public QLogEvent {
 public:
  QLogConnectionCloseEvent(
      QuicErrorCode error_in,
      std::string reason_in,
      ConnectionCloseSource source_in,
      std::chrono::microseconds ref_time_in);
  ~QLogConnectionCloseEvent() override = default;
  QuicErrorCode error_;
  std::string reason_;
  ConnectionCloseSource source_;

  Document ToJson() const override;
};

struct TransportSummaryArgs {
  uint64_t total_bytes_sent{};
  uint64_t total_bytes_recvd{};
  uint64_t sum_cur_write_offset{};
  uint64_t sum_max_observed_offset{};
  uint64_t sum_cur_stream_buffer_len{};
  uint64_t total_packets_lost{};
  uint64_t total_startup_duration{};
  uint64_t total_drain_duration{};
  uint64_t total_probebw_Duration{};
  uint64_t total_probertt_duration{};
  uint64_t total_not_recovery_duration{};
  uint64_t total_growth_duration{};
  uint64_t total_conservation_duration{};
  uint64_t total_stream_bytes_cloned{};
  uint64_t total_bytes_cloned{};
  uint64_t total_crypto_data_written{};
  uint64_t total_crypto_data_recvd{};
  uint64_t current_writable_bytes{};
  uint64_t current_conn_flow_control{};
  bool used_zero_rtt{};
  double smoothed_min_rtt{};
  double smoothed_max_bandwidth{};
  float startup_suration_ratio{};
  float drain_duration_ratio{};
  float probebw_duration_ratio{};
  float probertt_duration_ratio{};
  float not_recovery_duration_ratio{};
  float growth_duration_ratio{};
  float conservation_duration_ratio{};
  float average_difference{};
};

class QLogTransportSummaryEvent : public QLogEvent {
 public:
  QLogTransportSummaryEvent(
      uint64_t total_bytes_sent,
      uint64_t total_packets_sent,
      uint64_t total_bytes_recvd,
      uint64_t total_packets_recvd,
      uint64_t sum_cur_write_offset,
      uint64_t sum_max_observed_offset,
      uint64_t sum_cur_stream_buffer_len,
      uint64_t total_packets_lost,
      uint64_t total_startup_duration,
      uint64_t total_drain_duration,
      uint64_t total_probebw_Duration,
      uint64_t total_probertt_duration,
      uint64_t total_not_recovery_duration,
      uint64_t total_growth_duration,
      uint64_t total_conservation_duration,
      uint64_t total_stream_bytes_cloned,
      uint64_t total_bytes_cloned,
      uint64_t total_crypto_data_written,
      uint64_t total_crypto_data_recvd,
      uint64_t current_writable_bytes,
      uint64_t current_conn_flow_control,
      bool used_zero_rtt,
      QuicTransportVersion version,
      CongestionControlType congestion_type,
      double smoothed_min_rtt,
      double smoothed_max_bandwidth,
      float startup_suration_ratio,
      float drain_duration_ratio,
      float probebw_duration_ratio,
      float probertt_duration_ratio,
      float not_recovery_duration_ratio,
      float growth_duration_ratio,
      float conservation_duration_ratio,
      float average_difference,
      std::chrono::microseconds ref_time);
  ~QLogTransportSummaryEvent() override = default;
  uint64_t total_bytes_sent;
  uint64_t total_packets_sent;
  uint64_t total_bytes_recvd;
  uint64_t total_packets_recvd;
  uint64_t sum_cur_write_offset;
  uint64_t sum_max_observed_offset;
  uint64_t sum_cur_stream_buffer_len;
  uint64_t total_packets_lost;
  uint64_t total_startup_duration;
  uint64_t total_drain_duration;
  uint64_t total_probebw_Duration;
  uint64_t total_probertt_duration;
  uint64_t total_not_recovery_duration;
  uint64_t total_growth_duration;
  uint64_t total_conservation_duration;
  uint64_t total_stream_bytes_cloned;
  uint64_t total_bytes_cloned;
  uint64_t total_crypto_data_written;
  uint64_t total_crypto_data_recvd;
  uint64_t current_writable_bytes;
  uint64_t current_conn_flow_control;
  bool used_zero_rtt;
  QuicTransportVersion quic_version;
  CongestionControlType congestion_type;
  double smoothed_min_rtt;
  double smoothed_max_bandwidth;
  float startup_suration_ratio;
  float drain_duration_ratio;
  float probebw_duration_ratio;
  float probertt_duration_ratio;
  float not_recovery_duration_ratio;
  float growth_duration_ratio;
  float conservation_duration_ratio;
  float average_difference;
  Document ToJson() const override;
};

class QLogBBRCongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogBBRCongestionMetricUpdateEvent(
      uint64_t bytes_in_flight_in,
      uint64_t current_cwnd_in,
      std::string congestion_event_in,
      quic::CongestionControlType type_in,
      void* state_in,
      std::chrono::microseconds ref_time_in);
  ~QLogBBRCongestionMetricUpdateEvent() override = default;
  uint64_t bytes_inflight_;
  uint64_t current_cwnd_;
  std::string congestion_event_;
  quic::CongestionControlType type_;
  void* state;

  Document ToJson() const override;
};

class QLogCubicCongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogCubicCongestionMetricUpdateEvent(
      uint64_t bytes_in_flight_in,
      uint64_t current_cwnd_in,
      std::string congestion_event_in,
      quic::CongestionControlType type_in,
      void* state_in,
      std::chrono::microseconds ref_time_in);
  ~QLogCubicCongestionMetricUpdateEvent() override = default;
  uint64_t bytes_inflight_;
  uint64_t current_cwnd_;
  std::string congestion_event_;
  quic::CongestionControlType type_;
  void* state;
  Document ToJson() const override;
};

class QLogBBR2CongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogBBR2CongestionMetricUpdateEvent(
      uint64_t bytes_in_flight_in,
      uint64_t current_cwnd_in,
      std::string congestion_event_in,
      quic::CongestionControlType type_in,
      void* state_in,
      std::chrono::microseconds ref_time_in);
  ~QLogBBR2CongestionMetricUpdateEvent() override = default;
  uint64_t bytes_inflight_;
  uint64_t current_cwnd_;
  std::string congestion_event_;
  quic::CongestionControlType type_;
  void* state;
  Document ToJson() const override;
};

class QLogAppLimitedUpdateEvent : public QLogEvent {
 public:
  explicit QLogAppLimitedUpdateEvent(
      bool limited_in,
      std::chrono::microseconds ref_time_in);
  ~QLogAppLimitedUpdateEvent() override = default;

  Document ToJson() const override;

  bool limited;
};

class QLogBandwidthEstUpdateEvent : public QLogEvent {
 public:
  explicit QLogBandwidthEstUpdateEvent(
      uint64_t bytes,
      std::chrono::microseconds interval,
      std::chrono::microseconds ref_time_in);
  ~QLogBandwidthEstUpdateEvent() override = default;

  Document ToJson() const override;

  uint64_t bytes_;
  std::chrono::microseconds interval_;
};

class QLogPacingMetricUpdateEvent : public QLogEvent {
 public:
  QLogPacingMetricUpdateEvent(
      uint64_t pacing_burst_size,
      std::chrono::microseconds pacing_interval,
      std::chrono::microseconds ref_time);
  ~QLogPacingMetricUpdateEvent() override = default;
  uint64_t pacing_burst_size_;
  std::chrono::microseconds pacing_interval_;

  Document ToJson() const override;
};

class QLogPacingObservationEvent : public QLogEvent {
 public:
  QLogPacingObservationEvent(
      std::string& actual_in,
      std::string& expect_in,
      std::string& conclusion_in,
      std::chrono::microseconds ref_time_in);
  std::string actual_;
  std::string expect_;
  std::string conclusion_;

  ~QLogPacingObservationEvent() override = default;
  Document ToJson() const override;
};

class QLogAppIdleUpdateEvent : public QLogEvent {
 public:
  QLogAppIdleUpdateEvent(
      std::string& idle_event,
      bool idle,
      std::chrono::microseconds ref_time);
  ~QLogAppIdleUpdateEvent() override = default;
  std::string idle_event_;
  bool idle_;

  Document ToJson() const override;
};

class QLogPacketDropEvent : public QLogEvent {
 public:
  QLogPacketDropEvent(
      size_t packet_size,
      std::string& drop_reason,
      std::chrono::microseconds ref_time);
  ~QLogPacketDropEvent() override = default;
  size_t packet_size_;
  std::string drop_reason_;

  Document ToJson() const override;
};

class QLogDatagramReceivedEvent : public QLogEvent {
 public:
  QLogDatagramReceivedEvent(
      uint64_t data_len,
      std::chrono::microseconds ref_time);
  ~QLogDatagramReceivedEvent() override = default;
  uint64_t data_len_;

  Document ToJson() const override;
};

class QLogLossAlarmEvent : public QLogEvent {
 public:
  QLogLossAlarmEvent(
      uint64_t largest_sent,
      uint64_t alarm_count,
      uint64_t outstanding_packets,
      std::string& type,
      std::chrono::microseconds ref_time);
  ~QLogLossAlarmEvent() override = default;
  uint64_t largest_sent_;
  uint64_t alarm_count_;
  uint64_t outstanding_packets_;
  std::string type_;
  Document ToJson() const override;
};

class QLogPacketLostEvent : public QLogEvent {
 public:
  QLogPacketLostEvent(
      uint64_t lost_packet_num,
      EncryptionLevel level,
      TransmissionType type,
      std::chrono::microseconds ref_time);
  ~QLogPacketLostEvent() override = default;
  uint64_t lost_packet_num_;
  EncryptionLevel encryption_level_;
  TransmissionType transmission_type_;
  Document ToJson() const override;
};

class QLogTransportStateUpdateEvent : public QLogEvent {
 public:
  QLogTransportStateUpdateEvent(
      std::string& update,
      std::chrono::microseconds ref_time);
  ~QLogTransportStateUpdateEvent() override = default;
  std::string update_;
  Document ToJson() const override;
};

class QLogPacketBufferedEvent : public QLogEvent {
 public:
  QLogPacketBufferedEvent(
      uint64_t packet_num,
      EncryptionLevel encryption_level,
      uint64_t packet_size,
      std::chrono::microseconds ref_time);
  ~QLogPacketBufferedEvent() override = default;
  uint64_t packet_num_;
  EncryptionLevel encryption_level_;
  uint64_t packet_size_;
  Document ToJson() const override;
};

class QLogPacketAckEvent : public QLogEvent {
 public:
  QLogPacketAckEvent(
      PacketNumberSpace packet_num_space,
      uint64_t packet_num,
      std::chrono::microseconds ref_time);
  ~QLogPacketAckEvent() override = default;
  PacketNumberSpace packet_num_space_;
  uint64_t packet_num_;
  Document ToJson() const override;
};

class QLogMetricUpdateEvent : public QLogEvent {
 public:
  QLogMetricUpdateEvent(
      std::chrono::microseconds latest_rtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ack_delay,
      std::chrono::microseconds ref_time);
  ~QLogMetricUpdateEvent() override = default;
  std::chrono::microseconds latest_rtt_;
  std::chrono::microseconds mrtt_;
  std::chrono::microseconds srtt_;
  std::chrono::microseconds ack_delay_;
  Document ToJson() const override;
};

class QLogStreamStateUpdateEvent : public QLogEvent {
 public:
  QLogStreamStateUpdateEvent(
      QuicStreamId id,
      std::string& update,
      quiche::QuicheOptionalImpl<std::chrono::milliseconds> time_since_stream_creation,
      VantagePoint vantage_point,
      std::chrono::microseconds ref_time);
  ~QLogStreamStateUpdateEvent() override = default;
  QuicStreamId id_;
  std::string update_;
  quiche::QuicheOptionalImpl<std::chrono::milliseconds> time_since_stream_creation_;
  Document ToJson() const override;

 private:
  VantagePoint vantagePoint_;
};

class QLogConnectionMigrationEvent : public QLogEvent {
 public:
  QLogConnectionMigrationEvent(
      bool intentional_migration,
      VantagePoint vantage_point,
      std::chrono::microseconds ref_time);

  ~QLogConnectionMigrationEvent() override = default;

  Document ToJson() const override;

  bool intentional_Migration_;
  VantagePoint vantagePoint_;
};

class QLogPathValidationEvent : public QLogEvent {
 public:
  // The VantagePoint represents who initiates the path validation (sends out
  // Path Challenge).
  QLogPathValidationEvent(
      bool success,
      VantagePoint vantage_point,
      std::chrono::microseconds ref_time);

  ~QLogPathValidationEvent() override = default;

  Document ToJson() const override;
  bool success_;
  VantagePoint vantagePoint_;
};

class QLogPriorityUpdateEvent : public QLogEvent {
 public:
  explicit QLogPriorityUpdateEvent(
      QuicStreamId id,
      uint8_t urgency,
      bool incremental,
      std::chrono::microseconds ref_time_in);
  ~QLogPriorityUpdateEvent() override = default;

  Document ToJson() const override;

 private:
  QuicStreamId streamId_;
  uint8_t urgency_;
  bool incremental_;
};

class QLogRequestOverStreamEvent : public QLogEvent {
 public:
  QLogRequestOverStreamEvent(
    std::string method_in,
    QuicStreamId stream_id_in,
    std::string uri_in,
    std::string range_in,
    std::chrono::microseconds ref_time_in);
  ~QLogRequestOverStreamEvent() override = default;

  QuicStreamId stream_id_;
  std::string method_;
  std::string uri_;
  std::string range_;

  Document ToJson() const override;
};

} // namespace quic
