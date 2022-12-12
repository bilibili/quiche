#pragma once
#include <unordered_map>
 
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "gquiche/quic/core/quic_stream.h"
#include "gquiche/quic/core/quic_connection_id.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/quic_versions.h"
#include "gquiche/quic/core/quic_types.h"
#include "platform/quiche_platform_impl/quiche_optional_impl.h"

namespace quic {

struct PacingObserver {
  PacingObserver() = default;
  virtual ~PacingObserver() = default;
  virtual void OnNewPacingRate(
      uint64_t packets_per_interval,
      std::chrono::microseconds interval) = 0;
  virtual void OnPacketSent() = 0;
};

class QLogger {
 public:
  explicit QLogger(VantagePoint vantage_point_in, std::string protocol_type_in)
      : vantagePoint_(vantage_point_in), protocolType_(std::move(protocol_type_in)) {}

  quiche::QuicheOptionalImpl<QuicConnectionId> dcid_;
  quiche::QuicheOptionalImpl<QuicConnectionId> scid_;
  VantagePoint vantagePoint_;
  std::string protocolType_;
  QLogger() = delete;
  virtual ~QLogger() = default;
  virtual void AddPacket(
      const std::string& new_connection_id,
      uint64_t packet_size,
      bool is_packet_recvd) = 0;
  virtual void AddPacket(
      const QuicPublicResetPacket& public_reset_packet,
      uint64_t packet_size,
      bool is_packet_recvd) = 0;
  virtual void AddPacket(
      const QuicVersionNegotiationPacket& version_negotiation_packet,
      uint64_t packet_size,
      bool is_packet_recvd) = 0;
  virtual void AddConnectionClose(
      QuicErrorCode error,
      const std::string& reason,
      ConnectionCloseSource source) = 0;
  struct TransportSummaryArgs {
    uint64_t total_bytes_sent{}; // bvc observed
    uint64_t total_packets_sent{}; // bvc observed
    uint64_t total_bytes_recvd{}; // bvc observed
    uint64_t total_packets_recvd{}; // bvc observed
    uint64_t sum_cur_write_offset{};
    uint64_t sum_max_observed_offset{};
    uint64_t sum_cur_stream_buffer_len{};
    uint64_t total_packets_lost{}; // bvc observed
    uint64_t total_startup_duration{}; // bvc observed
    uint64_t total_drain_duration{}; // bvc observed
    uint64_t total_probebw_Duration{}; // bvc observed
    uint64_t total_probertt_duration{}; // bvc observed
    uint64_t total_not_recovery_duration{}; // bvc observed
    uint64_t total_growth_duration{}; // bvc observed
    uint64_t total_conservation_duration{}; // bvc observed
    uint64_t total_stream_bytes_cloned{};
    uint64_t total_bytes_cloned{};
    uint64_t total_crypto_data_written{};
    uint64_t total_crypto_data_recvd{};
    uint64_t current_writable_bytes{};
    uint64_t current_conn_flow_control{};
    double smoothed_max_bandwidth{};
    double smoothed_min_rtt{};
    double smoothed_mean_deviation{};
    bool used_zero_rtt{false}; // bvc observed
    QuicTransportVersion quic_version{}; // bvc observed
    CongestionControlType congestion_control{}; // bvc observed
  };

  virtual void AddTransportSummary(const TransportSummaryArgs& args) = 0;
  virtual void AddBBRCongestionMetricUpdate(
      uint64_t bytes_inflight,
      uint64_t current_cwnd,
      const std::string& congestion_event,
      quic::CongestionControlType type,
      void* state) = 0;
  virtual void AddCubicCongestionMetricUpdate(
      uint64_t bytes_inflight,
      uint64_t current_cwnd,
      const std::string& congestion_event,
      quic::CongestionControlType type,
      void* state) = 0;
  virtual void AddBBR2CongestionMetricUpdate(
      uint64_t bytes_inflight,
      uint64_t current_cwnd,
      const std::string& congestion_event,
      quic::CongestionControlType type,
      void* state) = 0;
  virtual void AddBandwidthEstUpdate(
      uint64_t bytes,
      std::chrono::microseconds interval) = 0;
  virtual void AddAppLimitedUpdate() = 0;
  virtual void AddAppUnlimitedUpdate() = 0;
  virtual void AddPacingMetricUpdate(
      uint64_t pacing_burst_size_in,
      std::chrono::microseconds pacing_interval_in) = 0;
  virtual void AddPacingObservation(
      std::string& actual,
      std::string& expected,
      std::string& conclusion) = 0;
  virtual void AddAppIdleUpdate(std::string& idle_event, bool idle) = 0;
  virtual void AddPacketDrop(size_t packet_size, std::string& drop_reason_in) = 0;
  virtual void AddDatagramReceived(uint64_t data_len) = 0;
  virtual void AddLossAlarm(
      uint64_t largest_sent,
      uint64_t alarm_count,
      uint64_t outstanding_packets,
      std::string& type) = 0;
  virtual void AddPacketLost(
      uint64_t lost_packet_num,
      EncryptionLevel level_,
      TransmissionType type) = 0;
  virtual void AddTransportStateUpdate(std::string& update) = 0;
  virtual void AddPacketBuffered(
      uint64_t packet_num,
      EncryptionLevel protection_type,
      uint64_t packet_size) = 0;
  virtual void AddMetricUpdate(
      std::chrono::microseconds ,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ack_delay) = 0;
  virtual void AddStreamStateUpdate(
      quic::QuicStreamId stream_id,
      std::string& update,
      quiche::QuicheOptionalImpl<std::chrono::milliseconds> time_since_stream_creation) = 0;
  virtual void AddConnectionMigrationUpdate(bool intentional_migration) = 0;
  virtual void AddPathValidationEvent(bool success) = 0;
  virtual void AddPriorityUpdate(
      quic::QuicStreamId stream_id,
      uint8_t urgency,
      bool incremental) = 0;

  virtual void SetDcid(quiche::QuicheOptionalImpl<QuicConnectionId> cid, const std::string& self_address, const std::string& peer_address) = 0;
  virtual void SetScid(quiche::QuicheOptionalImpl<QuicConnectionId> cid) = 0;
  virtual void SetQuicVersion(const QuicTransportVersion version) = 0;
  virtual void SetCongestionType(const CongestionControlType type) = 0;
  virtual void UsedZeroRtt(bool use) = 0;
  TransportSummaryArgs report_summary_;
  std::unordered_map<std::size_t, std::size_t> stream_map_;
};

std::string GetFlowControlEvent(int offset);

std::string GetRxStreamWU(QuicStreamId stream_id, uint64_t packet_num, uint64_t maximumData);

std::string GetRxConnWU(uint64_t packet_num, uint64_t maximumData);

std::string GetPeerClose(const std::string& errMsg);

std::string GetFlowControlWindowAvailable(uint64_t windowAvailable);

std::string GetClosingStream(const std::string& stream_id);

} // namespace quic
