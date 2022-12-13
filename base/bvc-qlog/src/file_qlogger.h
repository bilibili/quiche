/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once
#include <fstream>
#include <sstream>
#include <vector>
#include <memory>
#include <unordered_map>
#include <regex>

#include "base/bvc-qlog/src/base_qlogger.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "base/bvc-qlog/src/qlogger_types.h"
#include "base/sinks/sequence_file_sink.h"

#include "gquiche/quic/core/quic_stream.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/quic_types.h"
#include "gquiche/quic/core/quic_connection_id.h"
#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

using namespace rapidjson;

namespace quic {

class FileQLogger : public BaseQLogger {
 public:
  using QLogger::TransportSummaryArgs;
  std::vector<std::unique_ptr<QLogEvent>> logs_;
    FileQLogger(
      VantagePoint vantage_point_in,
      std::string path,
      std::string final_path,      
      std::shared_ptr<spdlog::details::thread_pool> tp,
      std::size_t max_size,
      std::size_t max_file,
      uint64_t init_cwnd,
      std::size_t log_event_buffer = 0,
      uint64_t switch_qlog_index = 0,
      std::string protocol_type_in = kHTTP3ProtocolType,
      bool pretty_json = false,
      bool streaming = true)
      : BaseQLogger(vantage_point_in, std::move(protocol_type_in)),
        path_(std::move(path)),
        tp_(tp),
        log_event_buffer_(log_event_buffer),
        final_path_(std::move(final_path)),
        max_size_(max_size),
        max_file_(max_file),
        init_cwnd_(init_cwnd),
        switch_qlog_index_(switch_qlog_index),
        switch_spdlog_index_(0),
        aggregate_(true),	
        pretty_json_(pretty_json),
        streaming_(streaming) {}

  ~FileQLogger() override {
    if (qlog_frames_processed_ != nullptr) {
      HandleEvent(std::move(qlog_frames_processed_));
    }
    if (streaming_ && !dcid_->IsEmpty()) {
      FinishStream();
    }
  }

  // retry packet (client)
  void AddPacket(const std::string& new_connection_id, uint64_t packet_size, bool is_packet_recvd) {}
  // public reset packet
  void AddPacket(const QuicPublicResetPacket& public_reset_packet, uint64_t packet_size, bool is_packet_recvd);
  // version negotiation packet
  void AddPacket(
      const QuicVersionNegotiationPacket& version_negotiation_packet,
      uint64_t packet_size,
      bool is_packet_recvd);
  // ietf stateless reset packet (client)
  void AddPacket(const QuicIetfStatelessResetPacket& ietfStatelessResetPacket, uint64_t packet_size, bool is_packet_recvd) {}
  void AddPacketFrame(
      QLogPacketEvent* event,
      QuicFrameType frame_type,
      void* frame,
      bool is_packet_recvd);
  // data packet received
  std::unique_ptr<QLogPacketEvent> CreatePacketEvent(
      const QuicPacketHeader& packet_header,
      uint64_t packet_size,
      bool is_packet_recvd);
  void FinishCreatePacketEvent(std::unique_ptr<QLogPacketEvent> event);
  // serialized packet to be sent
  void AddPacket(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool is_packet_recvd);

  void FramesProcessed(
     const QuicPacketHeader& packet_header,
      uint64_t packet_size,
      bool is_packet_recvd);

  void AddConnectionClose(
      QuicErrorCode error,
      const std::string& reason,
      ConnectionCloseSource source) override;
  void AddTransportSummary(const TransportSummaryArgs& args) override;
  void AddBBRCongestionMetricUpdate(
      uint64_t bytes_inflight,
      uint64_t current_cwnd,
      const std::string& congestion_event,
      CongestionControlType type,
      void* state) override;
  void AddCubicCongestionMetricUpdate(
      uint64_t bytes_inflight,
      uint64_t current_cwnd,
      const std::string& congestion_event,
      CongestionControlType type,
      void* state) override;
  void AddBBR2CongestionMetricUpdate(
      uint64_t bytes_inflight,
      uint64_t current_cwnd,
      const std::string& congestion_event,
      CongestionControlType type,
      void* state) override;
  void AddPacingMetricUpdate(
      uint64_t pacing_burst_size_in,
      std::chrono::microseconds pacing_interval_in) override;
  void AddPacingObservation(
      std::string& actual,
      std::string& expected,
      std::string& conclusion) override;
  void AddBandwidthEstUpdate(uint64_t bytes, std::chrono::microseconds interval)
      override;
  void AddAppLimitedUpdate() override;
  void AddAppUnlimitedUpdate() override;
  void AddAppIdleUpdate(std::string& idle_event, bool idle) override;
  void AddPacketDrop(size_t packet_size, std::string& drop_reason_in) override;
  void AddDatagramReceived(uint64_t data_len) override;
  void AddLossAlarm(
      uint64_t largest_sent,
      uint64_t alarm_count,
      uint64_t outstanding_packets,
      std::string& type) override;
  void AddPacketLost(
      uint64_t lost_packet_num,
      EncryptionLevel level,
      TransmissionType type) override;
  void AddTransportStateUpdate(std::string& update) override;
  void AddPacketBuffered(
      uint64_t packet_num,
      EncryptionLevel protection_type,
      uint64_t packet_size) override;
  void AddMetricUpdate(
      std::chrono::microseconds latest_rtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ack_delay) override;
  void AddStreamStateUpdate(
      QuicStreamId id,
      std::string& update,
      quiche::QuicheOptionalImpl<std::chrono::milliseconds> time_since_stream_creation)
      override;
  virtual void AddConnectionMigrationUpdate(bool intentional_migration) override;
  virtual void AddPathValidationEvent(bool success) override;
  void AddPriorityUpdate(
      quic::QuicStreamId stream_id,
      uint8_t urgency,
      bool incremental) override;

  void OutputLogsToFile(const std::string& path, bool pretty_json);
  Document ToJson();
  void ToJsonBase(Document& j, Document& trace);
  Document GenerateSummary(
      size_t num_events,
      std::chrono::microseconds start_time,
      std::chrono::microseconds end_time);

  void SetDcid(quiche::QuicheOptionalImpl<QuicConnectionId> cid, const std::string& self_address, const std::string& peer_address) override;
  void SetScid(quiche::QuicheOptionalImpl<QuicConnectionId> cid) override;
  void SetQuicVersion(const QuicTransportVersion version) override;
  void SetCongestionType(const CongestionControlType type) override;
  void UsedZeroRtt(bool use) override;

  void GenerateIndexMap();
  void AddSummary(Value& value, Document::AllocatorType& summary_allocator);
  void AddMapInSummary(Value& value, Value& tmp_document, Document::AllocatorType& tmp_allocator);

  void InitialSummary();
  void UpdateSummary();
  void SummaryReportOnAlarm();
  void SwitchSpdlogObject(const std::string& tmp_path, const std::string& final_path, uint64_t switch_qlog_index);

#ifdef QLOG_FOR_QBONE
  void GenerateQboneReport(Document& summary);
  void (*metricsQboneCallback)(float lost_ratio);
  void (*writeLogQboneCallback)(const int priority, const int event_id,
                                const std::string& msg1, const std::string& msg2, const std::string& msg3,
                                const std::string& msg4, const std::string& msg5, uint32_t msg6, uint32_t msg7);
#else
  void GetUriOfStream(std::string& method, QuicStreamId id, std::string& request_uri, std::string& range, std::string& trid);
  void SetFirstFrame(QuicStreamId id, unsigned long long int size, quic::QuicStreamOffset stream_offset, std::string trid, std::string protocol, uint64_t request_index, std::chrono::microseconds receive_request_time);
  void AddBBRSummary(Value& value, Document::AllocatorType& summary_allocator);
  void AddBBR2Summary(Value& value, Document::AllocatorType& summary_allocator);
  void AddCubicSummary(Value& value, Document::AllocatorType& summary_allocator);  
  void WriteLogCallbackByDuration(size_t report_id_for_7000, size_t report_id_for_8000);
  void GetCallbackIdByDuration(size_t& report_id_for_7000, size_t& report_id_for_8000);  
  void GenerateBvcReport(Document& summary);
  void AlarmReport(Document& summary);
  void (*packetlostCallback)(float lost_ratio, CongestionControlType type);
  void (*minrttCallback)(float min_rtt, CongestionControlType type);
  void (*meandeviationCallback)(float meandeviation, CongestionControlType type);
  void (*bandwidthCallback)(float bandwidth, CongestionControlType type);
  void (*metricsCallback)(float lost_ratio);
  void (*emptyCallback)(CongestionControlType type);
  void (*firstFrameCallback)(uint64_t first_frame_size, uint64_t first_frame_completed_time, uint64_t init_cwnd, std::string& protocol_type);
  void (*writeLogCallback)(const int priority, 
                           const int event_id,
                           ...);
#endif

 private:
  void GenerateFirstFrameReport();
  void CreateBaseJson();
  void SetFileObject();
  void SetSpdlogObject();
  void SetupStream();
  void FinishStream();
  void HandleEvent(std::unique_ptr<QLogEvent> event);

  std::string path_;
  std::string basePadding_ = "  ";
  std::string eventsPadding_ = "";
  std::string eventLine_;
  std::string token_;
  std::string endLine_;
  std::string metadata_head_;
  std::stringstream baseJson_;
  std::string metadata_head_extra_;
  StringBuffer buffer_;
  Writer<StringBuffer> writer_;  
  std::string  logstring_;  

  std::string error_;
  std::string reason_;
  std::string source_;

  std::ofstream fileObj_;
  std::shared_ptr<spdlog::async_logger> logger_; 
  std::shared_ptr<spdlog::details::thread_pool> tp_;

  std::size_t log_event_buffer_; 

  std::string final_path_;  
  std::size_t max_size_; 
  std::size_t max_file_;
  uint64_t init_cwnd_;
  uint64_t switch_qlog_index_;
  uint64_t switch_spdlog_index_;  
  std::shared_ptr<Document> pre_summary_;
  std::shared_ptr<Document> last_summary_;
  std::shared_ptr<quic::QuicMutex> lock_;

#ifndef QLOG_FOR_QBONE
  mutable std::vector<std::pair<std::string, std::vector<int>>> uri_map_;
  mutable std::vector<std::string> trid_;
#endif

  // For aggregation use
  QuicFrameType last_type_;
  std::string self_address_;
  std::string peer_address_;
  bool aggregate_;
  std::unique_ptr<QLogFramesProcessed> qlog_frames_processed_;
  std::string packet_type_now_;

  //current BBR mode timestamp to calculate time
  std::chrono::microseconds current_bbr_mode_timestamp_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());
  //current BBR2 mode timestamp to calculate time
  std::chrono::microseconds current_bbr2_mode_timestamp_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());
  //current BBR state timestamp to calculate time
  std::chrono::microseconds current_state_timestamp_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());

  BbrSender::Mode current_bbrmode_ = BbrSender::Mode::STARTUP;
  Bbr2Mode current_bbr2mode_ = Bbr2Mode::STARTUP;
  //current BBR state used to distinguish
  BbrSender::RecoveryState current_state_ = BbrSender::RecoveryState::NOT_IN_RECOVERY;

  double smoothed_mean_deviation_ = 0;
  double sum_of_mean_deviation_ = 0;
  double smoothed_max_bandwidth_ = 0;
  double smoothed_min_rtt_ = 0;
  double num_of_congestion_message_ = 0;
//for calculate each qlog's congestion message
#if 0
  double smoothed_mean_deviation_for_now_ = 0;
  double sum_of_mean_deviation_for_now_ = 0;
  double smoothed_max_bandwidth_for_now_ = 0;
  double smoothed_min_rtt_for_now_ = 0;
  double pre_num_of_congestion_message_ = 0;
#endif

  std::unordered_map<std::string, double> index_map_;

  CongestionControlType congestion_type_;
  bool pretty_json_;
  bool streaming_;
  int num_events_ = 0;
  size_t pos_;
  std::string first_frame_pre_range_;
};
} // namespace quic
