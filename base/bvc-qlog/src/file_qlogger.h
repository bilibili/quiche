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
  std::vector<std::unique_ptr<QLogEvent>> logs;
    FileQLogger(
      VantagePoint vantagePointIn,
      std::string& path,     
      std::shared_ptr<spdlog::details::thread_pool> tp,
      std::size_t log_event_buffer = 0,
      std::string protocolTypeIn = kHTTP3ProtocolType,
      bool prettyJson = false,
      bool streaming = true)
      : BaseQLogger(vantagePointIn, std::move(protocolTypeIn)),
        path_(path),
        tp_(tp),
        log_event_buffer_(log_event_buffer),
        prettyJson_(prettyJson),
        streaming_(streaming) {}

  ~FileQLogger() override {
    if (streaming_ && !dcid_->IsEmpty()) {
      finishStream();
    }
  }

  // retry packet (client)
  void addPacket(const std::string& newConnectionId, uint64_t packetSize, bool isPacketRecvd) {}
  // public reset packet
  void addPacket(const QuicPublicResetPacket& publicResetPacket, uint64_t packetSize, bool isPacketRecvd);
  // version negotiation packet
  void addPacket(
      const QuicVersionNegotiationPacket& versionNegotiationPacket,
      uint64_t packetSize,
      bool isPacketRecvd);
  // ietf stateless reset packet (client)
  void addPacket(const QuicIetfStatelessResetPacket& ietfStatelessResetPacket, uint64_t packetSize, bool isPacketRecvd) {}
  void addPacketFrame(
      QLogPacketEvent* event,
      QuicFrameType frame_type,
      void* frame,
      bool isPacketRecvd);
  // data packet received
  std::unique_ptr<QLogPacketEvent> createPacketEvent(
      const QuicPacketHeader& packetHeader,
      uint64_t packetSize,
      bool isPacketRecvd);
  void finishCreatePacketEvent(std::unique_ptr<QLogPacketEvent> event);
  // serialized packet to be sent
  void addPacket(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool isPacketRecvd);

  void addConnectionClose(
      QuicErrorCode error,
      const std::string& reason,
      ConnectionCloseSource source) override;
  void addPacingMetricUpdate(
      uint64_t pacingBurstSizeIn,
      std::chrono::microseconds pacingIntervalIn) override;
  void addPacingObservation(
      std::string& actual,
      std::string& expected,
      std::string& conclusion) override;
  void addBandwidthEstUpdate(uint64_t bytes, std::chrono::microseconds interval)
      override;
  void addAppLimitedUpdate() override;
  void addAppUnlimitedUpdate() override;
  void addAppIdleUpdate(std::string& idleEvent, bool idle) override;
  void addPacketDrop(size_t packetSize, std::string& dropReasonIn) override;
  void addDatagramReceived(uint64_t dataLen) override;
  void addLossAlarm(
      uint64_t largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string& type) override;
  void addPacketLost(
      uint64_t LostPacketNum,
      EncryptionLevel level,
      TransmissionType type) override;
  void addTransportStateUpdate(std::string& update) override;
  void addPacketBuffered(
      uint64_t packetNum,
      EncryptionLevel protectionType,
      uint64_t packetSize) override;
  void addMetricUpdate(
      std::chrono::microseconds latestRtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ackDelay) override;
  void addStreamStateUpdate(
      QuicStreamId id,
      std::string& update,
      quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreation)
      override;
  virtual void addConnectionMigrationUpdate(bool intentionalMigration) override;
  virtual void addPathValidationEvent(bool success) override;
  void addPriorityUpdate(
      quic::QuicStreamId streamId,
      uint8_t urgency,
      bool incremental) override;

  void outputLogsToFile(const std::string& path, bool prettyJson);
  Document toJson();
  void toJsonBase(Document& j, Document& trace);
  Document generateSummary(
      size_t numEvents,
      std::chrono::microseconds endTime);

  void setDcid(quiche::QuicheOptionalImpl<QuicConnectionId> connID) override;
  void setScid(quiche::QuicheOptionalImpl<QuicConnectionId> connID) override;
  void setQuicVersion(const QuicTransportVersion version) override;
  void usedZeroRtt(bool use) override;

  void addSummary(Value& value, Document::AllocatorType& summary_allocator);

  void initialSummary();
  void switchSpdlogObject(const std::string& tmp_path, const std::string& final_path, uint64_t switch_qlog_index);

 private:
  void createBaseJson();
  void setFileObject();
  void setSpdlogObject();
  void setupStream();
  void finishStream();
  void handleEvent(std::unique_ptr<QLogEvent> event);

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

  uint64_t connection_duration_;
  bool prettyJson_;
  bool streaming_;
  int numEvents_ = 0;
  size_t pos_;
};
} // namespace quic
