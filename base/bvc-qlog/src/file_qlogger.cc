#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <syslog.h>

#include "base/bvc-qlog/src/file_qlogger.h"
#include "gquiche/quic/platform/api/quic_logging.h"

#include "absl/strings/str_cat.h"

using namespace spdlog;

namespace quic {


void FileQLogger::setDcid(quiche::QuicheOptionalImpl<QuicConnectionId> connID) {
  if (!connID->IsEmpty()) {
    dcid_ = connID;
    if (streaming_) {
      setFileObject();
      setupStream();
    }
  }
}

void FileQLogger::setScid(quiche::QuicheOptionalImpl<QuicConnectionId> connID) {
  if (!connID->IsEmpty()) {
    scid_ = connID;
  }
}

void FileQLogger::setQuicVersion(const QuicTransportVersion version) {
   summary_.quicVersion = version;
}

void FileQLogger::usedZeroRtt(bool use) {
  summary_.usedZeroRtt = use;
}

void FileQLogger::initialSummary() {
  Document initial_summary;
  connection_duration_ = (numEvents_ == 0) ? 0 : (double)endTime_.count()/1000;
  initial_summary.SetObject();
  auto duration = (numEvents_ == 0) ? (std::chrono::microseconds)0 : (std::chrono::microseconds)endTime_.count()/1000; 
  initial_summary = generateSummary(numEvents_, duration);
  
  Document copy_summary;
  copy_summary.CopyFrom(initial_summary, copy_summary.GetAllocator());
}

void FileQLogger::createBaseJson() {
  if (!metadata_head_.empty() && !metadata_head_extra_.empty()) {
    return;
  }
  // Create the base json
  Document qLog, traces;
  qLog.SetObject(); 
  traces.SetObject();
  toJsonBase(qLog, traces);
  Value& traces_value = qLog["traces"];
  traces_value.PushBack(traces, traces.GetAllocator());
  
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  qLog.Accept(writer);
  std::string base_Json = buffer.GetString();

  baseJson_.clear();
  if (prettyJson_) {
    baseJson_ << std::setw(4) << base_Json;
  } else {
    baseJson_ << base_Json;
  }
  // start copying from base to outputFile, stop at events
  metadata_head_.clear();
  metadata_head_extra_.clear();
  baseJson_.seekg(0, baseJson_.beg);
  token_ = prettyJson_ ? "\"events\": [" : "\"events\":[";
  while (getline(baseJson_, eventLine_)) {
    pos_ = eventLine_.find(token_);
    if (pos_ == std::string::npos) {
      absl::StrAppend(&metadata_head_, eventLine_);
    } else {
      // Found the token
      for (char c : eventLine_) {
        // get the amount of spaces each event should be padded
        eventsPadding_.clear();
        if (c == ' ') {
          eventsPadding_ += ' ';
        } else {
          break;
        }
      }
      // get metadata 
      absl::StrAppend(&metadata_head_, eventLine_.substr(0, pos_ + token_.size()));
      absl::StrAppend(&metadata_head_extra_, eventLine_.substr(pos_ + token_.size(),  eventLine_.size() - pos_ - token_.size() - (prettyJson_ ? 0 : 1)), ",");
      break;
    }
  }
}

void FileQLogger::setFileObject() {
  absl::StrAppend(&path_, "/", dcid_->ToString(), ".qlog");
  if(!spdlog::details::os::path_exists(path_)) {
    spdlog::details::os::create_dir(spdlog::details::os::dir_name(path_));
  }

  if(fileObj_.is_open()) {
    fileObj_.close();
  }
  fileObj_.open(path_, std::fstream::out);
}

void FileQLogger::setSpdlogObject() {
  auto file_sink = std::make_shared<sinks::basic_file_sink_st>(path_, true);
  auto formatter = std::make_unique<pattern_formatter>("%v", pattern_time_type::local, std::string(""));
  logger_ = std::make_shared<async_logger>(dcid_->ToString(), std::move(file_sink), tp_, async_overflow_policy::block);  
  logger_->set_formatter(std::move(formatter));
}

void FileQLogger::setupStream() {
  // create the output file
  if (dcid_->IsEmpty()) {
    QUIC_LOG(ERROR) << "Error: No dcid found";
    return;
  }
  endLine_ = prettyJson_ ? "\n" : "";
  initialSummary();

  if (fileObj_) {
    createBaseJson();    
    setSpdlogObject();
    logger_->info(metadata_head_);
  }
}

void FileQLogger::finishStream() {
  connection_duration_ = (numEvents_ == 0) ? 0 : (double)endTime_.count()/1000;
  Document summaryJson = generateSummary(numEvents_, endTime_);

  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  summaryJson.Accept(writer);
  std::string summary = buffer.GetString();
  
  if (fileObj_) {
    // logger remaining event
    if(log_event_buffer_ != 0 && !logstring_.empty()) {
      logger_->info(logstring_);
    }
    // finish copying the line that was stopped on
    std::string tail;
    if (!prettyJson_) {
      absl::StrAppend(&tail, metadata_head_extra_);
    } else {
      // copy all the remaining lines but the last one
      std::string previousLine = eventsPadding_ + metadata_head_extra_;
      while (getline(baseJson_, eventLine_)) {
        absl::StrAppend(&tail, endLine_, previousLine);
        previousLine = eventLine_;
      }
    }
    std::stringstream summaryBuffer;
    std::string line;
    if (prettyJson_) {
      absl::StrAppend(&tail, basePadding_, "\"summary\" : ");
      summaryBuffer << summary;
    } else {
      absl::StrAppend(&tail, "\"summary\":");
      summaryBuffer << summary;
    }

    std::string summaryPadding = "";
    // add padding to every line in the summary except the first
    while (getline(summaryBuffer, line)) {
      absl::StrAppend(&tail, summaryPadding, line, endLine_);
      summaryPadding = basePadding_;
    }
    absl::StrAppend(&tail, "}");
    logger_->info(tail);
    logger_->flush();
    fileObj_.close();
  }
}

void FileQLogger::handleEvent(std::unique_ptr<QLogEvent> event) {
  if (streaming_) {
    ++numEvents_;
    Document eventjson = event->toJson();

    buffer_.Clear();
    writer_.Reset(buffer_);
    eventjson.Accept(writer_);
    std::string event_json = buffer_.GetString();
    if (fileObj_) {
      std::stringstream eventBuffer;
      std::string line;
      if (prettyJson_) {
        eventBuffer << std::setw(4) << event_json;
      } else {
        eventBuffer << event_json;
      }

      if (numEvents_ > 1) {
        absl::StrAppend(&logstring_, ",");
      }
      // add padding to every line in the event
      while (getline(eventBuffer, line)) {
        absl::StrAppend(&logstring_, endLine_, basePadding_, eventsPadding_, line);
      }

      if(log_event_buffer_ == 0 || numEvents_ % log_event_buffer_ == 0) {
        logger_->info(logstring_);
        logstring_.clear();
      }
    }
  } else {
    logs.push_back(std::move(event));
  }
}

void FileQLogger::addPacket(
    const QuicPublicResetPacket& publicResetPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(createPacketEventImpl(publicResetPacket, packetSize, isPacketRecvd));
}

void FileQLogger::addPacket(
    const QuicVersionNegotiationPacket& versionNegotiationPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(createPacketEventImpl(versionNegotiationPacket, packetSize, isPacketRecvd));
}

void FileQLogger::addPacket(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool isPacketRecvd) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(createPacketEventImpl(packet_number, packet_length, transmission_type, encryption_level, retransmittable_frames, nonretransmittable_frames, isPacketRecvd));
}

std::unique_ptr<QLogPacketEvent> FileQLogger::createPacketEvent(
    const QuicPacketHeader& packetHeader,
    uint64_t packetSize,
    bool isPacketRecvd) {
  return createPacketEventImpl(packetHeader, packetSize, isPacketRecvd);
}

void FileQLogger::addPacketFrame(
    QLogPacketEvent* event,
    QuicFrameType frame_type,
    void* frame,
    bool isPacketRecvd) {
      // aggregation switch
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  addPacketFrameImpl(event, frame_type, frame, isPacketRecvd);
  return;
}

void FileQLogger::finishCreatePacketEvent(std::unique_ptr<QLogPacketEvent> event) {
  if (event->frames.size() == 0) {
    return;
  }
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::move(event));
}

void FileQLogger::addConnectionClose(
    QuicErrorCode error,
    const std::string& reason,
    ConnectionCloseSource source) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  error_ = QuicErrorCodeToString(error);
  reason_ = reason;
  source_ = ConnectionCloseSourceToString(source);
  handleEvent(std::make_unique<quic::QLogConnectionCloseEvent>(
      error,
      reason,
      source,
      refTime));
}

void FileQLogger::addBandwidthEstUpdate(
    uint64_t bytes,
    std::chrono::microseconds interval) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogBandwidthEstUpdateEvent>(
      bytes,
      interval,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_));
}

void FileQLogger::addAppLimitedUpdate() {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogAppLimitedUpdateEvent>(
      true,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_));
}

void FileQLogger::addAppUnlimitedUpdate() {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogAppLimitedUpdateEvent>(
      false,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_));
}

void FileQLogger::addPacingMetricUpdate(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogPacingMetricUpdateEvent>(
      pacingBurstSizeIn, pacingIntervalIn, refTime));
}

void FileQLogger::addPacingObservation(
    std::string& actual,
    std::string& expect,
    std::string& conclusion) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogPacingObservationEvent>(
      actual, expect, conclusion, refTime));
}

void FileQLogger::addAppIdleUpdate(std::string& idleEvent, bool idle) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogAppIdleUpdateEvent>(
      idleEvent, idle, refTime));
}

void FileQLogger::addPacketDrop(size_t packetSize, std::string& dropReason) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogPacketDropEvent>(
      packetSize, dropReason, refTime));
}

void FileQLogger::addDatagramReceived(uint64_t dataLen) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(
      std::make_unique<quic::QLogDatagramReceivedEvent>(dataLen, refTime));
}

void FileQLogger::addLossAlarm(
    uint64_t largestSent,
    uint64_t alarmCount,
    uint64_t outstandingPackets,
    std::string& type) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogLossAlarmEvent>(
      largestSent, alarmCount, outstandingPackets, type, refTime));
}

void FileQLogger::addPacketLost(
    uint64_t LostPacketNum,
    EncryptionLevel level,
    TransmissionType type) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  summary_.totalPacketsLost++;
  handleEvent(std::make_unique<quic::QLogPacketLostEvent>(
      LostPacketNum, level, type, refTime));
}

void FileQLogger::addTransportStateUpdate(std::string& update) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogTransportStateUpdateEvent>(
      update, refTime));
}

void FileQLogger::addPacketBuffered(
    uint64_t packetNum,
    EncryptionLevel protectionType,
    uint64_t packetSize) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogPacketBufferedEvent>(
      packetNum, protectionType, packetSize, refTime));
}

void FileQLogger::addMetricUpdate(
    std::chrono::microseconds latestRtt,
    std::chrono::microseconds mrtt,
    std::chrono::microseconds srtt,
    std::chrono::microseconds ackDelay) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
	std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogMetricUpdateEvent>(
      latestRtt, mrtt, srtt, ackDelay, refTime));
}

Document FileQLogger::toJson() {
  Document j, trace;
  j.SetObject(); 
  trace.SetObject();

  toJsonBase(j, trace);
  Value& traces_value = j["traces"];
  traces_value.PushBack(trace, trace.GetAllocator()); 


  if (logs.size() > 0) {
    Document summaryJson = generateSummary(logs.size(), logs.back()->refTime);
    j.AddMember("summary", summaryJson, j.GetAllocator());
  }

  // convert stored logs into json event array
  Value value;
  value.SetArray();
  for (auto& event : logs) {
    Value event_json;
    event_json.CopyFrom(event->toJson(), j.GetAllocator());
    value.PushBack(event_json, j.GetAllocator());
  }

  j["traces"]["events"] = value;
  return j;
}

void FileQLogger::toJsonBase(Document& j, Document& traces) {

  Document::AllocatorType& j_allocator = j.GetAllocator();
  Document::AllocatorType& traces_allocator = traces.GetAllocator();
  
  j.AddMember(Value(kQLogDescriptionField, j_allocator).Move(), 
              Value(kQLogDescription, j_allocator).Move(), 
              j_allocator);

  j.AddMember(Value(kQLogVersionField, j_allocator).Move(), 
              Value(kQLogVersion, j_allocator).Move(), 
              j_allocator);

  j.AddMember(Value(kQLogTitleField, j_allocator).Move(), 
              Value(kQLogTitle, j_allocator).Move(), 
              j_allocator);
  Value event_fields;
  j.AddMember("qlog_format", "JSON", j_allocator);

  Value value;
  value.SetArray();
  j.AddMember("traces", value, j_allocator);

  // trace[common_fields]
  std::string dcidStr = (!dcid_ || dcid_->IsEmpty()) ? "" : dcid_->ToString();
  std::string scidStr = (!scid_ || scid_->IsEmpty()) ? "" : scid_->ToString();
  value.SetObject();
  value.AddMember( "dcid", Value(dcidStr.c_str(), traces_allocator).Move(), traces_allocator); 
  value.AddMember( "protocol_type", Value(protocolType_.c_str(), traces_allocator).Move(), traces_allocator); 
  value.AddMember( "reference_time", system_startTime_.count(), traces_allocator); 
  value.AddMember( "scid", Value(scidStr.c_str(), traces_allocator).Move(), traces_allocator); 
  traces.AddMember("common_fields", value, traces_allocator);

  event_fields.SetArray();
  event_fields.PushBack("relative_time", traces_allocator);
  event_fields.PushBack("category", traces_allocator);
  event_fields.PushBack("event", traces_allocator);
  event_fields.PushBack("data", traces_allocator);
  traces.AddMember("event_fields", event_fields, traces_allocator);

  value.SetObject();
  value.AddMember( "time_offset", 0, traces_allocator); 
  value.AddMember( "time_units", Value(kQLogTimeUnits, traces_allocator).Move(), traces_allocator); 
  traces.AddMember("configuration", value, traces_allocator);

  traces.AddMember("description", Value(kQLogTraceDescription, traces_allocator).Move(), traces_allocator);

  value.SetArray();
  traces.AddMember("events", value, traces_allocator);
  traces.AddMember("title", Value(kQLogTraceTitle, traces_allocator).Move(), traces_allocator);

  char host[100] = {0};
  gethostname(host, sizeof(host));

  value.SetObject();
  value.AddMember( "type", Value(vantagePointString(vantagePoint_).data(), traces_allocator).Move(), traces_allocator);
  value.AddMember( "name", Value(host, traces_allocator).Move(), traces_allocator); 
  traces.AddMember("vantage_point", value, traces_allocator);
}

void FileQLogger::addSummary(Value& value, Document::AllocatorType& summary_allocator) {
  value.AddMember("total_bytes_sent", summary_.totalBytesSent, summary_allocator);
  value.AddMember("total_packets_sent", summary_.totalPacketsSent, summary_allocator);
  value.AddMember("total_bytes_recvd", summary_.totalBytesRecvd, summary_allocator);
  value.AddMember("total_packets_recvd", summary_.totalPacketsRecvd, summary_allocator);
  value.AddMember("total_packets_lost", summary_.totalPacketsLost, summary_allocator);
  value.AddMember("quic_transport_version", Value(QuicVersionToString(summary_.quicVersion).c_str(), summary_allocator).Move(), summary_allocator);
  value.AddMember("connection_duration", ((int)(connection_duration_ * 100 + 0.5)) / 100.0, summary_allocator);  
}

Document FileQLogger::generateSummary(
    size_t numEvents,
    std::chrono::microseconds endTime) {
  Document summaryObj;
  summaryObj.SetObject();
  Document::AllocatorType& summary_allocator = summaryObj.GetAllocator();
  
  Value key, value;
  key.SetString(StringRef(kQLogTraceCountField));  
  value.SetInt(1);  
  summaryObj.AddMember(key, value, summary_allocator); // hardcoded, we only support 1 trace right now

  // is calculated like this : if there is <= 1 event, summary [max_duration] is 0
  // otherwise, it is the (time of the last event - time of the  first event)
  key.SetString(StringRef("max_duration"));  
  value.SetInt64((numEvents == 0) ? 0 : endTime.count());
  summaryObj.AddMember(key, value, summary_allocator);  

  key.SetString(StringRef("total_event_count"));  
  value.SetInt64(numEvents);
  summaryObj.AddMember(key, value, summary_allocator);

  // summaryObj [report_summary] 
  value.SetObject();
  addSummary(value, summary_allocator);
  summaryObj.AddMember("report_summary", value, summary_allocator);

  return summaryObj;
}

void FileQLogger::addStreamStateUpdate(
    quic::QuicStreamId id,
    std::string& update,
    quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreation) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogStreamStateUpdateEvent>(
      id,
      update,
      std::move(timeSinceStreamCreation),
      vantagePoint_,
      refTime));
}

void FileQLogger::addConnectionMigrationUpdate(bool intentionalMigration) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogConnectionMigrationEvent>(
      intentionalMigration, vantagePoint_, refTime));
}

void FileQLogger::addPathValidationEvent(bool success) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogPathValidationEvent>(
      success, vantagePoint_, refTime));
}

void FileQLogger::addPriorityUpdate(
    quic::QuicStreamId streamId,
    uint8_t urgency,
    bool incremental) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  endTime_ = refTime;
  handleEvent(std::make_unique<quic::QLogPriorityUpdateEvent>(
      streamId, urgency, incremental, refTime));
}

void FileQLogger::outputLogsToFile(const std::string& path, bool prettyJson) {
  if (streaming_) {
    return;
  }
  if (dcid_->IsEmpty()) {
    QUIC_LOG(ERROR) << "Error: No dcid_ found";
    return;
  }

  std::string outputPath;
  absl::StrAppend(&outputPath, path, "/", dcid_->ToString(), ".qlog");
  std::ofstream fileObj;
  fileObj.open(outputPath, std::fstream::out);

  if (fileObj) {
    Document qLog = toJson();
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    qLog.Accept(writer);
    std::string base_Json = buffer.GetString();
    if (prettyJson) {
      fileObj << std::setw(4) << base_Json;
    } else {
      fileObj << base_Json;
    }
  } else {
    QUIC_LOG(ERROR) << "Error: Can't write to provided path: " << path;
  }
  fileObj.close();
}

} // namespace quic
