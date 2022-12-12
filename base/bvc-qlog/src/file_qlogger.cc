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


void FileQLogger::SetDcid(quiche::QuicheOptionalImpl<QuicConnectionId> cid, const std::string& self_address, const std::string& peer_address) {
  if (!cid->IsEmpty()) {
    dcid_ = cid;
    if (streaming_) {
      self_address_ = self_address;
      peer_address_ = peer_address.substr(0, peer_address.find(":"));
      SetFileObject();
      SetupStream();
    }
  }
}

void FileQLogger::SetScid(quiche::QuicheOptionalImpl<QuicConnectionId> cid) {
  if (!cid->IsEmpty()) {
    scid_ = cid;
  }
}

void FileQLogger::SetQuicVersion(const QuicTransportVersion version) {
   report_summary_.quic_version = version;
}

void FileQLogger::SetCongestionType(const CongestionControlType type) {
   congestion_type_ = type;
}

void FileQLogger::UsedZeroRtt(bool use) {
  report_summary_.used_zero_rtt = use;
}

#ifndef QLOG_FOR_QBONE
void FileQLogger::GetUriOfStream(
  std::string& method, QuicStreamId id, std::string& request_uri, std::string& range, std::string& trid) {
  std::vector<std::pair<std::string, std::vector<int>>>::iterator it;
  for (it = uri_map_.begin(); it != uri_map_.end(); it++) {
    if (request_uri.compare((*it).first) == 0) {
      it->second.push_back(id);
      break;
    }
  }
  if (it == uri_map_.end()) {
    uri_map_.push_back(std::make_pair(request_uri,std::vector<int>{static_cast<int>(id)}));
  }

  if (!trid.empty()) {
    std::vector<std::string>::iterator it = find(trid_.begin(), trid_.end(), trid);
    if (it == trid_.end()) {
      trid_.push_back(trid);
    }
  }
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogRequestOverStreamEvent>(
    method, id, request_uri, range, ref_time));
}

void FileQLogger::SetFirstFrame(QuicStreamId id, unsigned long long int size, quic::QuicStreamOffset stream_offset, std::string trid, std::string protocol, uint64_t request_index, std::chrono::microseconds receive_request_time) {
  BaseQLogger::FrameMsg tmp_frame = {size, stream_offset, trid, protocol, request_index, receive_request_time, std::chrono::microseconds::zero()};
  sid_first_frame_msg_map_.insert({id, tmp_frame});
}
#endif

void FileQLogger::InitialSummary() {
  Document initial_summary;
  GenerateIndexMap();
  initial_summary.SetObject();
  Document::AllocatorType& summary_allocator = initial_summary.GetAllocator();

  Value value;
  uint32_t duration = (num_events_ == 0) ? 0 : end_time_.count()/1000;

  value.SetInt(1);  
  initial_summary.AddMember(Value(kQLogTraceCountField, summary_allocator).Move(), 
                            value, 
                            summary_allocator); 

  value.SetInt64(duration);
  initial_summary.AddMember("max_duration", value, summary_allocator);  

  value.SetInt64(num_events_);
  initial_summary.AddMember("total_event_count", value, summary_allocator);  

  value.SetObject();
  AddSummary(value, summary_allocator);
  initial_summary.AddMember("report_summary", value, summary_allocator);
  AddMapInSummary(value, initial_summary, summary_allocator);

  Document copy_summary;
  copy_summary.CopyFrom(initial_summary, copy_summary.GetAllocator());
  pre_summary_ = std::make_shared<Document>(std::move(initial_summary));
  last_summary_ = std::make_shared<Document>(std::move(copy_summary));
}

void FileQLogger::UpdateSummary() {
  lock_->WriterLock();
  GenerateIndexMap();
  uint32_t duration = (num_events_ == 0) ? 0 : end_time_.count()/1000;
  Document tmp_document;
  tmp_document.SetObject();
  Document::AllocatorType& tmp_allocator = tmp_document.GetAllocator();

  Value value;

  value.SetInt(1);  
  tmp_document.AddMember(Value(kQLogTraceCountField, tmp_allocator).Move(), value, tmp_allocator);
  
  value.SetInt64(duration);
  tmp_document.AddMember("max_duration", value, tmp_allocator);  

  value.SetInt64(num_events_);
  tmp_document.AddMember("total_event_count", value, tmp_allocator);

  value.SetObject();
  AddSummary(value, tmp_allocator);
  tmp_document.AddMember("report_summary", value, tmp_allocator);
  AddMapInSummary(value, tmp_document, tmp_allocator);

  *last_summary_ = std::move(tmp_document);
  lock_->WriterUnlock(); 
}

void FileQLogger::SummaryReportOnAlarm() {
  GenerateIndexMap();
  Document summaryJson = GenerateSummary(num_events_, steady_startTime_, end_time_);
#ifndef QLOG_FOR_QBONE
  AlarmReport(summaryJson);
#else
  GenerateQboneReport(summaryJson);
#endif
}

void FileQLogger::CreateBaseJson() {
  if (!metadata_head_.empty() && !metadata_head_extra_.empty()) {
    return;
  }
  // Create the base json
  Document qLog, traces;
  qLog.SetObject(); 
  traces.SetObject();
  ToJsonBase(qLog, traces);
  Value& traces_value = qLog["traces"];
  traces_value.PushBack(traces, traces.GetAllocator());
  
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  qLog.Accept(writer);
  std::string base_Json = buffer.GetString();

  baseJson_.clear();
  if (pretty_json_) {
    baseJson_ << std::setw(4) << base_Json;
  } else {
    baseJson_ << base_Json;
  }
  // start copying from base to outputFile, stop at events
  metadata_head_.clear();
  metadata_head_extra_.clear();
  baseJson_.seekg(0, baseJson_.beg);
  token_ = pretty_json_ ? "\"events\": [" : "\"events\":[";
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
      absl::StrAppend(&metadata_head_extra_, eventLine_.substr(pos_ + token_.size(),  eventLine_.size() - pos_ - token_.size() - (pretty_json_ ? 0 : 1)), ",");
      break;
    }
  }
}

void FileQLogger::SwitchSpdlogObject(const std::string& tmp_path, const std::string& final_path, uint64_t switch_qlog_index) {
  path_ = tmp_path;
  SetFileObject();

  if (!fileObj_) {
    logger_.reset();
  } else {
    final_path_ = final_path;
    switch_qlog_index_ = switch_qlog_index;
    switch_spdlog_index_++;
    SetupStream(); 
  }
}

void FileQLogger::SetFileObject() {
  absl::StrAppend(&path_, "/", dcid_->ToString(), ".qlog");
  if(!spdlog::details::os::path_exists(path_)) {
    spdlog::details::os::create_dir(spdlog::details::os::dir_name(path_));
  }

  if(fileObj_.is_open()) {
    fileObj_.close();
  }
  fileObj_.open(path_, std::fstream::out);
}

void FileQLogger::SetSpdlogObject() {
  auto file_sink = std::make_shared<sinks::sequence_file_sink_st>(path_, final_path_, max_size_, max_file_, metadata_head_, metadata_head_extra_, last_summary_, pre_summary_, lock_);
  auto formatter = std::make_unique<pattern_formatter>("%v", pattern_time_type::local, std::string(""));
  logger_ = std::make_shared<async_logger>(dcid_->ToString(), std::move(file_sink), tp_, async_overflow_policy::block);  
  logger_->set_formatter(std::move(formatter));
}

void FileQLogger::SetupStream() {
  // create the output file
  if (dcid_->IsEmpty()) {
    QUIC_LOG(ERROR) << "Error: No dcid found";
    return;
  }
  endLine_ = pretty_json_ ? "\n" : "";

  absl::StrAppend(&final_path_, "/", dcid_->ToString(), "_", switch_qlog_index_, "_", switch_spdlog_index_,".qlog");  
  if (lock_ == nullptr) {
    lock_ = std::make_shared<quic::QuicMutex>();
  }
  InitialSummary();

  if (fileObj_) {
    CreateBaseJson();    
    SetSpdlogObject();
    logger_->info(metadata_head_);
  }
}

void FileQLogger::GenerateIndexMap() {
  index_map_["duration"] = (num_events_ == 0) ? 0 : (double)end_time_.count()/1000;
#ifndef QLOG_FOR_QBONE
  index_map_["startup_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_startup_duration / end_time_.count();
  index_map_["drain_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_drain_duration / end_time_.count();
  index_map_["probebw_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_probebw_Duration / end_time_.count();
  index_map_["probertt_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_probertt_duration / end_time_.count();
  index_map_["not_recovery_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_not_recovery_duration / end_time_.count();
  index_map_["growth_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_growth_duration / end_time_.count();
  index_map_["conservation_duration_ratio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_conservation_duration / end_time_.count();
  index_map_["packetLostRatio"] = (num_events_ == 0) ? 0 : (double)report_summary_.total_packets_lost/report_summary_.total_packets_sent;
  index_map_["average_difference"] = (num_of_congestion_message_ == 0) ? 0 : (double)sum_of_mean_deviation_ / num_of_congestion_message_;
#endif
}

void FileQLogger::FinishStream() {
  // generate and add the summary
  GenerateIndexMap();
  Document summaryJson = GenerateSummary(num_events_, steady_startTime_, end_time_);

#ifndef QLOG_FOR_QBONE
  GenerateBvcReport(summaryJson);
#else
  GenerateQboneReport(summaryJson);
#endif

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
    if (!pretty_json_) {
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
    if (pretty_json_) {
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

void FileQLogger::HandleEvent(std::unique_ptr<QLogEvent> event) {
  if (streaming_) {
    ++num_events_;
    Document eventjson = event->ToJson();

    buffer_.Clear();
    writer_.Reset(buffer_);
    eventjson.Accept(writer_);
    std::string event_json = buffer_.GetString();
    if (fileObj_) {
      std::stringstream eventBuffer;
      std::string line;
      if (pretty_json_) {
        eventBuffer << std::setw(4) << event_json;
      } else {
        eventBuffer << event_json;
      }

      if (num_events_ > 1) {
        absl::StrAppend(&logstring_, ",");
      }
      // add padding to every line in the event
      while (getline(eventBuffer, line)) {
        absl::StrAppend(&logstring_, endLine_, basePadding_, eventsPadding_, line);
      }

      if(log_event_buffer_ == 0 || num_events_ % log_event_buffer_ == 0) {
        logger_->info(logstring_);
        logstring_.clear();
      }
    }
  } else {
    logs_.push_back(std::move(event));
  }
}

void FileQLogger::AddPacket(
    const QuicPublicResetPacket& public_reset_packet,
    uint64_t packet_size,
    bool is_packet_recvd) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(createPacketEventImpl(public_reset_packet, packet_size, is_packet_recvd));
}

void FileQLogger::AddPacket(
    const QuicVersionNegotiationPacket& version_negotiation_packet,
    uint64_t packet_size,
    bool is_packet_recvd) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(createPacketEventImpl(version_negotiation_packet, packet_size, is_packet_recvd));
}

void FileQLogger::AddPacket(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool is_packet_recvd) {
  // Because the quic frame inline vector is optimized towards 1-stream-frame in 
  // QuicTransmissionInfo.retransmittable_frames, we only aggregate this case.
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  std::string packet_type;
  if (encryption_level >= ENCRYPTION_FORWARD_SECURE) {
    packet_type = std::string(kShortHeaderPacketType);
  } else {
    packet_type =
        std::string(toQlogString(encryptionLevelToLongHeaderType(encryption_level)));
  }

  if(!aggregate_ ||
      retransmittable_frames.size() != 1 ||
      // If the only frame in the packet is not stream frame, we don't aggregate
      retransmittable_frames.front().type != QuicFrameType::STREAM_FRAME ||
      // If the packet type has changed, handle it and change the packet type flag
      packet_type.compare(packet_type_now_)!= 0
    ) {
    if (qlog_frames_processed_ != nullptr) {
      // when encounter a non-aggregate frame, we pass the already created event to handler
      HandleEvent(std::move(qlog_frames_processed_));
    }
    // handle every other frames normally
    if(packet_type.compare(packet_type_now_)!= 0) {
       packet_type_now_ = packet_type;
    }
    HandleEvent(createPacketEventImpl(packet_number, packet_length, transmission_type, encryption_level, retransmittable_frames, nonretransmittable_frames, is_packet_recvd));
    return;
  }

  // This check needs to happen after the nullptr check is passed to avoid error
  if (qlog_frames_processed_ != nullptr && qlog_frames_processed_->weaver_ != kQLogClientVantagePoint) {
    HandleEvent(std::move(qlog_frames_processed_));
  }

  if (qlog_frames_processed_ == nullptr) {
    // Created a frames_processed event object if there's none.
    qlog_frames_processed_ = std::make_unique<QLogFramesProcessed>();
    qlog_frames_processed_->weaver_ = kQLogClientVantagePoint;
    qlog_frames_processed_->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
    steady_packetTime_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch());
    qlog_frames_processed_->event_type_ = QLogEventType::FRAMES_PROCESSED;
    qlog_frames_processed_->frames_type_ = retransmittable_frames.front().type;
  }

  report_summary_.total_packets_sent++;
  report_summary_.total_bytes_sent += packet_length;

  // Add the stream frame to the frames_processed event
  auto f = retransmittable_frames.front();
  auto time_dirft=std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_packetTime_;
  addFramesProcessedImpl(qlog_frames_processed_.get(), f.type, getFrameType(f), packet_number, packet_length, packet_type, time_dirft);
  // TODO: handle nonretransmittable_frames
  return;
}

std::unique_ptr<QLogPacketEvent> FileQLogger::CreatePacketEvent(
    const QuicPacketHeader& packet_header,
    uint64_t packet_size,
    bool is_packet_recvd) {
  return createPacketEventImpl(packet_header, packet_size, is_packet_recvd);
}

void FileQLogger::AddPacketFrame(
    QLogPacketEvent* event,
    QuicFrameType frame_type,
    void* frame,
    bool is_packet_recvd) {
      // aggregation switch
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  if ((!aggregate_) ||
      // Only aggregate at ACK frame or PADDING frame
      (frame_type != QuicFrameType::ACK_FRAME && frame_type != QuicFrameType::PADDING_FRAME) || 
      // If there are ongoing normal packet events, do not try to aggregate
      (event->frames_.size() > 0) ||
      packet_type_now_.compare(event->packet_type_)) {
    if (qlog_frames_processed_ != nullptr) {
      HandleEvent(std::move(qlog_frames_processed_));
    }
    if(event->packet_type_.compare(packet_type_now_)!= 0) {
       packet_type_now_ = event->packet_type_;
    }
    return addPacketFrameImpl(event, frame_type, frame, is_packet_recvd);
  }
  // This check needs to happen after the nullptr check is passed to avoid error
  if (qlog_frames_processed_ != nullptr && qlog_frames_processed_->weaver_ != kQLogServerVantagePoint) {
    HandleEvent(std::move(qlog_frames_processed_));
  }

  // Created a frames_processed event object if there's none.
  if (qlog_frames_processed_ == nullptr) {
    qlog_frames_processed_ = std::make_unique<QLogFramesProcessed>();
    qlog_frames_processed_->weaver_ = kQLogServerVantagePoint;
    qlog_frames_processed_->ref_time_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
    steady_packetTime_ = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch());
    qlog_frames_processed_->event_type_ = QLogEventType::FRAMES_PROCESSED;
    qlog_frames_processed_->frames_type_ = frame_type;
  }
  auto time_dirft=std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_packetTime_;
  addFramesProcessedImpl(qlog_frames_processed_.get(), frame_type, frame, event->packet_num_,  event->packet_size_, event->packet_type_,time_dirft);
  return;
}

void FileQLogger::FinishCreatePacketEvent(std::unique_ptr<QLogPacketEvent> event) {
  if (event->frames_.size() == 0 && aggregate_) {
    return;
  }
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::move(event));
}

void FileQLogger::AddConnectionClose(
    QuicErrorCode error,
    const std::string& reason,
    ConnectionCloseSource source) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  error_ = QuicErrorCodeToString(error);
  reason_ = reason;
  source_ = ConnectionCloseSourceToString(source);
  HandleEvent(std::make_unique<quic::QLogConnectionCloseEvent>(
      error,
      reason,
      source,
      ref_time));
}

void FileQLogger::AddTransportSummary(const TransportSummaryArgs& args) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  float startup_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_startup_duration / end_time_.count();
  float drain_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_drain_duration / end_time_.count();
  float probebw_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_probebw_Duration / end_time_.count();
  float probertt_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_probertt_duration / end_time_.count();
  float not_recovery_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_not_recovery_duration / end_time_.count();
  float growth_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_growth_duration / end_time_.count();
  float conservation_duration_ratio = (num_events_ == 0) ? 0 : (float)report_summary_.total_conservation_duration / end_time_.count();
  float average_difference = args.smoothed_mean_deviation / num_of_congestion_message_;
  HandleEvent(std::make_unique<quic::QLogTransportSummaryEvent>(
      args.total_bytes_sent,
      args.total_packets_sent,
      args.total_bytes_recvd,
      args.total_packets_recvd,
      args.sum_cur_write_offset,
      args.sum_max_observed_offset,
      args.sum_cur_stream_buffer_len,
      args.total_packets_lost,
      args.total_startup_duration,
      args.total_drain_duration,
      args.total_probebw_Duration,
      args.total_probertt_duration,
      args.total_not_recovery_duration,
      args.total_growth_duration,
      args.total_conservation_duration,
      args.total_stream_bytes_cloned,
      args.total_bytes_cloned,
      args.total_crypto_data_written,
      args.total_crypto_data_recvd,
      args.current_writable_bytes,
      args.current_conn_flow_control,
      args.used_zero_rtt,
      args.quic_version,
      args.congestion_control,
      args.smoothed_min_rtt,
      args.smoothed_max_bandwidth,
      startup_duration_ratio,
      drain_duration_ratio,
      probebw_duration_ratio,
      probertt_duration_ratio,
      not_recovery_duration_ratio,
      growth_duration_ratio,
      conservation_duration_ratio,
      average_difference,
      ref_time));
}

void FileQLogger::AddBBRCongestionMetricUpdate(
    uint64_t bytes_inflight,
    uint64_t current_cwnd,
    const std::string& congestion_event,
    CongestionControlType type,
    void* state) {
  num_of_congestion_message_ ++;
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  BbrSender::DebugState* bbr_state =
	    static_cast<BbrSender::DebugState*>(state);
  if (ref_time > current_bbr_mode_timestamp_) {
     switch ( current_bbrmode_ ) {
      case BbrSender::Mode::PROBE_RTT : {
        report_summary_.total_probertt_duration += 
            (ref_time - current_bbr_mode_timestamp_).count();
        break; 
      }
      case BbrSender::Mode::STARTUP : {
        report_summary_.total_startup_duration += 
            (ref_time - current_bbr_mode_timestamp_).count();
        break; 
      }
      case BbrSender::Mode::DRAIN : {
        report_summary_.total_drain_duration += 
            (ref_time - current_bbr_mode_timestamp_).count();
        break; 
      }
      case BbrSender::Mode::PROBE_BW : {
        report_summary_.total_probebw_Duration += 
            (ref_time - current_bbr_mode_timestamp_).count();
        break; 
      }
      default:
        break;
    }
  }
  if (ref_time > current_state_timestamp_) {
    switch ( current_state_ ) {
      case BbrSender::RecoveryState::NOT_IN_RECOVERY : {
        report_summary_.total_not_recovery_duration += 
            (ref_time - current_state_timestamp_).count();
        break; 
      }
      case BbrSender::RecoveryState::GROWTH : {
        report_summary_.total_growth_duration += 
            (ref_time - current_state_timestamp_).count();
        break; 
      }
      case BbrSender::RecoveryState::CONSERVATION : {
        report_summary_.total_conservation_duration += 
            (ref_time - current_state_timestamp_).count();
        break; 
      }
      default:
        break;
    }
  }
  if ( smoothed_mean_deviation_ == 0 ) {
    smoothed_mean_deviation_ = 
        bbr_state->mean_deviation.ToMicroseconds();
  } else {
    smoothed_mean_deviation_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_mean_deviation_ + (1/(num_of_congestion_message_)) * bbr_state->mean_deviation.ToMicroseconds();
  }
  if ( smoothed_min_rtt_ == 0 ) {
    smoothed_min_rtt_ = 
        bbr_state->min_rtt.ToMicroseconds();
  }else{
    smoothed_min_rtt_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_min_rtt_ + (1/(num_of_congestion_message_)) * bbr_state->min_rtt.ToMicroseconds();
  }
  if( smoothed_max_bandwidth_ == 0) {
   smoothed_max_bandwidth_ = 
        bbr_state->max_bandwidth.ToKBitsPerSecond();
  }else{
    smoothed_max_bandwidth_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_max_bandwidth_ + (1/(num_of_congestion_message_)) * bbr_state->max_bandwidth.ToKBitsPerSecond();
  }
  sum_of_mean_deviation_ += std::abs(bbr_state->mean_deviation.ToMicroseconds() - smoothed_mean_deviation_);

  current_bbr_mode_timestamp_ = ref_time;
  current_state_timestamp_ = ref_time;
  if ( current_bbrmode_ != bbr_state->mode ) {
    current_bbrmode_ = bbr_state->mode;
  }
  if ( current_state_ != bbr_state->recovery_state ) {
    current_state_ = bbr_state->recovery_state;
  }
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogBBRCongestionMetricUpdateEvent>(
      bytes_inflight,
      current_cwnd,
      congestion_event,
      type,
      state,
      ref_time));
}

void FileQLogger::AddCubicCongestionMetricUpdate(
    uint64_t bytes_inflight,
    uint64_t current_cwnd,
    const std::string& congestion_event,
    CongestionControlType type,
    void* state) {
  num_of_congestion_message_ ++;
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  TcpCubicSenderBytes::DebugState* cubic_state =
	    static_cast<TcpCubicSenderBytes::DebugState*>(state);
  if ( smoothed_mean_deviation_ == 0 ) {
    smoothed_mean_deviation_ = 
        cubic_state->mean_deviation.ToMicroseconds();
  } else {
    smoothed_mean_deviation_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_mean_deviation_ + (1/(num_of_congestion_message_)) * cubic_state->mean_deviation.ToMicroseconds();
  }
  if ( smoothed_min_rtt_ == 0 ) {
    smoothed_min_rtt_ = 
        cubic_state->min_rtt.ToMicroseconds();
  } else {
   smoothed_min_rtt_ = 
        (1 - 1/ (num_of_congestion_message_)) * smoothed_min_rtt_ + (1/(num_of_congestion_message_)) * cubic_state->min_rtt.ToMicroseconds();
  }
  if( smoothed_max_bandwidth_ == 0) {
   smoothed_max_bandwidth_ = 
        cubic_state->bandwidth_est.ToKBitsPerSecond();
  }else{
    smoothed_max_bandwidth_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_max_bandwidth_ + (1/(num_of_congestion_message_)) * cubic_state->bandwidth_est.ToKBitsPerSecond();
  }
  sum_of_mean_deviation_ += std::abs(cubic_state->mean_deviation.ToMicroseconds() - smoothed_mean_deviation_);
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogCubicCongestionMetricUpdateEvent>(
      bytes_inflight,
      current_cwnd,
      congestion_event,
      type,
      state,
      ref_time));
}

void FileQLogger::AddBBR2CongestionMetricUpdate(
    uint64_t bytes_inflight,
    uint64_t current_cwnd,
    const std::string& congestion_event,
    CongestionControlType type,
    void* state) {
  num_of_congestion_message_++;
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  Bbr2Sender::DebugState* bbr_state =
	    static_cast<Bbr2Sender::DebugState*>(state);
  if (ref_time > current_bbr2_mode_timestamp_) {
     switch ( current_bbr2mode_ ) {
      case Bbr2Mode::PROBE_RTT : {
        report_summary_.total_probertt_duration += 
            (ref_time - current_bbr2_mode_timestamp_).count();
        break; 
      }
      case Bbr2Mode::STARTUP : {
        report_summary_.total_startup_duration += 
            (ref_time - current_bbr2_mode_timestamp_).count();
        break; 
      }
      case Bbr2Mode::DRAIN : {
        report_summary_.total_drain_duration += 
            (ref_time - current_bbr2_mode_timestamp_).count();
        break; 
      }
      case Bbr2Mode::PROBE_BW : {
        report_summary_.total_probebw_Duration += 
            (ref_time - current_bbr2_mode_timestamp_).count();
        break; 
      }
      default:
        break;
    }
  }
  if (smoothed_mean_deviation_ == 0) {
    smoothed_mean_deviation_ = 
        bbr_state->mean_deviation.ToMicroseconds();
  } else {
    smoothed_mean_deviation_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_mean_deviation_ + (1/(num_of_congestion_message_)) * bbr_state->mean_deviation.ToMicroseconds();
  }
  if (smoothed_min_rtt_ == 0) {
    smoothed_min_rtt_ = 
        bbr_state->min_rtt.ToMicroseconds();
  } else {
   smoothed_min_rtt_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_min_rtt_ + (1/(num_of_congestion_message_)) * bbr_state->min_rtt.ToMicroseconds();
  }
  if (smoothed_max_bandwidth_ == 0) {
   smoothed_max_bandwidth_ = 
        bbr_state->bandwidth_est.ToKBitsPerSecond();
  } else {
    smoothed_max_bandwidth_ = 
        (1 - 1/(num_of_congestion_message_)) * smoothed_max_bandwidth_ + (1/(num_of_congestion_message_)) * bbr_state->bandwidth_est.ToKBitsPerSecond();
  }
  sum_of_mean_deviation_ += std::abs(bbr_state->mean_deviation.ToMicroseconds()- smoothed_mean_deviation_);
  current_bbr2_mode_timestamp_ = ref_time;
  if(current_bbr2mode_ != bbr_state->mode) {
    current_bbr2mode_ = bbr_state->mode;
  }
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogBBR2CongestionMetricUpdateEvent>(
      bytes_inflight,
      current_cwnd,
      congestion_event,
      type,
      state,
      ref_time));
}

void FileQLogger::AddBandwidthEstUpdate(
    uint64_t bytes,
    std::chrono::microseconds interval) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogBandwidthEstUpdateEvent>(
      bytes,
      interval,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_));
}

void FileQLogger::AddAppLimitedUpdate() {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogAppLimitedUpdateEvent>(
      true,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_));
}

void FileQLogger::AddAppUnlimitedUpdate() {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogAppLimitedUpdateEvent>(
      false,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_));
}

void FileQLogger::AddPacingMetricUpdate(
    uint64_t pacing_burst_size_in,
    std::chrono::microseconds pacing_interval_in) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogPacingMetricUpdateEvent>(
      pacing_burst_size_in, pacing_interval_in, ref_time));
}

void FileQLogger::AddPacingObservation(
    std::string& actual,
    std::string& expect,
    std::string& conclusion) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogPacingObservationEvent>(
      actual, expect, conclusion, ref_time));
}

void FileQLogger::AddAppIdleUpdate(std::string& idle_event, bool idle) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogAppIdleUpdateEvent>(
      idle_event, idle, ref_time));
}

void FileQLogger::AddPacketDrop(size_t packet_size, std::string& drop_reason) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogPacketDropEvent>(
      packet_size, drop_reason, ref_time));
}

void FileQLogger::AddDatagramReceived(uint64_t data_len) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(
      std::make_unique<quic::QLogDatagramReceivedEvent>(data_len, ref_time));
}

void FileQLogger::AddLossAlarm(
    uint64_t largest_sent,
    uint64_t alarm_count,
    uint64_t outstanding_packets,
    std::string& type) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogLossAlarmEvent>(
      largest_sent, alarm_count, outstanding_packets, type, ref_time));
}

void FileQLogger::AddPacketLost(
    uint64_t lost_packet_num,
    EncryptionLevel level,
    TransmissionType type) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  report_summary_.total_packets_lost++;
  HandleEvent(std::make_unique<quic::QLogPacketLostEvent>(
      lost_packet_num, level, type, ref_time));
}

void FileQLogger::AddTransportStateUpdate(std::string& update) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogTransportStateUpdateEvent>(
      update, ref_time));
}

void FileQLogger::AddPacketBuffered(
    uint64_t packet_num,
    EncryptionLevel protection_type,
    uint64_t packet_size) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogPacketBufferedEvent>(
      packet_num, protection_type, packet_size, ref_time));
}

void FileQLogger::AddMetricUpdate(
    std::chrono::microseconds latest_rtt,
    std::chrono::microseconds mrtt,
    std::chrono::microseconds srtt,
    std::chrono::microseconds ack_delay) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
	std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogMetricUpdateEvent>(
      latest_rtt, mrtt, srtt, ack_delay, ref_time));
}

Document FileQLogger::ToJson() {
  Document j, trace;
  j.SetObject(); 
  trace.SetObject();

  ToJsonBase(j, trace);
#ifndef QLOG_FOR_QBONE
  GenerateBvcReport(trace);
#endif
  Value& traces_value = j["traces"];
  traces_value.PushBack(trace, trace.GetAllocator()); 


  if (logs_.size() > 0) {
    Document summaryJson = GenerateSummary(logs_.size(), logs_[0]->ref_time_, logs_.back()->ref_time_);
    j.AddMember("summary", summaryJson, j.GetAllocator());
  }

  // convert stored logs into json event array
  Value value;
  value.SetArray();
  for (auto& event : logs_) {
    Value event_json;
    event_json.CopyFrom(event->ToJson(), j.GetAllocator());
    value.PushBack(event_json, j.GetAllocator());
  }

  j["traces"]["events"] = value;
  return j;
}

void FileQLogger::ToJsonBase(Document& j, Document& traces) {

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
  value.AddMember( "ip", Value(self_address_.c_str(), traces_allocator).Move(), traces_allocator); 
  value.AddMember( "name", Value(host, traces_allocator).Move(), traces_allocator); 
  traces.AddMember("vantage_point", value, traces_allocator);
}

void FileQLogger::AddSummary(Value& value, Document::AllocatorType& summary_allocator) {
  value.AddMember("total_bytes_sent", report_summary_.total_bytes_sent, summary_allocator);
  value.AddMember("total_packets_sent", report_summary_.total_packets_sent, summary_allocator);
  value.AddMember("total_bytes_recvd", report_summary_.total_bytes_recvd, summary_allocator);
  value.AddMember("total_packets_recvd", report_summary_.total_packets_recvd, summary_allocator);
  value.AddMember("total_packets_lost", report_summary_.total_packets_lost, summary_allocator);
  value.AddMember("quic_transport_version", Value(QuicVersionToString(report_summary_.quic_version).c_str(), summary_allocator).Move(), summary_allocator);
  value.AddMember("connection_duration", ((int)(index_map_.at("duration") * 100 + 0.5)) / 100.0, summary_allocator);  
#ifndef QLOG_FOR_QBONE
  value.AddMember("used_zero_rtt", report_summary_.used_zero_rtt, summary_allocator);
  value.AddMember("smoothed_min_rtt", (int)(smoothed_min_rtt_ / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("smoothed_max_bandwidth", (int)((smoothed_max_bandwidth_ / 8) * 100 + 0.5) / 100.0, summary_allocator);
  value.AddMember("average_difference", ((int)(index_map_.at("average_difference") * 100 + 0.5)) / 100.0, summary_allocator);
  if (congestion_type_ == CongestionControlType::kBBR) {
    AddBBRSummary(value, summary_allocator);
  } else if (congestion_type_==CongestionControlType::kBBRv2) {
    AddBBR2Summary(value, summary_allocator);
  } else if (congestion_type_==CongestionControlType::kCubicBytes) {
    AddCubicSummary(value, summary_allocator);
  } else {
    // TODO : Other CC Algorithm
  }
#endif
}

void FileQLogger::AddMapInSummary(Value& value, Value& tmp_document, Document::AllocatorType& tmp_allocator) {
  // summary [stream_map]
  value.SetArray();
  Value tmp_arr;
  for(auto it = stream_map_.begin(); it != stream_map_.end(); it++) {
    tmp_arr.SetArray();
    tmp_arr.PushBack(it->first, tmp_allocator);
    tmp_arr.PushBack(it->second, tmp_allocator);
    value.PushBack(tmp_arr, tmp_allocator);    
  } 
  tmp_document.AddMember("stream_map", value, tmp_allocator);
#ifndef QLOG_FOR_QBONE
   // summaryObj [uri_map]
  value.SetArray();
  tmp_document.AddMember("uri_map", value, tmp_allocator);
  Value& uriMap_value = tmp_document["uri_map"];

  for (size_t i = 0; i < uri_map_.size(); i++) {
    size_t current_size =  uri_map_[i].second.size();
    Value temp_value;
    temp_value.SetArray();
    for (size_t j = 0; j < current_size; j++) {
      temp_value.PushBack((uri_map_[i].second)[j], tmp_allocator); 
    }

    value.SetArray();
    value.PushBack(Value((uri_map_[i].first).c_str(), tmp_allocator).Move(), tmp_allocator); 
    value.PushBack(temp_value, tmp_allocator); 
    uriMap_value.PushBack(value, tmp_allocator);
  } 
  
  std::string trid_str = "";
  for (auto it = trid_.begin(); it != trid_.end(); it++) {
    if(trid_str == "") {
      absl::StrAppend(&trid_str, *it);
    } else {
      absl::StrAppend(&trid_str, ", ", *it);
    }
  }
  tmp_document.AddMember("trid", Value(trid_str.c_str(), tmp_allocator).Move(), tmp_allocator);
#endif
}

#ifdef QLOG_FOR_QBONE
//Todo : ops-log 
void FileQLogger::GenerateQboneReport(Document& summary) {
  uint32_t duration = (num_events_ == 0) ? 0 : end_time_.count()/1000;
  float packetLostRatio = (float)report_summary_.total_packets_lost/report_summary_.total_packets_sent;
  if (metricsQboneCallback) {
    (*metricsQboneCallback)(packetLostRatio);
  }

  std::string dcidStr = (!dcid_ || dcid_->IsEmpty()) ? "" : dcid_->ToString();
  if (writeLogQboneCallback) {
    if (packetLostRatio > 0.2) {
      (*writeLogQboneCallback)(LOG_INFO | LOG_LOCAL0, 7001, dcidStr, error_, reason_, source_, "", (int)(packetLostRatio * 100), duration);
    }

    Value& reportSummary_value = summary["report_summary"];
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    reportSummary_value.Accept(writer);
    std::string sum_str = buffer.GetString();

    std::string trid_str = "";
    (*writeLogQboneCallback)(LOG_INFO | LOG_LOCAL0, 8001, dcidStr, error_, reason_, source_, sum_str, report_summary_.quic_version, duration);
  }
}
#else
void FileQLogger::AddBBRSummary(Value& value, Document::AllocatorType& summary_allocator) {
  value.AddMember("total_startup_duration", (int)(report_summary_.total_startup_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_drain_duration", (int)(report_summary_.total_drain_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_probebw_Duration", (int)(report_summary_.total_probebw_Duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_probertt_duration", (int)(report_summary_.total_probertt_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_not_recovery_duration", (int)(report_summary_.total_not_recovery_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_growth_duration", (int)(report_summary_.total_growth_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_conservation_duration", (int)(report_summary_.total_conservation_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("congestion_type", "BBR", summary_allocator);
  value.AddMember("startup_duration_ratio", ((int)(index_map_.at("startup_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("drain_duration_ratio", ((int)(index_map_.at("drain_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("probebw_duration_ratio", ((int)(index_map_.at("probebw_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("probertt_duration_ratio", ((int)(index_map_.at("probertt_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("not_recovery_duration_ratio", ((int)(index_map_.at("not_recovery_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("growth_duration_ratio", ((int)(index_map_.at("growth_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("conservation_duration_ratio", ((int)(index_map_.at("conservation_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
}

void FileQLogger::AddBBR2Summary(Value& value, Document::AllocatorType& summary_allocator) {
  value.AddMember("total_startup_duration", (int)(report_summary_.total_startup_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_drain_duration", (int)(report_summary_.total_drain_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_probebw_Duration", (int)(report_summary_.total_probebw_Duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("total_probertt_duration", (int)(report_summary_.total_probertt_duration / 10 + 0.5) / 100.0, summary_allocator);
  value.AddMember("congestion_type", "BBRv2", summary_allocator);
  value.AddMember("startup_duration_ratio", ((int)(index_map_.at("startup_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("drain_duration_ratio", ((int)(index_map_.at("drain_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("probebw_duration_ratio", ((int)(index_map_.at("probebw_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
  value.AddMember("probertt_duration_ratio", ((int)(index_map_.at("probertt_duration_ratio") * 10000 + 0.5)) / 10000.0, summary_allocator);
}

void FileQLogger::AddCubicSummary(Value& value, Document::AllocatorType& summary_allocator) {
  value.AddMember("congestion_type", "Cubic", summary_allocator);
}

void FileQLogger::WriteLogCallbackByDuration(size_t report_id_for_7000, size_t report_id_for_8000) {
  std::string dcidStr = (!dcid_ || dcid_->IsEmpty()) ? "" : dcid_->ToString();
  (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, report_id_for_7000, (int)(index_map_.at("packetLostRatio") * 100), (int)index_map_.at("duration"), (int)(index_map_.at("startup_duration_ratio") * 10000), (int)(index_map_.at("drain_duration_ratio") * 10000), (int)(index_map_.at("probebw_duration_ratio") * 10000), (int)(index_map_.at("probertt_duration_ratio") * 10000), 
      dcidStr.c_str(), error_.c_str(), reason_.c_str(), source_.c_str(), std::string(toQlogString(congestion_type_)).c_str());
  if ( congestion_type_ == CongestionControlType::kBBR ) {
    (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, report_id_for_8000, (int)(index_map_.at("packetLostRatio") * 100), (int)index_map_.at("duration"), (int)(index_map_.at("not_recovery_duration_ratio") * 10000), (int)(index_map_.at("growth_duration_ratio") * 10000), (int)(index_map_.at("conservation_duration_ratio") * 10000), -1,
        dcidStr.c_str(), error_.c_str(), reason_.c_str(), source_.c_str(), "", "", "", "closed", peer_address_.c_str());
  }
}

void FileQLogger::GetCallbackIdByDuration(size_t& report_id_for_7000, size_t& report_id_for_8000) {
  switch((int)index_map_.at("duration")) {
          case 0 ... 1000 : {
            report_id_for_7000 = 7002;
            report_id_for_8000 = 8002;
            break;
          }
          case 1001 ... 5000 : {
            report_id_for_7000 = 7003;
            report_id_for_8000 = 8003;
            break;
          } 
          case 5001 ... 10000 : {
            report_id_for_7000 = 7004;
            report_id_for_8000 = 8004;
            break;
          }
          case 10001 ... 30000 : {
            report_id_for_7000 = 7005;
            report_id_for_8000 = 8005;
            break;
          }
          case 30001 ... 60000 : {
            report_id_for_7000 = 7006;
            report_id_for_8000 = 8006;
            break;
          }
          case 60001 ... 120000 : {
            report_id_for_7000 = 7007;
            report_id_for_8000 = 8007;
            break;
          }
          case 120001 ... 180000 : {
            report_id_for_7000 = 7008;
            report_id_for_8000 = 8008;
            break;
          }
          case 180001 ... 240000 : {
            report_id_for_7000 = 7009;
            report_id_for_8000 = 8009;
            break;
          }
          case 240001 ... 300000 : {
            report_id_for_7000 = 7010;
            report_id_for_8000 = 8010;
            break;
          }
          case 300001 ... 420000 : {
            report_id_for_7000 = 7011;
            report_id_for_8000 = 8011;
            break;
          }
          case 420001 ... 540000 : {
            report_id_for_7000 = 7012;
            report_id_for_8000 = 8012;
            break;
          }
          case 540001 ... 660000 : {
            report_id_for_7000 = 7013;
            report_id_for_8000 = 8013;
            break;
          }
          case 660001 ... 1800000 : {
            report_id_for_7000 = 7014;
            report_id_for_8000 = 8014;
            break;
          }
          case 1800001 ... 3600000 : {
            report_id_for_7000 = 7015;
            report_id_for_8000 = 8015;
            break;
          }
          default : {
            report_id_for_7000 = 7016;
            report_id_for_8000 = 8016;
            break;
          }
  }
}

void FileQLogger::GenerateBvcReport(Document& summary) {
  if (metricsCallback) {
    (*metricsCallback)(index_map_.at("packetLostRatio"));
  }
  if (emptyCallback && trid_.size() == 1 && trid_[0] == "") {
    (*emptyCallback)(congestion_type_);
  }else{
    if (packetlostCallback) {
      (*packetlostCallback)(index_map_.at("packetLostRatio"), congestion_type_);
    }
    if (minrttCallback) {
      (*minrttCallback)(smoothed_min_rtt_ / 1000, congestion_type_);
    }
    if (meandeviationCallback) {
      (*meandeviationCallback)(smoothed_mean_deviation_ / 1000, congestion_type_);
    }
    if (bandwidthCallback) {
      (*bandwidthCallback)(smoothed_max_bandwidth_ / 8, congestion_type_);
    }
  }

  std::string dcidStr = (!dcid_ || dcid_->IsEmpty()) ? "" : dcid_->ToString();
  if (writeLogCallback) {
    if (index_map_.at("packetLostRatio") > 0.2) {
      (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, 7001, (int)(index_map_.at("packetLostRatio") * 100), (int)index_map_.at("duration"), (int)report_summary_.total_packets_lost, 0, 0, 0, 
          dcidStr.c_str(), error_.c_str(), reason_.c_str(), source_.c_str(), std::string(toQlogString(congestion_type_)).c_str(), "closed");
    }
    if ( congestion_type_ != CongestionControlType::kCubicBytes ) {
      size_t report_id_for_7000 = 0, report_id_for_8000 =0;
      GetCallbackIdByDuration(report_id_for_7000, report_id_for_8000);
      WriteLogCallbackByDuration(report_id_for_7000, report_id_for_8000);
    }
    
    Value& reportSummary_value = summary["report_summary"];
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    reportSummary_value.Accept(writer);
    std::string sum_str = buffer.GetString();
    std::string trid_str = summary["trid"].GetString();
    (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, 8001, (int)(index_map_.at("packetLostRatio") * 100), (int)index_map_.at("duration"), (int)((smoothed_max_bandwidth_ / 8) * 100 + 0.5) / 100, -1, (int)(smoothed_min_rtt_ / 10 + 0.5) / 100, init_cwnd_, 
        dcidStr.c_str(), trid_str.c_str(), sum_str.c_str(), error_.c_str(), reason_.c_str(), first_frame_pre_range_.c_str(), std::string(toQlogString(congestion_type_)).c_str(), "closed", peer_address_.c_str());
    
    GenerateFirstFrameReport();
  }
}
#endif

void FileQLogger::GenerateFirstFrameReport() {
  std::string dcidStr = (!dcid_ || dcid_->IsEmpty()) ? "" : dcid_->ToString();
  for (auto it = sid_first_frame_msg_map_.begin(); it != sid_first_frame_msg_map_.end(); ++it) {
    if (it->second.size <= 1000 || 
        it->second.send_frame_end_time.count() >= 5 * 1000 * 1000 ||
	      it->second.send_frame_end_time.count() == 0) {   // filter condition
      continue;
    }
    if (firstFrameCallback) {
      (*firstFrameCallback)(it->second.size + it->second.stream_offset, it->second.send_frame_end_time.count() / 1000, init_cwnd_, it->second.protocol);
    }
    std::string zero_rtt = report_summary_.used_zero_rtt ? "true" : "false";
    (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, 8100, it->first, init_cwnd_, it->second.stream_offset, it->second.size, it->second.request_index, it->second.send_frame_end_time.count() / 1000, 
      dcidStr.c_str(), (it->second.trid).c_str(), zero_rtt.c_str(), (it->second.protocol).c_str(), "", "", std::string(toQlogString(congestion_type_)).c_str(), "closed", peer_address_.c_str());
  }
}

Document FileQLogger::GenerateSummary(
    size_t num_events,
    std::chrono::microseconds start_time,
    std::chrono::microseconds end_time) {
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
  value.SetInt64((num_events == 0) ? 0 : end_time.count());
  summaryObj.AddMember(key, value, summary_allocator);  

  key.SetString(StringRef("total_event_count"));  
  value.SetInt64(num_events);
  summaryObj.AddMember(key, value, summary_allocator);

  // summaryObj [report_summary] 
  value.SetObject();
  AddSummary(value, summary_allocator);
  summaryObj.AddMember("report_summary", value, summary_allocator);
  AddMapInSummary(value, summaryObj, summary_allocator);

  return summaryObj;
}

void FileQLogger::AlarmReport(Document& summary) {
  std::string dcidStr = (!dcid_ || dcid_->IsEmpty()) ? "" : dcid_->ToString();
  if (writeLogCallback) {
    if (index_map_.at("packetLostRatio") > 0.2) {
      (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, 7001, (int)(index_map_.at("packetLostRatio") * 100), (int)index_map_.at("duration"), (int)report_summary_.total_packets_lost, 0, 0, 0, 
          dcidStr.c_str(), error_.c_str(), reason_.c_str(), source_.c_str(), std::string(toQlogString(congestion_type_)).c_str(), "connected");
    }
    Value& reportSummary_value = summary["report_summary"];
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    reportSummary_value.Accept(writer);
    std::string sum_str = buffer.GetString();
    std::string trid_str = summary["trid"].GetString();
    (*writeLogCallback)(LOG_INFO | LOG_LOCAL0, 8001, (int)(index_map_.at("packetLostRatio") * 100), (int)index_map_.at("duration"), (int)((smoothed_max_bandwidth_ / 8) * 100 + 0.5) / 100, -1, (int)(smoothed_min_rtt_ / 10 + 0.5) / 100, -1, 
        dcidStr.c_str(), trid_str.c_str(), sum_str.c_str(), error_.c_str(), reason_.c_str(), source_.c_str(), std::string(toQlogString(congestion_type_)).c_str(), "connected", "");
  }
}

void FileQLogger::AddStreamStateUpdate(
    quic::QuicStreamId id,
    std::string& update,
    quiche::QuicheOptionalImpl<std::chrono::milliseconds> time_since_stream_creation) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogStreamStateUpdateEvent>(
      id,
      update,
      std::move(time_since_stream_creation),
      vantagePoint_,
      ref_time));
}

void FileQLogger::AddConnectionMigrationUpdate(bool intentional_migration) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogConnectionMigrationEvent>(
      intentional_migration, vantagePoint_, ref_time));
}

void FileQLogger::AddPathValidationEvent(bool success) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogPathValidationEvent>(
      success, vantagePoint_, ref_time));
}

void FileQLogger::AddPriorityUpdate(
    quic::QuicStreamId stream_id,
    uint8_t urgency,
    bool incremental) {
  auto ref_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()) - steady_startTime_;
  end_time_ = ref_time;
  HandleEvent(std::make_unique<quic::QLogPriorityUpdateEvent>(
      stream_id, urgency, incremental, ref_time));
}

void FileQLogger::OutputLogsToFile(const std::string& path, bool pretty_json) {
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
    Document qLog = ToJson();
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    qLog.Accept(writer);
    std::string base_Json = buffer.GetString();
    if (pretty_json) {
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
