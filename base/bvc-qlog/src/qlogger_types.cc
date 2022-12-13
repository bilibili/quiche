#include "base/bvc-qlog/src/qlogger_types.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "gquiche/quic/core/quic_error_codes.h"

namespace quic {

Document QLogFrame::toShortJson() const {
  Document j;
  return j;
}

Document PaddingFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PADDING_FRAME).data(), j.GetAllocator()).Move(),  
              j.GetAllocator());
  return j;
}

// TODO: padding is not showing up in short form, need to fix
Document PaddingFrameLog::toShortJson() const {
  Document j;
  j.SetArray();
  j.PushBack("padding", j.GetAllocator());
  return j;
}

Document RstStreamFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::RST_STREAM_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              stream_id_,
              j_allocator);
  j.AddMember("error_code",
              error_code_,
              j_allocator);
  j.AddMember("offset",
              offset_,
              j_allocator);
  return j;
}

Document ConnectionCloseFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::CONNECTION_CLOSE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("wire_error_code",
              wire_error_code_,
              j_allocator);
  j.AddMember("quic_error_code",
              Value(QuicErrorCodeToString(quic_error_code_), j_allocator).Move(),
              j_allocator);
  j.AddMember("error_details",
              Value(error_details_.c_str(), j_allocator).Move(),
              j_allocator);
  j.AddMember("close_type",
              Value((toQlogString(close_type_)).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("transport_closing_frame_type",
              transport_close_frame_type_,
              j_allocator);
  return j;
}

Document GoAwayFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::GOAWAY_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("error_code",
              Value(QuicErrorCodeToString(error_code_), j_allocator).Move(),
              j_allocator);
  j.AddMember("reason_phrase",
              Value(reason_phrase_.c_str(), j_allocator).Move(),
              j_allocator);
  j.AddMember("last_good_stream_id",
              last_good_streamId_,
              j_allocator);
  return j;
}

Document WindowUpdateFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::WINDOW_UPDATE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              stream_id_,
              j_allocator);
  j.AddMember("max_data",
              max_data_,
              j_allocator);
  return j;
}

Document BlockedFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::BLOCKED_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              stream_id_,
              j_allocator);
  return j;
}

Document StopWaitingFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STOP_WAITING_FRAME).data(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document PingFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PING_FRAME).data(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document AckFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();

  Value value;
  value.SetArray();

  Value temp_value;
  for (auto interval : packet_number_queue_) {
    temp_value.SetArray();      
    //*: Because the interval uses half-closed  `[)` and causes confusion,
    //*: minus 1 here to make it closed range '[]'
    if(interval.max().ToUint64() - 1 == interval.min().ToUint64()) {
      temp_value.PushBack(interval.min().ToUint64(), j_allocator);             
    } else { 
      temp_value.PushBack(interval.min().ToUint64(), j_allocator);
      temp_value.PushBack(interval.max().ToUint64() - 1, j_allocator);
    }
    value.PushBack(temp_value, j_allocator);
  }
  
  j.AddMember("acked_ranges",
              value,
              j_allocator);  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::ACK_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("ack_delay",
              ack_delay_.count(),
              j_allocator);
  return j;
}

Document AckFrameLog::toShortJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();

  Value value;
  value.SetArray();

  Value tmp_arr;
  for (auto interval : packet_number_queue_) {
    tmp_arr.SetArray();
    if(interval.max().ToUint64() - 1 == interval.min().ToUint64()) {
      tmp_arr.PushBack(interval.min().ToUint64(), j_allocator);
    } else {
      tmp_arr.PushBack(interval.min().ToUint64(), j_allocator);
      tmp_arr.PushBack(interval.max().ToUint64() - 1, j_allocator);      
    }
    value.PushBack(tmp_arr, j_allocator);
  }

  j.PushBack(value, j_allocator);
  j.PushBack(ack_delay_.count(), j_allocator);
  return j;
}

Document StreamFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STREAM_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              stream_id_,
              j_allocator);
  j.AddMember("offset",
              offset_,
              j_allocator);
  j.AddMember("length",
              len_,
              j_allocator);
  j.AddMember("fin",
              fin_,
              j_allocator);              
  return j;
}

Document StreamFrameLog::toShortJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.PushBack(stream_id_, j_allocator);
  j.PushBack(offset_, j_allocator);
  j.PushBack(len_, j_allocator);
  j.PushBack(fin_, j_allocator); 
  return j;
}

Document CryptoFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("encryption_level",
              Value(toQlogString(level_).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::CRYPTO_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("offset",
              offset_,
              j_allocator);
  j.AddMember("data_length",
              data_length_,
              j_allocator);
  return j;
}

Document HandshakeDoneFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::HANDSHAKE_DONE_FRAME).data(), j.GetAllocator()).Move(),
              j.GetAllocator());
  return j;
}

Document MTUDiscoveryFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::MTU_DISCOVERY_FRAME).data(), j.GetAllocator()).Move(),
              j.GetAllocator());
  return j;
}

Document NewConnectionIdFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();    
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::NEW_CONNECTION_ID_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("sequence",
              sequence_number_,
              j_allocator);
  return j;
}

Document MaxStreamsFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::MAX_STREAMS_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("max_streams",
              stream_count_,
              j_allocator);
  j.AddMember("direction",
              Value(unidirectional_ ? "unidirectional" : "bidirectional", j_allocator).Move(),
              j_allocator);
  return j;
}

Document StreamsBlockedFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STREAMS_BLOCKED_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("max_streams",
              stream_count_,
              j_allocator);
  j.AddMember("direction",
              Value(unidirectional_ ? "unidirectional" : "bidirectional", j_allocator).Move(),
              j_allocator);
  return j;
}

Document PathResponseFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PATH_RESPONSE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("path_data",
              Value(path_data_.c_str(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document PathChallengeFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PATH_CHALLENGE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("path_data",
              Value(path_data_.c_str(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document StopSendingFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STOP_SENDING_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              stream_id_,
              j_allocator);
  j.AddMember("error_code",
              Value(QuicRstStreamErrorCodeToString(error_code_), j_allocator).Move(),
              j_allocator);
  return j;
}

Document MessageFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::MESSAGE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("message_id",
              message_id_,
              j_allocator);
  j.AddMember("length",
              length_,
              j_allocator);
  return j;
}

Document NewTokenFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::NEW_TOKEN_FRAME).data(), j.GetAllocator()).Move(),
              j.GetAllocator());
  return j;
}

Document RetireConnectionIdFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::RETIRE_CONNECTION_ID_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("sequence",
              sequence_number_,
              j_allocator);
  return j;
}

Document AckFrequencyFrameLog::ToJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::ACK_FREQUENCY_FRAME).data(), j_allocator ).Move(),
              j_allocator);
  j.AddMember("sequence_number",
              sequence_number_,
              j_allocator);
  j.AddMember("packet_tolerance",
              packet_tolerance_,
              j_allocator);
  j.AddMember("update_max_ack_delay",
              update_max_ack_delay_,
              j_allocator);
  j.AddMember("ignore_order",
              ignore_order_,
              j_allocator);
  return j;
}

Document VersionNegotiationLog::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  for (const auto& v : versions_) {
    j.PushBack(Value(ParsedQuicVersionToString(v).c_str(), j_allocator).Move(), j_allocator);
  }
  return j;
}

Document QLogFramesProcessed::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);

  Value value;
  value.SetObject();
  value.AddMember("frames_type",
                  Value(toQlogString(frames_type_).data(), j_allocator).Move(),
                  j_allocator);

  //frames_fields
  Value tmp_arr;
  tmp_arr.SetArray();
  switch(frames_type_) {
    case QuicFrameType::STREAM_FRAME:
      tmp_arr.PushBack("stream_id", j_allocator);
      tmp_arr.PushBack("offset", j_allocator);
      tmp_arr.PushBack("length", j_allocator);
      tmp_arr.PushBack("fin", j_allocator);      
      break;
    case QuicFrameType::ACK_FRAME:
      tmp_arr.PushBack("acked_ranges", j_allocator);
      tmp_arr.PushBack("ack_delay", j_allocator);
      break;
    default:
      break;
  }
  value.AddMember("frames_fields",
                  tmp_arr,
                  j_allocator);

  tmp_arr.SetArray();
  for (const auto& frame : frames_) {
    tmp_arr.PushBack(Value().CopyFrom(frame->toShortJson(), j_allocator).Move(), j_allocator);  
  }
  value.AddMember("frames",
                  tmp_arr,
                  j_allocator);

  tmp_arr.SetArray();
  for (const auto& packet_size : packet_sizes_) {
    tmp_arr.PushBack(packet_size, j_allocator);
  }
  value.AddMember("packet_sizes",
                  tmp_arr,
                  j_allocator);

  tmp_arr.SetArray();
  for (const auto& timeDrift : time_drifts_) {
    tmp_arr.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(timeDrift.count()).c_str(), j_allocator).Move(), j_allocator);
  }
  value.AddMember("timeDrift",
                  tmp_arr,
                  j_allocator);


  tmp_arr.SetArray();
  for (const auto& packet_num : packet_nums_) {
    tmp_arr.PushBack(packet_num, j_allocator);
  }
  value.AddMember("packetNums",
                  tmp_arr,
                  j_allocator);

  value.AddMember("packet_type",
                  Value(packet_type_.c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(value, j_allocator);
  return j;
}

Document QLogPacketEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);

  Value tmp_object, tmp_arr;
  tmp_object.SetObject();
  tmp_arr.SetArray();
  tmp_object.AddMember("packet_size",
                       packet_size_,
                       j_allocator);  
  if (packet_type_ != toQlogString(QuicLongHeaderType::RETRY)) {
    tmp_object.AddMember("packet_number",
                         packet_num_,
                         j_allocator);

    for (const auto& frame : frames_) {
      tmp_arr.PushBack(Value().CopyFrom(frame->ToJson(), j_allocator).Move(), j_allocator);
    }
  }

  Value value;
  value.SetObject();
  value.AddMember("header",
                  tmp_object,
                  j_allocator);
  value.AddMember("frames",
                  tmp_arr,
                  j_allocator);
  value.AddMember("packet_type",
                  Value(packet_type_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("transmission_type",
                  Value(transmission_type_.c_str(), j_allocator).Move(),
                  j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

Document QLogVersionNegotiationEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value tmp_object;
  tmp_object.SetObject();
  tmp_object.AddMember("packet_size",
                       packet_size_,
                       j_allocator);  

  Value value;
  value.SetObject();
  value.AddMember("versions",
                  version_log_->ToJson(),
                  j_allocator);
  value.AddMember("header",
                  tmp_object,
                  j_allocator);
  value.AddMember("packet_type",
                  Value(packet_type_.c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

Document QLogRetryEvent::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value tmp_object;
  tmp_object.SetObject();
  tmp_object.AddMember("packet_size",
                       packet_size_,
                       j_allocator);  

  Value value;
  value.SetObject();
  value.AddMember("header",
                  tmp_object,
                  j_allocator);
  value.AddMember("packet_type",
                  Value(packet_type_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("token_size",
                  token_size_,
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogConnectionCloseEvent::QLogConnectionCloseEvent(
    QuicErrorCode error_in,
    std::string reason_in,
    ConnectionCloseSource source_in,
    std::chrono::microseconds ref_time_in)
    : error_{std::move(error_in)},
      reason_{std::move(reason_in)},
      source_{source_in} {
  event_type_ = QLogEventType::CONNECTION_CLOSE;
  ref_time_ = ref_time_in;
}

Document QLogConnectionCloseEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("error",
                  Value(QuicErrorCodeToString(error_), j_allocator).Move(),
                  j_allocator);
  value.AddMember("reason",
                  Value(reason_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("source",
                  Value(ConnectionCloseSourceToString(source_).c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("connectivity", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogTransportSummaryEvent::QLogTransportSummaryEvent(
    uint64_t totalBytesSentIn,
    uint64_t totalPacketsSentIn,
    uint64_t totalBytesRecvdIn,
    uint64_t totalPacketsRecvdIn,
    uint64_t sumCurWriteOffsetIn,
    uint64_t sumMaxObservedOffsetIn,
    uint64_t sumCurStreamBufferLenIn,
    uint64_t totalStartupDurationIn,
    uint64_t totalDrainDurationIn,
    uint64_t totalProbeBWDurationIn,
    uint64_t totalProbeRttDurationIn,
    uint64_t totalNotRecoveryDurationIn,
    uint64_t totalGrowthDurationIn,
    uint64_t totalConservationDurationIn,
    uint64_t totalPacketsLostIn,
    uint64_t totalStreamBytesClonedIn,
    uint64_t totalBytesClonedIn,
    uint64_t totalCryptoDataWrittenIn,
    uint64_t totalCryptoDataRecvdIn,
    uint64_t currentWritableBytesIn,
    uint64_t currentConnFlowControlIn,
    bool usedZeroRttIn,
    QuicTransportVersion quicVersionIn,
    CongestionControlType congestionTypeIn,
    double smoothedMinRttIn,
    double smoothedMaxBandwidthIn,
    float startupDurationRatioIn,
    float drainDurationRatioIn,
    float probebwDurationRatioIn,
    float proberttDurationRatioIn,
    float NotRecoveryDurationRatioIn,
    float GrowthDurationRatioIn,
    float ConservationDurationRatioIn,
    float AverageDifferenceIn,
    std::chrono::microseconds ref_time_in)
    : total_bytes_sent{totalBytesSentIn},
      total_packets_sent{totalPacketsSentIn},
      total_bytes_recvd{totalBytesRecvdIn},
      total_packets_recvd{totalPacketsRecvdIn},
      sum_cur_write_offset{sumCurWriteOffsetIn},
      sum_max_observed_offset{sumMaxObservedOffsetIn},
      sum_cur_stream_buffer_len{sumCurStreamBufferLenIn},
      total_packets_lost{totalPacketsLostIn},
      total_startup_duration{totalStartupDurationIn},
      total_drain_duration{totalDrainDurationIn},
      total_probebw_Duration{totalProbeBWDurationIn},
      total_probertt_duration{totalProbeRttDurationIn},
      total_not_recovery_duration{totalNotRecoveryDurationIn},
      total_growth_duration{totalGrowthDurationIn},
      total_conservation_duration{totalConservationDurationIn},
      total_stream_bytes_cloned{totalStreamBytesClonedIn},
      total_bytes_cloned{totalBytesClonedIn},
      total_crypto_data_written{totalCryptoDataWrittenIn},
      total_crypto_data_recvd{totalCryptoDataRecvdIn},
      current_writable_bytes{currentWritableBytesIn},
      current_conn_flow_control{currentConnFlowControlIn},
      used_zero_rtt{usedZeroRttIn},
      quic_version{quicVersionIn},
      congestion_type{congestionTypeIn},
      smoothed_min_rtt{smoothedMinRttIn},
      smoothed_max_bandwidth{smoothedMaxBandwidthIn},
      startup_suration_ratio{startupDurationRatioIn},
      drain_duration_ratio{drainDurationRatioIn},
      probebw_duration_ratio{probebwDurationRatioIn},
      probertt_duration_ratio{proberttDurationRatioIn},
      not_recovery_duration_ratio {NotRecoveryDurationRatioIn},
      growth_duration_ratio {GrowthDurationRatioIn},
      conservation_duration_ratio {ConservationDurationRatioIn},
      average_difference {AverageDifferenceIn} {
  event_type_ = QLogEventType::TRANSPORT_SUMMARY;
  ref_time_ = ref_time_in;
}

Document QLogTransportSummaryEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("total_bytes_sent",
                  total_bytes_sent,
                  j_allocator);
  value.AddMember("reatotal_packets_sentson",
                  total_packets_sent,
                  j_allocator);
  value.AddMember("total_bytes_recvd",
                  total_bytes_recvd,
                  j_allocator);
  value.AddMember("total_packets_recvd",
                  total_packets_recvd,
                  j_allocator);
  value.AddMember("sum_cur_write_offset",
                  sum_cur_write_offset,
                  j_allocator);
  value.AddMember("sum_max_observed_offset",
                  sum_max_observed_offset,
                  j_allocator);
  value.AddMember("sum_cur_stream_buffer_len",
                  sum_cur_stream_buffer_len,
                  j_allocator);
  value.AddMember("total_packets_lost",
                  total_packets_lost,
                  j_allocator);
  value.AddMember("total_stream_bytes_cloned",
                  total_stream_bytes_cloned,
                  j_allocator);
  value.AddMember("total_bytes_cloned",
                  total_bytes_cloned,
                  j_allocator);
  value.AddMember("total_crypto_data_written",
                  total_crypto_data_written,
                  j_allocator);
  value.AddMember("total_crypto_data_recvd",
                  total_crypto_data_recvd,
                  j_allocator);                
  value.AddMember("current_writable_bytes",
                  current_writable_bytes,
                  j_allocator);
  value.AddMember("current_conn_flow_control",
                  current_conn_flow_control,
                  j_allocator);
  value.AddMember("used_zero_rtt",
                  used_zero_rtt,
                  j_allocator);
  value.AddMember("quic_version",
                  Value(QuicVersionToString(quic_version).c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogBBRCongestionMetricUpdateEvent::QLogBBRCongestionMetricUpdateEvent(
    uint64_t bytes_in_flight_in,
    uint64_t current_cwnd_in,
    std::string congestion_event_in,
    CongestionControlType type_in,
    void* state_in,
    std::chrono::microseconds ref_time_in)
    : bytes_inflight_{bytes_in_flight_in},
      current_cwnd_{current_cwnd_in},
      congestion_event_{std::move(congestion_event_in)},
      type_{type_in},
      state{state_in} {
  event_type_ = QLogEventType::CONGESTION_METRIC_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogBBRCongestionMetricUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("bytes_in_flight",
                  bytes_inflight_,
                  j_allocator);
  value.AddMember("current_cwnd",
                  current_cwnd_,
                  j_allocator);
  value.AddMember("congestion_event",
                  Value(congestion_event_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("congestion_control_type",
                  Value(toQlogString(type_).data(), j_allocator).Move(),
                  j_allocator);
  if (type_ == kBBR) {
    BbrSender::DebugState* bbr_state =
	    static_cast<BbrSender::DebugState*>(state);
    Value tmp_object(kObjectType);
    tmp_object.AddMember("mode",
                         Value(toQlogString(bbr_state->mode).data(), j_allocator).Move(),
                         j_allocator);
    tmp_object.AddMember("max_bandwidth",
                         bbr_state->max_bandwidth.ToKBitsPerSecond(),
                         j_allocator);
    tmp_object.AddMember("round_trip_counter",
                         bbr_state->round_trip_count,
                         j_allocator);
    tmp_object.AddMember("gain_cycle_index",
                         static_cast<int>(bbr_state->gain_cycle_index),
                         j_allocator);
    tmp_object.AddMember("min_rtt",
                         bbr_state->min_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("latest_rtt",
                         bbr_state->latest_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("smoothed_rtt",
                         bbr_state->smoothed_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("mean_deviation",
                         bbr_state->mean_deviation.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("recovery_state",
                         Value(toQlogString(bbr_state->recovery_state).data(), j_allocator).Move(),
                         j_allocator); 
    value.AddMember("state",
                    tmp_object,
                    j_allocator);
  }

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogCubicCongestionMetricUpdateEvent::QLogCubicCongestionMetricUpdateEvent(
    uint64_t bytes_in_flight_in,
    uint64_t current_cwnd_in,
    std::string congestion_event_in,
    CongestionControlType type_in,
    void* state_in,
    std::chrono::microseconds ref_time_in)
    : bytes_inflight_{bytes_in_flight_in},
      current_cwnd_{current_cwnd_in},
      congestion_event_{std::move(congestion_event_in)},
      type_{type_in},
      state{state_in} {
  event_type_ = QLogEventType::CONGESTION_METRIC_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogCubicCongestionMetricUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();

  value.AddMember("bytes_in_flight",
                  bytes_inflight_,
                  j_allocator);
  value.AddMember("current_cwnd",
                  current_cwnd_,
                  j_allocator);
  value.AddMember("congestion_event",
                  Value(congestion_event_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("congestion_control_type",
                  Value(toQlogString(type_).data(), j_allocator).Move(),
                  j_allocator);
  if (type_ == kCubicBytes) {
    TcpCubicSenderBytes::DebugState* cubic_state =
	    static_cast<TcpCubicSenderBytes::DebugState*>(state);
    Value tmp_object(kObjectType);
    tmp_object.AddMember("min_rtt",
                         cubic_state->min_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("latest_rtt",
                         cubic_state->latest_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("smoothed_rtt",
                         cubic_state->smoothed_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("mean_deviation",
                         cubic_state->mean_deviation.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("bandwidth_est",
                      cubic_state->bandwidth_est.ToKBitsPerSecond(),
                      j_allocator);
    value.AddMember("state",
                    tmp_object,
                    j_allocator);

  }
  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogBBR2CongestionMetricUpdateEvent::QLogBBR2CongestionMetricUpdateEvent(
    uint64_t bytes_in_flight_in,
    uint64_t current_cwnd_in,
    std::string congestion_event_in,
    CongestionControlType type_in,
    void* state_in,
    std::chrono::microseconds ref_time_in)
    : bytes_inflight_{bytes_in_flight_in},
      current_cwnd_{current_cwnd_in},
      congestion_event_{std::move(congestion_event_in)},
      type_{type_in},
      state{state_in} {
  event_type_ = QLogEventType::CONGESTION_METRIC_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogBBR2CongestionMetricUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  Value value;
  value.SetObject();
  value.AddMember("bytes_in_flight",
                  bytes_inflight_,
                  j_allocator);
  value.AddMember("current_cwnd",
                  current_cwnd_,
                  j_allocator);
  value.AddMember("congestion_event",
                  Value(congestion_event_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("congestion_control_type",
                  Value(toQlogString(type_).data(), j_allocator).Move(),
                  j_allocator);

  if (type_ == kBBRv2) {
    Bbr2Sender::DebugState* bbr2_state =
	    static_cast<Bbr2Sender::DebugState*>(state);
    Value tmp_object(kObjectType);
    tmp_object.AddMember("mode",
                         Value(toQlogString(bbr2_state->mode).data(), j_allocator).Move(),
                         j_allocator);
    tmp_object.AddMember("bandwidth_hi",
                         bbr2_state->bandwidth_hi.ToKBitsPerSecond(),
                         j_allocator);
    tmp_object.AddMember("bandwidth_lo",
                         bbr2_state->bandwidth_lo.ToKBitsPerSecond(),
                         j_allocator);
    tmp_object.AddMember("bandwidth_est",
                         bbr2_state->bandwidth_est.ToKBitsPerSecond(),
                         j_allocator);
    tmp_object.AddMember("round_trip_counter",
                         bbr2_state->round_trip_count,
                         j_allocator);
    tmp_object.AddMember("min_rtt",
                         bbr2_state->min_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("latest_rtt",
                         bbr2_state->latest_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("smoothed_rtt",
                         bbr2_state->smoothed_rtt.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("mean_deviation",
                         bbr2_state->mean_deviation.ToMicroseconds(),
                         j_allocator);
    tmp_object.AddMember("inflight_hi",
                         bbr2_state->inflight_hi,
                         j_allocator);
    tmp_object.AddMember("inflight_lo",
                         bbr2_state->inflight_lo,
                         j_allocator);

    value.AddMember("state",
                    tmp_object,
                    j_allocator);
  }

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}


QLogRequestOverStreamEvent::QLogRequestOverStreamEvent(
    std::string method_in,
    QuicStreamId stream_id_in,
    std::string uri_in,
    std::string range_in,
    std::chrono::microseconds ref_time_in)
    : stream_id_{stream_id_in},
      method_{std::move(method_in)},
      uri_{std::move(uri_in)},
      range_{std::move(range_in)} {
  event_type_ = QLogEventType::REQUEST_OVER_STREAM;
  ref_time_ = ref_time_in;
}

Document QLogRequestOverStreamEvent::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("stream_id",
                  stream_id_,
                  j_allocator);
  value.AddMember("method",
                  Value(method_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("uri",
                  Value(uri_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("range",
                  Value(range_.c_str(),j_allocator).Move(),
                  j_allocator);              
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("application", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogAppLimitedUpdateEvent::QLogAppLimitedUpdateEvent(
    bool limited_in,
    std::chrono::microseconds ref_time_in)
    : limited(limited_in) {
  event_type_ = QLogEventType::APP_LIMITED_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogAppLimitedUpdateEvent::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("app_limited",
                  Value(limited ? kAppLimited : kAppUnlimited, j_allocator).Move(),
                  j_allocator);
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("APP_LIMITED_UPDATE", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogBandwidthEstUpdateEvent::QLogBandwidthEstUpdateEvent(
    uint64_t bytesIn,
    std::chrono::microseconds intervalIn,
    std::chrono::microseconds ref_time_in)
    : bytes_(bytesIn), interval_(intervalIn) {
  ref_time_ = ref_time_in;
  event_type_ = QLogEventType::BANDWIDTH_ESTUPDATE;
}

Document QLogBandwidthEstUpdateEvent::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("bandwidth_bytes",
                  bytes_,
                  j_allocator);
  value.AddMember("bandwidth_interval",
                  interval_.count(),
                  j_allocator);                  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("BANDIWDTH_EST_UPDATE", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacingMetricUpdateEvent::QLogPacingMetricUpdateEvent(
    uint64_t pacing_burst_size_in,
    std::chrono::microseconds pacing_interval_in,
    std::chrono::microseconds ref_time_in)
    : pacing_burst_size_{pacing_burst_size_in}, pacing_interval_{pacing_interval_in} {
  event_type_ = QLogEventType::PACING_METRIC_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogPacingMetricUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("pacing_burst_size",
                  pacing_burst_size_,
                  j_allocator);
  value.AddMember("pacing_interval",
                  pacing_interval_.count(),
                  j_allocator);                  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacingObservationEvent::QLogPacingObservationEvent(
    std::string& actual_in,
    std::string& expect_in,
    std::string& conclusion_in,
    std::chrono::microseconds ref_time_in)
    : actual_(actual_in),
      expect_(expect_in),
      conclusion_(conclusion_in) {
  event_type_ = QLogEventType::PACING_OBSERVATION;
  ref_time_ = ref_time_in;
}

// TODO: Sad. I wanted moved all the string into the dynamic but this function
// is const. I think we should make all the toDynamic rvalue qualified since
// users are not supposed to use them after ToJson() is called.
Document QLogPacingObservationEvent::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("actual_pacing_rate",
                  Value(actual_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("expect_pacing_rate",
                  Value(expect_.c_str(), j_allocator).Move(),
                  j_allocator);     
  value.AddMember("conclusion",
                  Value(conclusion_.c_str(), j_allocator).Move(),
                  j_allocator);                                 
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogAppIdleUpdateEvent::QLogAppIdleUpdateEvent(
    std::string& idleEventIn,
    bool idleIn,
    std::chrono::microseconds ref_time_in)
    : idle_event_{idleEventIn}, idle_{idleIn} {
  event_type_ = QLogEventType::APPIDLE_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogAppIdleUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("idle_event",
                  Value(idle_event_.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("idle",
                  idle_,
                  j_allocator);                                    
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("idle_update", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketDropEvent::QLogPacketDropEvent(
    size_t packetSizeIn,
    std::string& drop_reason_in,
    std::chrono::microseconds ref_time_in)
    : packet_size_{packetSizeIn}, drop_reason_{drop_reason_in} {
  event_type_ = QLogEventType::PACKET_DROP;
  ref_time_ = ref_time_in;
}

Document QLogPacketDropEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("packet_size",
                  packet_size_,
                  j_allocator);
  value.AddMember("drop_reason",
                  Value(drop_reason_.c_str(), j_allocator).Move(),
                  j_allocator);                                             
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("loss", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
} // namespace quic

QLogDatagramReceivedEvent::QLogDatagramReceivedEvent(
    uint64_t data_len,
    std::chrono::microseconds ref_time_in)
    : data_len_{data_len} {
  event_type_ = QLogEventType::DATAGRAM_RECEIVED;
  ref_time_ = ref_time_in;
}

Document QLogDatagramReceivedEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("data_len",
                  data_len_,
                  j_allocator);                                          
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogLossAlarmEvent::QLogLossAlarmEvent(
    uint64_t largestSentIn,
    uint64_t alarmCountIn,
    uint64_t outstandingPacketsIn,
    std::string& type_in,
    std::chrono::microseconds ref_time_in)
    : largest_sent_{largestSentIn},
      alarm_count_{alarmCountIn},
      outstanding_packets_{outstandingPacketsIn},
      type_{type_in} {
  event_type_ = QLogEventType::LOSS_ALARM;
  ref_time_ = ref_time_in;
}

Document QLogLossAlarmEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("largest_sent",
                  largest_sent_,
                  j_allocator); 
  value.AddMember("alarm_count",
                  alarm_count_,
                  j_allocator); 
  value.AddMember("outstanding_packets",
                  outstanding_packets_,
                  j_allocator);  
  value.AddMember("type",
                  Value(type_.c_str(), j_allocator).Move(),
                  j_allocator);                                                                                                   
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("loss", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketLostEvent::QLogPacketLostEvent(
    uint64_t lostPacketNumIn,
    EncryptionLevel encryptionLevelIn,
    TransmissionType transmissionTypeIn,
    std::chrono::microseconds ref_time_in)
    : lost_packet_num_{lostPacketNumIn},
      encryption_level_{encryptionLevelIn},
      transmission_type_{transmissionTypeIn} {
  event_type_ = QLogEventType::PACKET_LOST;
  ref_time_ = ref_time_in;
}

Document QLogPacketLostEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("lost_packet_num",
                  lost_packet_num_,
                  j_allocator); 
  value.AddMember("encryption_level",
                  Value(toQlogString(encryption_level_).data(), j_allocator).Move(),
                  j_allocator); 
  value.AddMember("transmission_type",
                  transmission_type_,
                  j_allocator);                                                                                                    
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("loss", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogTransportStateUpdateEvent::QLogTransportStateUpdateEvent(
    std::string& updateIn,
    std::chrono::microseconds ref_time_in)
    : update_{updateIn} {
  event_type_ = QLogEventType::TRANSPORT_STATE_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogTransportStateUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("update",
                  Value(update_.c_str(), j_allocator).Move(),
                  j_allocator);                                                                                                  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketBufferedEvent::QLogPacketBufferedEvent(
    uint64_t packetNumIn,
    EncryptionLevel encryptionLevelIn,
    uint64_t packetSizeIn,
    std::chrono::microseconds ref_time_in)
    : packet_num_{packetNumIn},
      encryption_level_{encryptionLevelIn},
      packet_size_{packetSizeIn} {
  event_type_ = QLogEventType::Packet_Buffered;
  ref_time_ = ref_time_in;
}

Document QLogPacketBufferedEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("packet_num",
                  packet_num_,
                  j_allocator);    
  value.AddMember("encryption_level",
                  Value(toQlogString(encryption_level_).data(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("packet_size",
                  packet_size_,
                  j_allocator);                                                                                                                    
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketAckEvent::QLogPacketAckEvent(
    PacketNumberSpace packetNumSpaceIn,
    uint64_t packetNumIn,
    std::chrono::microseconds ref_time_in)
    : packet_num_space_{packetNumSpaceIn}, packet_num_{packetNumIn} {
  event_type_ = QLogEventType::PACKET_ACK;
  ref_time_ = ref_time_in;
}

Document QLogPacketAckEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("packet_num_space",
                  Value(quiche::QuicheTextUtilsImpl::Uint64ToString(packet_num_space_).c_str(), j_allocator).Move(),
                  j_allocator);    
  value.AddMember("packet_num",
                  packet_num_,
                  j_allocator);                                                                                                                 
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogMetricUpdateEvent::QLogMetricUpdateEvent(
    std::chrono::microseconds latestRttIn,
    std::chrono::microseconds mrttIn,
    std::chrono::microseconds srttIn,
    std::chrono::microseconds ack_delay_in,
    std::chrono::microseconds ref_time_in)
    : latest_rtt_{latestRttIn}, mrtt_{mrttIn}, srtt_{srttIn}, ack_delay_{ack_delay_in} {
  event_type_ = QLogEventType::METRIC_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogMetricUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("latest_rtt",
                  latest_rtt_.count(),
                  j_allocator);    
  value.AddMember("min_rtt",
                  mrtt_.count(),
                  j_allocator);   
  value.AddMember("smoothed_rtt",
                  srtt_.count(),
                  j_allocator); 
  value.AddMember("ack_delay",
                  ack_delay_.count(),
                  j_allocator);                                                                                                                                                   
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("recovery", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogStreamStateUpdateEvent::QLogStreamStateUpdateEvent(
    QuicStreamId idIn,
    std::string& updateIn,
    quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreationIn,
    VantagePoint vantage_point,
    std::chrono::microseconds ref_time_in)
    : id_{idIn},
      update_{updateIn},
      time_since_stream_creation_(std::move(timeSinceStreamCreationIn)),
      vantagePoint_(vantage_point) {
  event_type_ = QLogEventType::STREAM_STATE_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogStreamStateUpdateEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("id",
                  id_,
                  j_allocator);    
  value.AddMember("update",
                  Value(update_.c_str(), j_allocator).Move(),
                  j_allocator);   
  if (time_since_stream_creation_) {
    if (update_ == kOnEOM && vantagePoint_ == VantagePoint::IS_CLIENT) {
      value.AddMember("ttlb",
                      time_since_stream_creation_->count(),
                      j_allocator);
    } else if (update_ == kOnHeaders && vantagePoint_ == VantagePoint::IS_CLIENT) {
      value.AddMember("ttfb",
                      time_since_stream_creation_->count(),
                      j_allocator);      
    } else {
      value.AddMember("ms_since_creation",
                      time_since_stream_creation_->count(),
                      j_allocator);
    }
  }                                                                                                                                                 
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("HTTP3", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogConnectionMigrationEvent::QLogConnectionMigrationEvent(
    bool intentional_migration,
    VantagePoint vantage_point,
    std::chrono::microseconds ref_time_in)
    : intentional_Migration_{intentional_migration}, vantagePoint_(vantage_point) {
  event_type_ = QLogEventType::CONNECTION_MIGRATION;
  ref_time_ = ref_time_in;
}

Document QLogConnectionMigrationEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("intentional",
                  intentional_Migration_,
                  j_allocator);
  if (vantagePoint_ == VantagePoint::IS_CLIENT) {
    value.AddMember("type",
                    "initiating",
                    j_allocator);
  } else {
    value.AddMember("type",
                    "accepting",
                    j_allocator);  
  }                                                                                                                                                         
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPathValidationEvent::QLogPathValidationEvent(
    bool success,
    VantagePoint vantage_point,
    std::chrono::microseconds ref_time_in)
    : success_{success}, vantagePoint_(vantage_point) {
  event_type_ = QLogEventType::PATH_VALIDATION;
  ref_time_ = ref_time_in;
}

Document QLogPathValidationEvent::ToJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("success",
                  success_,
                  j_allocator);  
  if (vantagePoint_ == VantagePoint::IS_CLIENT) {
    value.AddMember("vantage_point",
                    "client",
                    j_allocator);
  } else {
    value.AddMember("vantage_point",
                    "server",
                    j_allocator);
  }                                                                                                                                             
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPriorityUpdateEvent::QLogPriorityUpdateEvent(
    QuicStreamId stream_id,
    uint8_t urgency,
    bool incremental,
    std::chrono::microseconds ref_time_in)
    : streamId_(stream_id), urgency_(urgency), incremental_(incremental) {
  event_type_ = QLogEventType::PRIORITY_UPDATE;
  ref_time_ = ref_time_in;
}

Document QLogPriorityUpdateEvent::ToJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("id",
                  streamId_,
                  j_allocator);
  value.AddMember("urgency",
                  urgency_,
                  j_allocator);
  value.AddMember("incremental",
                  "incremental_",
                  j_allocator);                                                                                                                                       
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(ref_time_.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("HTTP3", j_allocator);
  j.PushBack(Value(ToString(event_type_).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

quiche::QuicheStringPiece ToString(QLogEventType type) {
  switch (type) {
    case QLogEventType::PACKET_SENT:
      return "packet_sent";
    case QLogEventType::PACKET_RECEIVED:
      return "packet_received";
    case QLogEventType::CONNECTION_CLOSE:
      return "connection_close";
    case QLogEventType::TRANSPORT_SUMMARY:
      return "transport_summary";
    case QLogEventType::CONGESTION_METRIC_UPDATE:
      return "congestion_metric_update";
    case QLogEventType::PACING_METRIC_UPDATE:
      return "pacing_metric_update";
    case QLogEventType::APPIDLE_UPDATE:
      return "app_idle_update";
    case QLogEventType::PACKET_DROP:
      return "packet_drop";
    case QLogEventType::DATAGRAM_RECEIVED:
      return "datagram_received";
    case QLogEventType::LOSS_ALARM:
      return "loss_alarm";
    case QLogEventType::PACKET_LOST:
      return "packet_lost";
    case QLogEventType::TRANSPORT_STATE_UPDATE:
      return "transport_state_update";
    case QLogEventType::Packet_Buffered:
      return "packet_buffered";
    case QLogEventType::PACKET_ACK:
      return "packet_ack";
    case QLogEventType::METRIC_UPDATE:
      return "metric_update";
    case QLogEventType::STREAM_STATE_UPDATE:
      return "stream_state_update";
    case QLogEventType::PACING_OBSERVATION:
      return "pacing_observation";
    case QLogEventType::APP_LIMITED_UPDATE:
      return "app_limited_update";
    case QLogEventType::BANDWIDTH_ESTUPDATE:
      return "bandwidth_est_update";
    case QLogEventType::CONNECTION_MIGRATION:
      return "connection_migration";
    case QLogEventType::PATH_VALIDATION:
      return "path_validation";
    case QLogEventType::PRIORITY_UPDATE:
      return "priority";
    case QLogEventType::FRAMES_PROCESSED:
      return "frames_processed";
    case QLogEventType::REQUEST_OVER_STREAM:
      return "http_request";
    default:
      return "unknown_event_type";
  }
}
} // namespace quic
