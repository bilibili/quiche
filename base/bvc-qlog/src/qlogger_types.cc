#include "base/bvc-qlog/src/qlogger_types.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "gquiche/quic/core/quic_error_codes.h"

namespace quic {

Document QLogFrame::toShortJson() const {
  Document j;
  return j;
}

Document PaddingFrameLog::toJson() const {
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

Document RstStreamFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::RST_STREAM_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              streamId,
              j_allocator);
  j.AddMember("error_code",
              errorCode,
              j_allocator);
  j.AddMember("offset",
              offset,
              j_allocator);
  return j;
}

Document ConnectionCloseFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::CONNECTION_CLOSE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("wire_error_code",
              wireErrorCode,
              j_allocator);
  j.AddMember("quic_error_code",
              Value(QuicErrorCodeToString(quicErrorCode), j_allocator).Move(),
              j_allocator);
  j.AddMember("error_details",
              Value(errorDetails.c_str(), j_allocator).Move(),
              j_allocator);
  j.AddMember("close_type",
              Value((toQlogString(closeType)).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("transport_closing_frame_type",
              transportCloseFrameType,
              j_allocator);
  return j;
}

Document GoAwayFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::GOAWAY_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("error_code",
              Value(QuicErrorCodeToString(errorCode), j_allocator).Move(),
              j_allocator);
  j.AddMember("reason_phrase",
              Value(reasonPhrase.c_str(), j_allocator).Move(),
              j_allocator);
  j.AddMember("last_good_stream_id",
              lastGoodStreamId,
              j_allocator);
  return j;
}

Document WindowUpdateFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::WINDOW_UPDATE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              streamId,
              j_allocator);
  j.AddMember("max_data",
              maxData,
              j_allocator);
  return j;
}

Document BlockedFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::BLOCKED_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              streamId,
              j_allocator);
  return j;
}

Document StopWaitingFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STOP_WAITING_FRAME).data(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document PingFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PING_FRAME).data(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document AckFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();

  Value value;
  value.SetArray();

  Value temp_value;
  for (auto interval : packetNumberQueue) {
    temp_value.SetArray();      
    //*: Because the interval uses half-closed range `[)` and causes confusion,
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
              ackDelay.count(),
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
  for (auto interval : packetNumberQueue) {
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
  j.PushBack(ackDelay.count(), j_allocator);
  return j;
}

Document StreamFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STREAM_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              streamId,
              j_allocator);
  j.AddMember("offset",
              offset,
              j_allocator);
  j.AddMember("length",
              len,
              j_allocator);
  j.AddMember("fin",
              fin,
              j_allocator);              
  return j;
}

Document StreamFrameLog::toShortJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.PushBack(streamId, j_allocator);
  j.PushBack(offset, j_allocator);
  j.PushBack(len, j_allocator);
  j.PushBack(fin, j_allocator); 
  return j;
}

Document CryptoFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();
  j.AddMember("encryption_level",
              Value(toQlogString(level).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::CRYPTO_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("offset",
              offset,
              j_allocator);
  j.AddMember("data_length",
              dataLength,
              j_allocator);
  return j;
}

Document HandshakeDoneFrameLog::toJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::HANDSHAKE_DONE_FRAME).data(), j.GetAllocator()).Move(),
              j.GetAllocator());
  return j;
}

Document MTUDiscoveryFrameLog::toJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::MTU_DISCOVERY_FRAME).data(), j.GetAllocator()).Move(),
              j.GetAllocator());
  return j;
}

Document NewConnectionIdFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();    
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::NEW_CONNECTION_ID_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("sequence",
              sequenceNumber,
              j_allocator);
  return j;
}

Document MaxStreamsFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::MAX_STREAMS_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("max_streams",
              streamCount,
              j_allocator);
  j.AddMember("direction",
              Value(unidirectional ? "unidirectional" : "bidirectional", j_allocator).Move(),
              j_allocator);
  return j;
}

Document StreamsBlockedFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STREAMS_BLOCKED_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("max_streams",
              streamCount,
              j_allocator);
  j.AddMember("direction",
              Value(unidirectional ? "unidirectional" : "bidirectional", j_allocator).Move(),
              j_allocator);
  return j;
}

Document PathResponseFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PATH_RESPONSE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("path_data",
              Value(pathData.c_str(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document PathChallengeFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::PATH_CHALLENGE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("path_data",
              Value(pathData.c_str(), j_allocator).Move(),
              j_allocator);
  return j;
}

Document StopSendingFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::STOP_SENDING_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("stream_id",
              streamId,
              j_allocator);
  j.AddMember("error_code",
              Value(QuicRstStreamErrorCodeToString(errorCode), j_allocator).Move(),
              j_allocator);
  return j;
}

Document MessageFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::MESSAGE_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("message_id",
              messageId,
              j_allocator);
  j.AddMember("length",
              length,
              j_allocator);
  return j;
}

Document NewTokenFrameLog::toJson() const {
  Document j;
  j.SetObject();
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::NEW_TOKEN_FRAME).data(), j.GetAllocator()).Move(),
              j.GetAllocator());
  return j;
}

Document RetireConnectionIdFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::RETIRE_CONNECTION_ID_FRAME).data(), j_allocator).Move(),
              j_allocator);
  j.AddMember("sequence",
              sequenceNumber,
              j_allocator);
  return j;
}

Document AckFrequencyFrameLog::toJson() const {
  Document j;
  j.SetObject();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.AddMember("frame_type",
              Value(toQlogString(QuicFrameType::ACK_FREQUENCY_FRAME).data(), j_allocator ).Move(),
              j_allocator);
  j.AddMember("sequence_number",
              sequenceNumber,
              j_allocator);
  j.AddMember("packet_tolerance",
              packetTolerance,
              j_allocator);
  j.AddMember("update_max_ack_delay",
              updateMaxAckDelay,
              j_allocator);
  j.AddMember("ignore_order",
              ignoreOrder,
              j_allocator);
  return j;
}

Document VersionNegotiationLog::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  for (const auto& v : versions) {
    j.PushBack(Value(ParsedQuicVersionToString(v).c_str(), j_allocator).Move(), j_allocator);
  }
  return j;
}

Document QLogFramesProcessed::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);

  Value value;
  value.SetObject();
  value.AddMember("frames_type",
                  Value(toQlogString(framesType).data(), j_allocator).Move(),
                  j_allocator);

  //frames_fields
  Value tmp_arr;
  tmp_arr.SetArray();
  switch(framesType) {
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
  for (const auto& frame : frames) {
    tmp_arr.PushBack(Value().CopyFrom(frame->toShortJson(), j_allocator).Move(), j_allocator);  
  }
  value.AddMember("frames",
                  tmp_arr,
                  j_allocator);

  tmp_arr.SetArray();
  for (const auto& packetSize : packetSizes) {
    tmp_arr.PushBack(packetSize, j_allocator);
  }
  value.AddMember("packetSizes",
                  tmp_arr,
                  j_allocator);

  tmp_arr.SetArray();
  for (const auto& timeDrift : timeDrifts) {
    tmp_arr.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(timeDrift.count()).c_str(), j_allocator).Move(), j_allocator);
  }
  value.AddMember("timeDrift",
                  tmp_arr,
                  j_allocator);


  tmp_arr.SetArray();
  for (const auto& packetNum : packetNums) {
    tmp_arr.PushBack(packetNum, j_allocator);
  }
  value.AddMember("packetNums",
                  tmp_arr,
                  j_allocator);

  value.AddMember("packet_type",
                  Value(packetType.c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(value, j_allocator);
  return j;
}

Document QLogPacketEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);

  Value tmp_object, tmp_arr;
  tmp_object.SetObject();
  tmp_arr.SetArray();
  tmp_object.AddMember("packet_size",
                       packetSize,
                       j_allocator);  
  if (packetType != toQlogString(QuicLongHeaderType::RETRY)) {
    tmp_object.AddMember("packet_number",
                         packetNum,
                         j_allocator);

    for (const auto& frame : frames) {
      tmp_arr.PushBack(Value().CopyFrom(frame->toJson(), j_allocator).Move(), j_allocator);
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
                  Value(packetType.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("transmission_type",
                  Value(transmissionType.c_str(), j_allocator).Move(),
                  j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

Document QLogVersionNegotiationEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value tmp_object;
  tmp_object.SetObject();
  tmp_object.AddMember("packet_size",
                       packetSize,
                       j_allocator);  

  Value value;
  value.SetObject();
  value.AddMember("versions",
                  versionLog->toJson(),
                  j_allocator);
  value.AddMember("header",
                  tmp_object,
                  j_allocator);
  value.AddMember("packet_type",
                  Value(packetType.c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

Document QLogRetryEvent::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value tmp_object;
  tmp_object.SetObject();
  tmp_object.AddMember("packet_size",
                       packetSize,
                       j_allocator);  

  Value value;
  value.SetObject();
  value.AddMember("header",
                  tmp_object,
                  j_allocator);
  value.AddMember("packet_type",
                  Value(packetType.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("token_size",
                  tokenSize,
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogConnectionCloseEvent::QLogConnectionCloseEvent(
    QuicErrorCode errorIn,
    std::string reasonIn,
    ConnectionCloseSource sourceIn,
    std::chrono::microseconds refTimeIn)
    : error{std::move(errorIn)},
      reason{std::move(reasonIn)},
      source{sourceIn} {
  eventType = QLogEventType::ConnectionClose;
  refTime = refTimeIn;
}

Document QLogConnectionCloseEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("error",
                  Value(QuicErrorCodeToString(error), j_allocator).Move(),
                  j_allocator);
  value.AddMember("reason",
                  Value(reason.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("source",
                  Value(ConnectionCloseSourceToString(source).c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("connectivity", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
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
    std::chrono::microseconds refTimeIn)
    : totalBytesSent{totalBytesSentIn},
      totalPacketsSent{totalPacketsSentIn},
      totalBytesRecvd{totalBytesRecvdIn},
      totalPacketsRecvd{totalPacketsRecvdIn},
      sumCurWriteOffset{sumCurWriteOffsetIn},
      sumMaxObservedOffset{sumMaxObservedOffsetIn},
      sumCurStreamBufferLen{sumCurStreamBufferLenIn},
      totalPacketsLost{totalPacketsLostIn},
      totalStartupDuration{totalStartupDurationIn},
      totalDrainDuration{totalDrainDurationIn},
      totalProbeBWDuration{totalProbeBWDurationIn},
      totalProbeRttDuration{totalProbeRttDurationIn},
      totalNotRecoveryDuration{totalNotRecoveryDurationIn},
      totalGrowthDuration{totalGrowthDurationIn},
      totalConservationDuration{totalConservationDurationIn},
      totalStreamBytesCloned{totalStreamBytesClonedIn},
      totalBytesCloned{totalBytesClonedIn},
      totalCryptoDataWritten{totalCryptoDataWrittenIn},
      totalCryptoDataRecvd{totalCryptoDataRecvdIn},
      currentWritableBytes{currentWritableBytesIn},
      currentConnFlowControl{currentConnFlowControlIn},
      usedZeroRtt{usedZeroRttIn},
      quicVersion{quicVersionIn},
      congestionType{congestionTypeIn},
      smoothedMinRtt{smoothedMinRttIn},
      smoothedMaxBandwidth{smoothedMaxBandwidthIn},
      startupDurationRatio{startupDurationRatioIn},
      drainDurationRatio{drainDurationRatioIn},
      probebwDurationRatio{probebwDurationRatioIn},
      proberttDurationRatio{proberttDurationRatioIn},
      NotRecoveryDurationRatio {NotRecoveryDurationRatioIn},
      GrowthDurationRatio {GrowthDurationRatioIn},
      ConservationDurationRatio {ConservationDurationRatioIn},
      AverageDifference {AverageDifferenceIn} {
  eventType = QLogEventType::TransportSummary;
  refTime = refTimeIn;
}

Document QLogTransportSummaryEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("total_bytes_sent",
                  totalBytesSent,
                  j_allocator);
  value.AddMember("reatotal_packets_sentson",
                  totalPacketsSent,
                  j_allocator);
  value.AddMember("total_bytes_recvd",
                  totalBytesRecvd,
                  j_allocator);
  value.AddMember("total_packets_recvd",
                  totalPacketsRecvd,
                  j_allocator);
  value.AddMember("sum_cur_write_offset",
                  sumCurWriteOffset,
                  j_allocator);
  value.AddMember("sum_max_observed_offset",
                  sumMaxObservedOffset,
                  j_allocator);
  value.AddMember("sum_cur_stream_buffer_len",
                  sumCurStreamBufferLen,
                  j_allocator);
  value.AddMember("total_packets_lost",
                  totalPacketsLost,
                  j_allocator);
  value.AddMember("total_stream_bytes_cloned",
                  totalStreamBytesCloned,
                  j_allocator);
  value.AddMember("total_bytes_cloned",
                  totalBytesCloned,
                  j_allocator);
  value.AddMember("total_crypto_data_written",
                  totalCryptoDataWritten,
                  j_allocator);
  value.AddMember("total_crypto_data_recvd",
                  totalCryptoDataRecvd,
                  j_allocator);                
  value.AddMember("current_writable_bytes",
                  currentWritableBytes,
                  j_allocator);
  value.AddMember("current_conn_flow_control",
                  currentConnFlowControl,
                  j_allocator);
  value.AddMember("used_zero_rtt",
                  usedZeroRtt,
                  j_allocator);
  value.AddMember("quic_version",
                  Value(QuicVersionToString(quicVersion).c_str(), j_allocator).Move(),
                  j_allocator);

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogBBRCongestionMetricUpdateEvent::QLogBBRCongestionMetricUpdateEvent(
    uint64_t bytesInFlightIn,
    uint64_t currentCwndIn,
    std::string congestionEventIn,
    CongestionControlType typeIn,
    void* stateIn,
    std::chrono::microseconds refTimeIn)
    : bytesInFlight{bytesInFlightIn},
      currentCwnd{currentCwndIn},
      congestionEvent{std::move(congestionEventIn)},
      type{typeIn},
      state{stateIn} {
  eventType = QLogEventType::CongestionMetricUpdate;
  refTime = refTimeIn;
}

Document QLogBBRCongestionMetricUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("bytes_in_flight",
                  bytesInFlight,
                  j_allocator);
  value.AddMember("current_cwnd",
                  currentCwnd,
                  j_allocator);
  value.AddMember("congestion_event",
                  Value(congestionEvent.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("congestion_control_type",
                  Value(toQlogString(type).data(), j_allocator).Move(),
                  j_allocator);
  if (type == kBBR) {
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

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogCubicCongestionMetricUpdateEvent::QLogCubicCongestionMetricUpdateEvent(
    uint64_t bytesInFlightIn,
    uint64_t currentCwndIn,
    std::string congestionEventIn,
    CongestionControlType typeIn,
    void* stateIn,
    std::chrono::microseconds refTimeIn)
    : bytesInFlight{bytesInFlightIn},
      currentCwnd{currentCwndIn},
      congestionEvent{std::move(congestionEventIn)},
      type{typeIn},
      state{stateIn} {
  eventType = QLogEventType::CongestionMetricUpdate;
  refTime = refTimeIn;
}

Document QLogCubicCongestionMetricUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();

  value.AddMember("bytes_in_flight",
                  bytesInFlight,
                  j_allocator);
  value.AddMember("current_cwnd",
                  currentCwnd,
                  j_allocator);
  value.AddMember("congestion_event",
                  Value(congestionEvent.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("congestion_control_type",
                  Value(toQlogString(type).data(), j_allocator).Move(),
                  j_allocator);
  if (type == kCubicBytes) {
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
  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogBBR2CongestionMetricUpdateEvent::QLogBBR2CongestionMetricUpdateEvent(
    uint64_t bytesInFlightIn,
    uint64_t currentCwndIn,
    std::string congestionEventIn,
    CongestionControlType typeIn,
    void* stateIn,
    std::chrono::microseconds refTimeIn)
    : bytesInFlight{bytesInFlightIn},
      currentCwnd{currentCwndIn},
      congestionEvent{std::move(congestionEventIn)},
      type{typeIn},
      state{stateIn} {
  eventType = QLogEventType::CongestionMetricUpdate;
  refTime = refTimeIn;
}

Document QLogBBR2CongestionMetricUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  
  Value value;
  value.SetObject();
  value.AddMember("bytes_in_flight",
                  bytesInFlight,
                  j_allocator);
  value.AddMember("current_cwnd",
                  currentCwnd,
                  j_allocator);
  value.AddMember("congestion_event",
                  Value(congestionEvent.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("congestion_control_type",
                  Value(toQlogString(type).data(), j_allocator).Move(),
                  j_allocator);

  if (type == kBBRv2) {
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

  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}


QLogRequestOverStreamEvent::QLogRequestOverStreamEvent(
    std::string methodIn,
    QuicStreamId streamIdIn,
    std::string uriIn,
    std::string rangeIn,
    std::chrono::microseconds refTimeIn)
    : streamId{streamIdIn},
      method{std::move(methodIn)},
      uri{std::move(uriIn)},
      range{std::move(rangeIn)} {
  eventType = QLogEventType::RequestOverStream;
  refTime = refTimeIn;
}

Document QLogRequestOverStreamEvent::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("stream_id",
                  streamId,
                  j_allocator);
  value.AddMember("method",
                  Value(method.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("uri",
                  Value(uri.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("range",
                  Value(range.c_str(),j_allocator).Move(),
                  j_allocator);              
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("application", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogAppLimitedUpdateEvent::QLogAppLimitedUpdateEvent(
    bool limitedIn,
    std::chrono::microseconds refTimeIn)
    : limited(limitedIn) {
  eventType = QLogEventType::AppLimitedUpdate;
  refTime = refTimeIn;
}

Document QLogAppLimitedUpdateEvent::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("app_limited",
                  Value(limited ? kAppLimited : kAppUnlimited, j_allocator).Move(),
                  j_allocator);
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("APP_LIMITED_UPDATE", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogBandwidthEstUpdateEvent::QLogBandwidthEstUpdateEvent(
    uint64_t bytesIn,
    std::chrono::microseconds intervalIn,
    std::chrono::microseconds refTimeIn)
    : bytes(bytesIn), interval(intervalIn) {
  refTime = refTimeIn;
  eventType = QLogEventType::BandwidthEstUpdate;
}

Document QLogBandwidthEstUpdateEvent::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("bandwidth_bytes",
                  bytes,
                  j_allocator);
  value.AddMember("bandwidth_interval",
                  interval.count(),
                  j_allocator);                  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("BANDIWDTH_EST_UPDATE", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacingMetricUpdateEvent::QLogPacingMetricUpdateEvent(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn,
    std::chrono::microseconds refTimeIn)
    : pacingBurstSize{pacingBurstSizeIn}, pacingInterval{pacingIntervalIn} {
  eventType = QLogEventType::PacingMetricUpdate;
  refTime = refTimeIn;
}

Document QLogPacingMetricUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("pacing_burst_size",
                  pacingBurstSize,
                  j_allocator);
  value.AddMember("pacing_interval",
                  pacingInterval.count(),
                  j_allocator);                  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacingObservationEvent::QLogPacingObservationEvent(
    std::string& actualIn,
    std::string& expectIn,
    std::string& conclusionIn,
    std::chrono::microseconds refTimeIn)
    : actual(actualIn),
      expect(expectIn),
      conclusion(conclusionIn) {
  eventType = QLogEventType::PacingObservation;
  refTime = refTimeIn;
}

// TODO: Sad. I wanted moved all the string into the dynamic but this function
// is const. I think we should make all the toDynamic rvalue qualified since
// users are not supposed to use them after toJson() is called.
Document QLogPacingObservationEvent::toJson() const {
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("actual_pacing_rate",
                  Value(actual.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("expect_pacing_rate",
                  Value(expect.c_str(), j_allocator).Move(),
                  j_allocator);     
  value.AddMember("conclusion",
                  Value(conclusion.c_str(), j_allocator).Move(),
                  j_allocator);                                 
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("metric_update", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogAppIdleUpdateEvent::QLogAppIdleUpdateEvent(
    std::string& idleEventIn,
    bool idleIn,
    std::chrono::microseconds refTimeIn)
    : idleEvent{idleEventIn}, idle{idleIn} {
  eventType = QLogEventType::AppIdleUpdate;
  refTime = refTimeIn;
}

Document QLogAppIdleUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("idle_event",
                  Value(idleEvent.c_str(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("idle",
                  idle,
                  j_allocator);                                    
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("idle_update", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketDropEvent::QLogPacketDropEvent(
    size_t packetSizeIn,
    std::string& dropReasonIn,
    std::chrono::microseconds refTimeIn)
    : packetSize{packetSizeIn}, dropReason{dropReasonIn} {
  eventType = QLogEventType::PacketDrop;
  refTime = refTimeIn;
}

Document QLogPacketDropEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("packet_size",
                  packetSize,
                  j_allocator);
  value.AddMember("drop_reason",
                  Value(dropReason.c_str(), j_allocator).Move(),
                  j_allocator);                                             
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("loss", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
} // namespace quic

QLogDatagramReceivedEvent::QLogDatagramReceivedEvent(
    uint64_t dataLen,
    std::chrono::microseconds refTimeIn)
    : dataLen{dataLen} {
  eventType = QLogEventType::DatagramReceived;
  refTime = refTimeIn;
}

Document QLogDatagramReceivedEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("data_len",
                  dataLen,
                  j_allocator);                                          
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogLossAlarmEvent::QLogLossAlarmEvent(
    uint64_t largestSentIn,
    uint64_t alarmCountIn,
    uint64_t outstandingPacketsIn,
    std::string& typeIn,
    std::chrono::microseconds refTimeIn)
    : largestSent{largestSentIn},
      alarmCount{alarmCountIn},
      outstandingPackets{outstandingPacketsIn},
      type{typeIn} {
  eventType = QLogEventType::LossAlarm;
  refTime = refTimeIn;
}

Document QLogLossAlarmEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("largest_sent",
                  largestSent,
                  j_allocator); 
  value.AddMember("alarm_count",
                  alarmCount,
                  j_allocator); 
  value.AddMember("outstanding_packets",
                  outstandingPackets,
                  j_allocator);  
  value.AddMember("type",
                  Value(type.c_str(), j_allocator).Move(),
                  j_allocator);                                                                                                   
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("loss", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketLostEvent::QLogPacketLostEvent(
    uint64_t lostPacketNumIn,
    EncryptionLevel encryptionLevelIn,
    TransmissionType transmissionTypeIn,
    std::chrono::microseconds refTimeIn)
    : lostPacketNum{lostPacketNumIn},
      encryptionLevel{encryptionLevelIn},
      transmissionType{transmissionTypeIn} {
  eventType = QLogEventType::PacketLost;
  refTime = refTimeIn;
}

Document QLogPacketLostEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("lost_packet_num",
                  lostPacketNum,
                  j_allocator); 
  value.AddMember("encryption_level",
                  Value(toQlogString(encryptionLevel).data(), j_allocator).Move(),
                  j_allocator); 
  value.AddMember("transmission_type",
                  transmissionType,
                  j_allocator);                                                                                                    
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("loss", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogTransportStateUpdateEvent::QLogTransportStateUpdateEvent(
    std::string& updateIn,
    std::chrono::microseconds refTimeIn)
    : update{updateIn} {
  eventType = QLogEventType::TransportStateUpdate;
  refTime = refTimeIn;
}

Document QLogTransportStateUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("update",
                  Value(update.c_str(), j_allocator).Move(),
                  j_allocator);                                                                                                  
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketBufferedEvent::QLogPacketBufferedEvent(
    uint64_t packetNumIn,
    EncryptionLevel encryptionLevelIn,
    uint64_t packetSizeIn,
    std::chrono::microseconds refTimeIn)
    : packetNum{packetNumIn},
      encryptionLevel{encryptionLevelIn},
      packetSize{packetSizeIn} {
  eventType = QLogEventType::PacketBuffered;
  refTime = refTimeIn;
}

Document QLogPacketBufferedEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("packet_num",
                  packetNum,
                  j_allocator);    
  value.AddMember("encryption_level",
                  Value(toQlogString(encryptionLevel).data(), j_allocator).Move(),
                  j_allocator);
  value.AddMember("packet_size",
                  packetSize,
                  j_allocator);                                                                                                                    
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPacketAckEvent::QLogPacketAckEvent(
    PacketNumberSpace packetNumSpaceIn,
    uint64_t packetNumIn,
    std::chrono::microseconds refTimeIn)
    : packetNumSpace{packetNumSpaceIn}, packetNum{packetNumIn} {
  eventType = QLogEventType::PacketAck;
  refTime = refTimeIn;
}

Document QLogPacketAckEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("packet_num_space",
                  Value(quiche::QuicheTextUtilsImpl::Uint64ToString(packetNumSpace).c_str(), j_allocator).Move(),
                  j_allocator);    
  value.AddMember("packet_num",
                  packetNum,
                  j_allocator);                                                                                                                 
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogMetricUpdateEvent::QLogMetricUpdateEvent(
    std::chrono::microseconds latestRttIn,
    std::chrono::microseconds mrttIn,
    std::chrono::microseconds srttIn,
    std::chrono::microseconds ackDelayIn,
    std::chrono::microseconds refTimeIn)
    : latestRtt{latestRttIn}, mrtt{mrttIn}, srtt{srttIn}, ackDelay{ackDelayIn} {
  eventType = QLogEventType::MetricUpdate;
  refTime = refTimeIn;
}

Document QLogMetricUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("latest_rtt",
                  latestRtt.count(),
                  j_allocator);    
  value.AddMember("min_rtt",
                  mrtt.count(),
                  j_allocator);   
  value.AddMember("smoothed_rtt",
                  srtt.count(),
                  j_allocator); 
  value.AddMember("ack_delay",
                  ackDelay.count(),
                  j_allocator);                                                                                                                                                   
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("recovery", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogStreamStateUpdateEvent::QLogStreamStateUpdateEvent(
    QuicStreamId idIn,
    std::string& updateIn,
    quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreationIn,
    VantagePoint vantagePoint,
    std::chrono::microseconds refTimeIn)
    : id{idIn},
      update{updateIn},
      timeSinceStreamCreation(std::move(timeSinceStreamCreationIn)),
      vantagePoint_(vantagePoint) {
  eventType = QLogEventType::StreamStateUpdate;
  refTime = refTimeIn;
}

Document QLogStreamStateUpdateEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("id",
                  id,
                  j_allocator);    
  value.AddMember("update",
                  Value(update.c_str(), j_allocator).Move(),
                  j_allocator);   
  if (timeSinceStreamCreation) {
    if (update == kOnEOM && vantagePoint_ == VantagePoint::IS_CLIENT) {
      value.AddMember("ttlb",
                      timeSinceStreamCreation->count(),
                      j_allocator);
    } else if (update == kOnHeaders && vantagePoint_ == VantagePoint::IS_CLIENT) {
      value.AddMember("ttfb",
                      timeSinceStreamCreation->count(),
                      j_allocator);      
    } else {
      value.AddMember("ms_since_creation",
                      timeSinceStreamCreation->count(),
                      j_allocator);
    }
  }                                                                                                                                                 
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("HTTP3", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogConnectionMigrationEvent::QLogConnectionMigrationEvent(
    bool intentionalMigration,
    VantagePoint vantagePoint,
    std::chrono::microseconds refTimeIn)
    : intentionalMigration_{intentionalMigration}, vantagePoint_(vantagePoint) {
  eventType = QLogEventType::ConnectionMigration;
  refTime = refTimeIn;
}

Document QLogConnectionMigrationEvent::toJson() const {
  // creating a json array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  Document j;
  j.SetArray();
  Document::AllocatorType& j_allocator = j.GetAllocator();  

  Value value;
  value.SetObject();
  value.AddMember("intentional",
                  intentionalMigration_,
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
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPathValidationEvent::QLogPathValidationEvent(
    bool success,
    VantagePoint vantagePoint,
    std::chrono::microseconds refTimeIn)
    : success_{success}, vantagePoint_(vantagePoint) {
  eventType = QLogEventType::PathValidation;
  refTime = refTimeIn;
}

Document QLogPathValidationEvent::toJson() const {
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
    value.AddMember("vantagePoint",
                    "client",
                    j_allocator);
  } else {
    value.AddMember("vantagePoint",
                    "server",
                    j_allocator);
  }                                                                                                                                             
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("transport", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

QLogPriorityUpdateEvent::QLogPriorityUpdateEvent(
    QuicStreamId streamId,
    uint8_t urgency,
    bool incremental,
    std::chrono::microseconds refTimeIn)
    : streamId_(streamId), urgency_(urgency), incremental_(incremental) {
  eventType = QLogEventType::PriorityUpdate;
  refTime = refTimeIn;
}

Document QLogPriorityUpdateEvent::toJson() const {
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
  j.PushBack(Value(quiche::QuicheTextUtilsImpl::Uint64ToString(refTime.count()).c_str(), j_allocator).Move(), j_allocator);
  j.PushBack("HTTP3", j_allocator);
  j.PushBack(Value(toString(eventType).data(), j_allocator).Move(), j_allocator);
  j.PushBack(value, j_allocator);
  return j;
}

quiche::QuicheStringPiece toString(QLogEventType type) {
  switch (type) {
    case QLogEventType::PacketSent:
      return "packet_sent";
    case QLogEventType::PacketReceived:
      return "packet_received";
    case QLogEventType::ConnectionClose:
      return "connection_close";
    case QLogEventType::TransportSummary:
      return "transport_summary";
    case QLogEventType::CongestionMetricUpdate:
      return "congestion_metric_update";
    case QLogEventType::PacingMetricUpdate:
      return "pacing_metric_update";
    case QLogEventType::AppIdleUpdate:
      return "app_idle_update";
    case QLogEventType::PacketDrop:
      return "packet_drop";
    case QLogEventType::DatagramReceived:
      return "datagram_received";
    case QLogEventType::LossAlarm:
      return "loss_alarm";
    case QLogEventType::PacketLost:
      return "packet_lost";
    case QLogEventType::TransportStateUpdate:
      return "transport_state_update";
    case QLogEventType::PacketBuffered:
      return "packet_buffered";
    case QLogEventType::PacketAck:
      return "packet_ack";
    case QLogEventType::MetricUpdate:
      return "metric_update";
    case QLogEventType::StreamStateUpdate:
      return "stream_state_update";
    case QLogEventType::PacingObservation:
      return "pacing_observation";
    case QLogEventType::AppLimitedUpdate:
      return "app_limited_update";
    case QLogEventType::BandwidthEstUpdate:
      return "bandwidth_est_update";
    case QLogEventType::ConnectionMigration:
      return "connection_migration";
    case QLogEventType::PathValidation:
      return "path_validation";
    case QLogEventType::PriorityUpdate:
      return "priority";
    case QLogEventType::FramesProcessed:
      return "frames_processed";
    case QLogEventType::RequestOverStream:
      return "http_request";
    default:
      return "unknown_event_type";
  }
}
} // namespace quic
