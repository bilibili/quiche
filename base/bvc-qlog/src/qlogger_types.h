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
  virtual Document toJson() const = 0;
  virtual Document toShortJson() const;
};

class PaddingFrameLog : public QLogFrame {
 public:
  PaddingFrameLog() = default;
  ~PaddingFrameLog() override = default;
  Document toJson() const override;
  Document toShortJson() const override;
};

class RstStreamFrameLog : public QLogFrame {
 public:
  QuicStreamId streamId;
  QuicRstStreamErrorCode errorCode;
  uint64_t offset;

  RstStreamFrameLog(
      QuicStreamId streamIdIn,
      QuicRstStreamErrorCode errorCodeIn,
      QuicStreamOffset offsetIn)
      : streamId{streamIdIn}, errorCode{errorCodeIn}, offset{offsetIn} {}

  ~RstStreamFrameLog() override = default;
  Document toJson() const override;
};

class ConnectionCloseFrameLog : public QLogFrame {
 public:
  QuicConnectionCloseType closeType;
  uint64_t wireErrorCode;
  QuicErrorCode quicErrorCode;
  std::string errorDetails;
  uint64_t transportCloseFrameType;

  ConnectionCloseFrameLog(
      QuicConnectionCloseType closeTypeIn,
      uint64_t wireErrorCodeIn,
      QuicErrorCode quicErrorCodeIn,
      std::string errorDetailsIn,
      uint64_t transportCloseFrameTypeIn)
      : closeType{closeTypeIn},
        wireErrorCode{wireErrorCodeIn},
	      quicErrorCode{quicErrorCodeIn},
        errorDetails(errorDetailsIn),
        transportCloseFrameType{transportCloseFrameTypeIn} {}

  ~ConnectionCloseFrameLog() override = default;
  Document toJson() const override;
};

class GoAwayFrameLog : public QLogFrame {
 public:
  QuicErrorCode errorCode;
  QuicStreamId lastGoodStreamId;
  std::string  reasonPhrase;

  GoAwayFrameLog(
      QuicErrorCode errorCodeIn,
      QuicStreamId lastGoodStreamIdIn,
      std::string reasonPhraseIn)
      : errorCode{errorCodeIn},
        lastGoodStreamId{lastGoodStreamIdIn},
        reasonPhrase{reasonPhraseIn} {}

  ~GoAwayFrameLog() override = default;
  Document toJson() const override;
};

class WindowUpdateFrameLog : public QLogFrame {
 public:
  QuicStreamId streamId;
  uint64_t maxData;

  WindowUpdateFrameLog(
      QuicStreamId streamIdIn,
      uint64_t maxDataIn)
      : streamId{streamIdIn},
	maxData{maxDataIn} {}

  ~WindowUpdateFrameLog() override = default;
  Document toJson() const override;
};

class BlockedFrameLog : public QLogFrame {
 public:
  QuicStreamId streamId;

  BlockedFrameLog(QuicStreamId streamIdIn)
  : streamId{streamIdIn} {}

  ~BlockedFrameLog() override = default;
  Document toJson() const override;
};

class StopWaitingFrameLog : public QLogFrame {
 public:
  StopWaitingFrameLog() = default;
  ~StopWaitingFrameLog() override = default;
  Document toJson() const override;
};

class PingFrameLog : public QLogFrame {
 public:
  PingFrameLog() = default;
  ~PingFrameLog() override = default;
  Document toJson() const override;
};

class AckFrameLog : public QLogFrame {
 public:
  PacketNumberQueue packetNumberQueue;
  std::chrono::microseconds ackDelay;

  AckFrameLog(
      const PacketNumberQueue packetNumberQueueIn,
      uint64_t ackDelayIn)
      : packetNumberQueue{packetNumberQueueIn}, ackDelay{ackDelayIn} {}
  ~AckFrameLog() override = default;
  Document toJson() const override;
  Document toShortJson() const override;
};

class StreamFrameLog : public QLogFrame {
 public:
  QuicStreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;

  StreamFrameLog(
      QuicStreamId streamIdIn,
      uint64_t offsetIn,
      uint64_t lenIn,
      bool finIn)
      : streamId{streamIdIn}, offset{offsetIn}, len{lenIn}, fin{finIn} {}
  ~StreamFrameLog() override = default;

  Document toJson() const override;
  Document toShortJson() const;
};

class CryptoFrameLog : public QLogFrame {
 public:
  EncryptionLevel level;
  uint64_t offset;
  uint64_t dataLength;

  CryptoFrameLog(
      EncryptionLevel levelIn,
      uint64_t offsetIn,
      uint64_t dataLengthIn)
      : level{levelIn}, offset{offsetIn}, dataLength{dataLengthIn} {}
  ~CryptoFrameLog() override = default;
  Document toJson() const override;
};

class HandshakeDoneFrameLog : public QLogFrame {
 public:
  HandshakeDoneFrameLog() = default;
  ~HandshakeDoneFrameLog() override = default;
  Document toJson() const override;
};

class MTUDiscoveryFrameLog : public QLogFrame {
 public:
  MTUDiscoveryFrameLog() = default;
  ~MTUDiscoveryFrameLog() override = default;
  Document toJson() const override;
};

class NewConnectionIdFrameLog : public QLogFrame {
 public:
  std::string newConnectionId;
  uint64_t sequenceNumber;

  NewConnectionIdFrameLog(
      std::string newConnectionIdIn,
      uint64_t sequenceNumberIn)
      : newConnectionId{newConnectionIdIn}, sequenceNumber{sequenceNumberIn} {}

  ~NewConnectionIdFrameLog() override = default;
  Document toJson() const override;
};

class MaxStreamsFrameLog : public QLogFrame {
 public:
  uint64_t streamCount;
  bool unidirectional;

  MaxStreamsFrameLog(
      uint64_t streamCountIn,
      bool unidirectionalIn)
      : streamCount{streamCountIn}, unidirectional{unidirectionalIn} {}

  ~MaxStreamsFrameLog() override = default;
  Document toJson() const override;
};

class StreamsBlockedFrameLog : public QLogFrame {
 public:
  uint64_t streamCount;
  bool unidirectional;

  StreamsBlockedFrameLog(
      uint64_t streamCountIn,
      bool unidirectionalIn)
      : streamCount{streamCountIn}, unidirectional{unidirectionalIn} {}

  ~StreamsBlockedFrameLog() override = default;
  Document toJson() const override;
};

class PathResponseFrameLog : public QLogFrame {
 public:
  std::string pathData;

  explicit PathResponseFrameLog(std::string pathDataIn) : pathData{pathDataIn} {}
  ~PathResponseFrameLog() override = default;
  Document toJson() const override;
};

class PathChallengeFrameLog : public QLogFrame {
 public:
  std::string pathData;

  explicit PathChallengeFrameLog(std::string pathDataIn) : pathData{pathDataIn} {}
  ~PathChallengeFrameLog() override = default;
  Document toJson() const override;
};

class StopSendingFrameLog : public QLogFrame {
 public:
  QuicStreamId streamId;
  QuicRstStreamErrorCode errorCode;

  StopSendingFrameLog(QuicStreamId streamIdIn, QuicRstStreamErrorCode errorCodeIn)
      : streamId{streamIdIn}, errorCode{errorCodeIn} {}
  ~StopSendingFrameLog() override = default;
  Document toJson() const override;
};

class MessageFrameLog : public QLogFrame {
 public:
  uint32_t messageId;
  uint64_t length;

  MessageFrameLog(uint32_t messageIdIn, uint64_t lengthIn)
      : messageId{messageIdIn}, length{lengthIn} {}
  ~MessageFrameLog() override = default;
  Document toJson() const override;
};

class NewTokenFrameLog : public QLogFrame {
 public:
  NewTokenFrameLog() = default;
  ~NewTokenFrameLog() override = default;
  Document toJson() const override;
};

class RetireConnectionIdFrameLog : public QLogFrame {
 public:
  uint64_t sequenceNumber;

  RetireConnectionIdFrameLog(uint64_t sequenceNumberIn)
  : sequenceNumber(sequenceNumberIn) {}

  ~RetireConnectionIdFrameLog() override = default;
  Document toJson() const override;
};

class AckFrequencyFrameLog : public QLogFrame {
 public:
  uint64_t sequenceNumber;
  uint64_t packetTolerance;
  uint64_t updateMaxAckDelay;
  bool ignoreOrder;

  explicit AckFrequencyFrameLog(
      uint64_t sequenceNumberIn,
      uint64_t packetToleranceIn,
      uint64_t updateMaxAckDelayIn,
      bool ignoreOrderIn)
      : sequenceNumber(sequenceNumberIn),
        packetTolerance(packetToleranceIn),
        updateMaxAckDelay(updateMaxAckDelayIn),
        ignoreOrder(ignoreOrderIn) {}
  ~AckFrequencyFrameLog() override = default;
  Document toJson() const override;
};

class VersionNegotiationLog {
 public:
  std::vector<ParsedQuicVersion> versions;

  explicit VersionNegotiationLog(const std::vector<ParsedQuicVersion>& versionsIn)
      : versions{versionsIn} {}
  ~VersionNegotiationLog() = default;
  Document toJson() const;
};

enum class QLogEventType : uint32_t {
  PacketReceived,
  PacketSent,
  ConnectionClose,
  TransportSummary,
  CongestionMetricUpdate,
  PacingMetricUpdate,
  AppIdleUpdate,
  PacketDrop,
  DatagramReceived,
  LossAlarm,
  PacketLost,
  TransportStateUpdate,
  PacketBuffered,
  PacketAck,
  MetricUpdate,
  StreamStateUpdate,
  PacingObservation,
  AppLimitedUpdate,
  BandwidthEstUpdate,
  ConnectionMigration,
  PathValidation,
  PriorityUpdate,
  FramesProcessed,
  RequestOverStream
};

quiche::QuicheStringPiece toString(QLogEventType type);

class QLogEvent {
 public:
  QLogEvent() = default;
  virtual ~QLogEvent() = default;
  virtual Document toJson() const = 0;
  std::chrono::microseconds refTime;
  QLogEventType eventType;
};

class QLogFramesProcessed : public QLogEvent {
  public:
  QLogFramesProcessed() = default;
  ~QLogFramesProcessed() override = default;
  quiche::QuicheStringPiece weaver;
  QuicFrameType framesType;
  std::vector<std::unique_ptr<QLogFrame>> frames;
  std::vector<uint64_t>  packetSizes;
  std::vector<uint64_t> packetNums;
  std::vector<std::chrono::microseconds> timeDrifts;
  std::string packetType;
  Document toJson() const override;
};

class QLogPacketEvent : public QLogEvent {
 public:
  QLogPacketEvent() = default;
  ~QLogPacketEvent() override = default;
  std::vector<std::unique_ptr<QLogFrame>> frames;
  std::string packetType;
  std::string transmissionType;
  uint64_t packetNum{0};
  uint64_t packetSize{0};
  Document toJson() const override;
};

class QLogVersionNegotiationEvent : public QLogEvent {
 public:
  QLogVersionNegotiationEvent() = default;
  ~QLogVersionNegotiationEvent() override = default;
  std::unique_ptr<VersionNegotiationLog> versionLog;
  std::string packetType;
  uint64_t packetSize{0};

  Document toJson() const override;
};

class QLogRetryEvent : public QLogEvent {
 public:
  QLogRetryEvent() = default;
  ~QLogRetryEvent() override = default;

  std::string packetType;
  uint64_t packetSize{0};
  uint64_t tokenSize{0};

  Document toJson() const override;
};

class QLogConnectionCloseEvent : public QLogEvent {
 public:
  QLogConnectionCloseEvent(
      QuicErrorCode errorIn,
      std::string reasonIn,
      ConnectionCloseSource sourceIn,
      std::chrono::microseconds refTimeIn);
  ~QLogConnectionCloseEvent() override = default;
  QuicErrorCode error;
  std::string reason;
  ConnectionCloseSource source;

  Document toJson() const override;
};

struct TransportSummaryArgs {
  uint64_t totalBytesSent{};
  uint64_t totalBytesRecvd{};
  uint64_t sumCurWriteOffset{};
  uint64_t sumMaxObservedOffset{};
  uint64_t sumCurStreamBufferLen{};
  uint64_t totalPacketsLost{};
  uint64_t totalStartupDuration{};
  uint64_t totalDrainDuration{};
  uint64_t totalProbeBWDuration{};
  uint64_t totalProbeRttDuration{};
  uint64_t totalNotRecoveryDuration{};
  uint64_t totalGrowthDuration{};
  uint64_t totalConservationDuration{};
  uint64_t totalStreamBytesCloned{};
  uint64_t totalBytesCloned{};
  uint64_t totalCryptoDataWritten{};
  uint64_t totalCryptoDataRecvd{};
  uint64_t currentWritableBytes{};
  uint64_t currentConnFlowControl{};
  bool usedZeroRtt{};
  double smoothedMinRtt{};
  double smoothedMaxBandwidth{};
  float startupDurationRatio{};
  float drainDurationRatio{};
  float probebwDurationRatio{};
  float proberttDurationRatio{};
  float NotRecoveryDurationRatio{};
  float GrowthDurationRatio{};
  float ConservationDurationRatio{};
  float AverageDifference{};
};

class QLogTransportSummaryEvent : public QLogEvent {
 public:
  QLogTransportSummaryEvent(
      uint64_t totalBytesSent,
      uint64_t totalPacketsSent,
      uint64_t totalBytesRecvd,
      uint64_t totalPacketsRecvd,
      uint64_t sumCurWriteOffset,
      uint64_t sumMaxObservedOffset,
      uint64_t sumCurStreamBufferLen,
      uint64_t totalPacketsLost,
      uint64_t totalStartupDuration,
      uint64_t totalDrainDuration,
      uint64_t totalProbeBWDuration,
      uint64_t totalProbeRttDuration,
      uint64_t totalNotRecoveryDuration,
      uint64_t totalGrowthDuration,
      uint64_t totalConservationDuration,
      uint64_t totalStreamBytesCloned,
      uint64_t totalBytesCloned,
      uint64_t totalCryptoDataWritten,
      uint64_t totalCryptoDataRecvd,
      uint64_t currentWritableBytes,
      uint64_t currentConnFlowControl,
      bool usedZeroRtt,
      QuicTransportVersion version,
      CongestionControlType congestionType,
      double smoothedMinRtt,
      double smoothedMaxBandwidth,
      float startupDurationRatio,
      float drainDurationRatio,
      float probebwDurationRatio,
      float proberttDurationRatio,
      float NotRecoveryDurationRatio,
      float GrowthDurationRatio,
      float ConservationDurationRatio,
      float AverageDifference,
      std::chrono::microseconds refTime);
  ~QLogTransportSummaryEvent() override = default;
  uint64_t totalBytesSent;
  uint64_t totalPacketsSent;
  uint64_t totalBytesRecvd;
  uint64_t totalPacketsRecvd;
  uint64_t sumCurWriteOffset;
  uint64_t sumMaxObservedOffset;
  uint64_t sumCurStreamBufferLen;
  uint64_t totalPacketsLost;
  uint64_t totalStartupDuration;
  uint64_t totalDrainDuration;
  uint64_t totalProbeBWDuration;
  uint64_t totalProbeRttDuration;
  uint64_t totalNotRecoveryDuration;
  uint64_t totalGrowthDuration;
  uint64_t totalConservationDuration;
  uint64_t totalStreamBytesCloned;
  uint64_t totalBytesCloned;
  uint64_t totalCryptoDataWritten;
  uint64_t totalCryptoDataRecvd;
  uint64_t currentWritableBytes;
  uint64_t currentConnFlowControl;
  bool usedZeroRtt;
  QuicTransportVersion quicVersion;
  CongestionControlType congestionType;
  double smoothedMinRtt;
  double smoothedMaxBandwidth;
  float startupDurationRatio;
  float drainDurationRatio;
  float probebwDurationRatio;
  float proberttDurationRatio;
  float NotRecoveryDurationRatio;
  float GrowthDurationRatio;
  float ConservationDurationRatio;
  float AverageDifference;
  Document toJson() const override;
};

class QLogBBRCongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogBBRCongestionMetricUpdateEvent(
      uint64_t bytesInFlightIn,
      uint64_t currentCwndIn,
      std::string congestionEventIn,
      quic::CongestionControlType typeIn,
      void* stateIn,
      std::chrono::microseconds refTimeIn);
  ~QLogBBRCongestionMetricUpdateEvent() override = default;
  uint64_t bytesInFlight;
  uint64_t currentCwnd;
  std::string congestionEvent;
  quic::CongestionControlType type;
  void* state;

  Document toJson() const override;
};

class QLogCubicCongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogCubicCongestionMetricUpdateEvent(
      uint64_t bytesInFlightIn,
      uint64_t currentCwndIn,
      std::string congestionEventIn,
      quic::CongestionControlType typeIn,
      void* stateIn,
      std::chrono::microseconds refTimeIn);
  ~QLogCubicCongestionMetricUpdateEvent() override = default;
  uint64_t bytesInFlight;
  uint64_t currentCwnd;
  std::string congestionEvent;
  quic::CongestionControlType type;
  void* state;
  Document toJson() const override;
};

class QLogBBR2CongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogBBR2CongestionMetricUpdateEvent(
      uint64_t bytesInFlightIn,
      uint64_t currentCwndIn,
      std::string congestionEventIn,
      quic::CongestionControlType typeIn,
      void* stateIn,
      std::chrono::microseconds refTimeIn);
  ~QLogBBR2CongestionMetricUpdateEvent() override = default;
  uint64_t bytesInFlight;
  uint64_t currentCwnd;
  std::string congestionEvent;
  quic::CongestionControlType type;
  void* state;
  Document toJson() const override;
};

class QLogAppLimitedUpdateEvent : public QLogEvent {
 public:
  explicit QLogAppLimitedUpdateEvent(
      bool limitedIn,
      std::chrono::microseconds refTimeIn);
  ~QLogAppLimitedUpdateEvent() override = default;

  Document toJson() const override;

  bool limited;
};

class QLogBandwidthEstUpdateEvent : public QLogEvent {
 public:
  explicit QLogBandwidthEstUpdateEvent(
      uint64_t bytes,
      std::chrono::microseconds interval,
      std::chrono::microseconds refTimeIn);
  ~QLogBandwidthEstUpdateEvent() override = default;

  Document toJson() const override;

  uint64_t bytes;
  std::chrono::microseconds interval;
};

class QLogPacingMetricUpdateEvent : public QLogEvent {
 public:
  QLogPacingMetricUpdateEvent(
      uint64_t pacingBurstSize,
      std::chrono::microseconds pacingInterval,
      std::chrono::microseconds refTime);
  ~QLogPacingMetricUpdateEvent() override = default;
  uint64_t pacingBurstSize;
  std::chrono::microseconds pacingInterval;

  Document toJson() const override;
};

class QLogPacingObservationEvent : public QLogEvent {
 public:
  QLogPacingObservationEvent(
      std::string& actualIn,
      std::string& expectIn,
      std::string& conclusionIn,
      std::chrono::microseconds refTimeIn);
  std::string actual;
  std::string expect;
  std::string conclusion;

  ~QLogPacingObservationEvent() override = default;
  Document toJson() const override;
};

class QLogAppIdleUpdateEvent : public QLogEvent {
 public:
  QLogAppIdleUpdateEvent(
      std::string& idleEvent,
      bool idle,
      std::chrono::microseconds refTime);
  ~QLogAppIdleUpdateEvent() override = default;
  std::string idleEvent;
  bool idle;

  Document toJson() const override;
};

class QLogPacketDropEvent : public QLogEvent {
 public:
  QLogPacketDropEvent(
      size_t packetSize,
      std::string& dropReason,
      std::chrono::microseconds refTime);
  ~QLogPacketDropEvent() override = default;
  size_t packetSize;
  std::string dropReason;

  Document toJson() const override;
};

class QLogDatagramReceivedEvent : public QLogEvent {
 public:
  QLogDatagramReceivedEvent(
      uint64_t dataLen,
      std::chrono::microseconds refTime);
  ~QLogDatagramReceivedEvent() override = default;
  uint64_t dataLen;

  Document toJson() const override;
};

class QLogLossAlarmEvent : public QLogEvent {
 public:
  QLogLossAlarmEvent(
      uint64_t largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string& type,
      std::chrono::microseconds refTime);
  ~QLogLossAlarmEvent() override = default;
  uint64_t largestSent;
  uint64_t alarmCount;
  uint64_t outstandingPackets;
  std::string type;
  Document toJson() const override;
};

class QLogPacketLostEvent : public QLogEvent {
 public:
  QLogPacketLostEvent(
      uint64_t LostPacketNum,
      EncryptionLevel level,
      TransmissionType type,
      std::chrono::microseconds refTime);
  ~QLogPacketLostEvent() override = default;
  uint64_t lostPacketNum;
  EncryptionLevel encryptionLevel;
  TransmissionType transmissionType;
  Document toJson() const override;
};

class QLogTransportStateUpdateEvent : public QLogEvent {
 public:
  QLogTransportStateUpdateEvent(
      std::string& update,
      std::chrono::microseconds refTime);
  ~QLogTransportStateUpdateEvent() override = default;
  std::string update;
  Document toJson() const override;
};

class QLogPacketBufferedEvent : public QLogEvent {
 public:
  QLogPacketBufferedEvent(
      uint64_t packetNum,
      EncryptionLevel encryptionLevel,
      uint64_t packetSize,
      std::chrono::microseconds refTime);
  ~QLogPacketBufferedEvent() override = default;
  uint64_t packetNum;
  EncryptionLevel encryptionLevel;
  uint64_t packetSize;
  Document toJson() const override;
};

class QLogPacketAckEvent : public QLogEvent {
 public:
  QLogPacketAckEvent(
      PacketNumberSpace packetNumSpace,
      uint64_t packetNum,
      std::chrono::microseconds refTime);
  ~QLogPacketAckEvent() override = default;
  PacketNumberSpace packetNumSpace;
  uint64_t packetNum;
  Document toJson() const override;
};

class QLogMetricUpdateEvent : public QLogEvent {
 public:
  QLogMetricUpdateEvent(
      std::chrono::microseconds latestRtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ackDelay,
      std::chrono::microseconds refTime);
  ~QLogMetricUpdateEvent() override = default;
  std::chrono::microseconds latestRtt;
  std::chrono::microseconds mrtt;
  std::chrono::microseconds srtt;
  std::chrono::microseconds ackDelay;
  Document toJson() const override;
};

class QLogStreamStateUpdateEvent : public QLogEvent {
 public:
  QLogStreamStateUpdateEvent(
      QuicStreamId id,
      std::string& update,
      quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreation,
      VantagePoint vantagePoint,
      std::chrono::microseconds refTime);
  ~QLogStreamStateUpdateEvent() override = default;
  QuicStreamId id;
  std::string update;
  quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreation;
  Document toJson() const override;

 private:
  VantagePoint vantagePoint_;
};

class QLogConnectionMigrationEvent : public QLogEvent {
 public:
  QLogConnectionMigrationEvent(
      bool intentionalMigration,
      VantagePoint vantagePoint,
      std::chrono::microseconds refTime);

  ~QLogConnectionMigrationEvent() override = default;

  Document toJson() const override;

  bool intentionalMigration_;
  VantagePoint vantagePoint_;
};

class QLogPathValidationEvent : public QLogEvent {
 public:
  // The VantagePoint represents who initiates the path validation (sends out
  // Path Challenge).
  QLogPathValidationEvent(
      bool success,
      VantagePoint vantagePoint,
      std::chrono::microseconds refTime);

  ~QLogPathValidationEvent() override = default;

  Document toJson() const override;
  bool success_;
  VantagePoint vantagePoint_;
};

class QLogPriorityUpdateEvent : public QLogEvent {
 public:
  explicit QLogPriorityUpdateEvent(
      QuicStreamId id,
      uint8_t urgency,
      bool incremental,
      std::chrono::microseconds refTimeIn);
  ~QLogPriorityUpdateEvent() override = default;

  Document toJson() const override;

 private:
  QuicStreamId streamId_;
  uint8_t urgency_;
  bool incremental_;
};

class QLogRequestOverStreamEvent : public QLogEvent {
 public:
  QLogRequestOverStreamEvent(
    std::string methodIn,
    QuicStreamId streamIdIn,
    std::string uriIn,
    std::string rangeIn,
    std::chrono::microseconds refTimeIn);
  ~QLogRequestOverStreamEvent() override = default;

  QuicStreamId streamId;
  std::string method;
  std::string uri;
  std::string range;

  Document toJson() const override;
};

} // namespace quic
