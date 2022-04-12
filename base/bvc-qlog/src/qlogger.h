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
  virtual void onNewPacingRate(
      uint64_t packetsPerInterval,
      std::chrono::microseconds interval) = 0;
  virtual void onPacketSent() = 0;
};

class QLogger {
 public:
  explicit QLogger(VantagePoint vantagePointIn, std::string protocolTypeIn)
      : vantagePoint_(vantagePointIn), protocolType_(std::move(protocolTypeIn)) {}

  quiche::QuicheOptionalImpl<QuicConnectionId> dcid_;
  quiche::QuicheOptionalImpl<QuicConnectionId> scid_;
  VantagePoint vantagePoint_;
  std::string protocolType_;
  QLogger() = delete;
  virtual ~QLogger() = default;
  virtual void addPacket(
      const std::string& newConnectionId,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void addPacket(
      const QuicPublicResetPacket& publicResetPacket,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void addPacket(
      const QuicVersionNegotiationPacket& versionNegotiationPacket,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void addConnectionClose(
      QuicErrorCode error,
      const std::string& reason,
      ConnectionCloseSource source) = 0;
  struct TransportSummaryArgs {
    uint64_t totalBytesSent{}; 
    uint64_t totalPacketsSent{}; 
    uint64_t totalBytesRecvd{}; 
    uint64_t totalPacketsRecvd{}; 
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
    double smoothedMaxBandwidth{};
    double smoothedMinRtt{};
    double smoothedMeanDeviation{};
    bool usedZeroRtt{false}; 
    QuicTransportVersion quicVersion{}; 
    CongestionControlType congestionControl{}; 
  };

  virtual void addBandwidthEstUpdate(
      uint64_t bytes,
      std::chrono::microseconds interval) = 0;
  virtual void addAppLimitedUpdate() = 0;
  virtual void addAppUnlimitedUpdate() = 0;
  virtual void addPacingMetricUpdate(
      uint64_t pacingBurstSizeIn,
      std::chrono::microseconds pacingIntervalIn) = 0;
  virtual void addPacingObservation(
      std::string& actual,
      std::string& expected,
      std::string& conclusion) = 0;
  virtual void addAppIdleUpdate(std::string& idleEvent, bool idle) = 0;
  virtual void addPacketDrop(size_t packetSize, std::string& dropReasonIn) = 0;
  virtual void addDatagramReceived(uint64_t dataLen) = 0;
  virtual void addLossAlarm(
      uint64_t largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string& type) = 0;
  virtual void addPacketLost(
      uint64_t LostPacketNum,
      EncryptionLevel level,
      TransmissionType type) = 0;
  virtual void addTransportStateUpdate(std::string& update) = 0;
  virtual void addPacketBuffered(
      uint64_t packetNum,
      EncryptionLevel protectionType,
      uint64_t packetSize) = 0;
  virtual void addMetricUpdate(
      std::chrono::microseconds latestRtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ackDelay) = 0;
  virtual void addStreamStateUpdate(
      quic::QuicStreamId streamId,
      std::string& update,
      quiche::QuicheOptionalImpl<std::chrono::milliseconds> timeSinceStreamCreation) = 0;
  virtual void addConnectionMigrationUpdate(bool intentionalMigration) = 0;
  virtual void addPathValidationEvent(bool success) = 0;
  virtual void addPriorityUpdate(
      quic::QuicStreamId streamId,
      uint8_t urgency,
      bool incremental) = 0;

  virtual void setDcid(quiche::QuicheOptionalImpl<QuicConnectionId> connID) = 0;
  virtual void setScid(quiche::QuicheOptionalImpl<QuicConnectionId> connID) = 0;
  virtual void setQuicVersion(const QuicTransportVersion version) = 0;
  virtual void usedZeroRtt(bool use) = 0;
  TransportSummaryArgs summary_;
};

std::string getFlowControlEvent(int offset);

std::string getRxStreamWU(QuicStreamId streamId, uint64_t packetNum, uint64_t maximumData);

std::string getRxConnWU(uint64_t packetNum, uint64_t maximumData);

std::string getPeerClose(const std::string& errMsg);

std::string getFlowControlWindowAvailable(uint64_t windowAvailable);

std::string getClosingStream(const std::string& streamId);

} // namespace quic
