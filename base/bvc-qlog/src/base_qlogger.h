#pragma once

#include "base/bvc-qlog/src/qlogger.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "base/bvc-qlog/src/qlogger_types.h"

namespace quic {

class BaseQLogger : public QLogger {
 public:
  explicit BaseQLogger(VantagePoint vantagePointIn, std::string protocolTypeIn)
      : QLogger(vantagePointIn, std::move(protocolTypeIn)) {}

  ~BaseQLogger() override = default;

 protected:
  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      const std::string newConnectionId,
      uint64_t packetSize,
      bool isPacketRecvd);

  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      const QuicPublicResetPacket& publicResetPacket,
      uint64_t packetSize,
      bool isPacketRecvd);

  std::unique_ptr<QLogVersionNegotiationEvent> createPacketEventImpl(
      const QuicVersionNegotiationPacket& versionNegotiationPacket,
      uint64_t packetSize,
      bool isPacketRecvd);
  
  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      const QuicPacketHeader& packetHeader,
      uint64_t packetSize,
      bool isPacketRecvd);

  void addFramesProcessedImpl(
      QLogFramesProcessed* event,
      QuicFrameType frame_type,
      void* frame,
      uint64_t packet_number,
      uint64_t packet_size,
      std::string packet_type,
      std::chrono::microseconds time_dirft);

  void addPacketFrameImpl(
      QLogPacketEvent* event,
      QuicFrameType frame_type,
      void* frame,
      bool isPacketRecvd);

  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool isPacketRecvd,
      bool aggregate);

  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool isPacketRecvd);

  void* getFrameType(const quic::QuicFrame& frame);

  std::chrono::microseconds steady_startTime_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());
  std::chrono::microseconds steady_packetTime_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());
  std::chrono::microseconds system_startTime_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());
  std::chrono::microseconds endTime_;

 //* for frame aggregation holder, whether or not place it here is a problem.
  
};
} // namespace quic
