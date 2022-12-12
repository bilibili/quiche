#pragma once
#include <map>
#include "base/bvc-qlog/src/qlogger.h"
#include "base/bvc-qlog/src/qlogger_constants.h"
#include "base/bvc-qlog/src/qlogger_types.h"

namespace quic {
using std::chrono::duration_cast;
using std::chrono::steady_clock;
using std::chrono::microseconds;

class BaseQLogger : public QLogger {
 public:
  struct FrameMsg {
    unsigned long long int size = 0;
    quic::QuicStreamOffset stream_offset = 0;
    std::string trid;
    std::string protocol;
    uint64_t request_index = 0;
    std::chrono::microseconds request_time = std::chrono::microseconds::zero();
    std::chrono::microseconds send_frame_end_time = std::chrono::microseconds::zero();
  }; 

  explicit BaseQLogger(VantagePoint vantage_point_in, std::string protocol_type_in)
      : QLogger(vantage_point_in, std::move(protocol_type_in)) {}

  ~BaseQLogger() override = default;

 protected:
  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      const std::string new_connection_id,
      uint64_t packet_size,
      bool is_packet_recvd);

  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      const QuicPublicResetPacket& public_reset_packet,
      uint64_t packet_size,
      bool is_packet_recvd);

  std::unique_ptr<QLogVersionNegotiationEvent> createPacketEventImpl(
      const QuicVersionNegotiationPacket& version_negotiation_packet,
      uint64_t packet_size,
      bool is_packet_recvd);
  
  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      const QuicPacketHeader& packet_header,
      uint64_t packet_size,
      bool is_packet_recvd);

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
      bool is_packet_recvd);

  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool is_packet_recvd,
      bool aggregate);

  std::unique_ptr<QLogPacketEvent> createPacketEventImpl(
      uint64_t packet_number,
      uint64_t packet_length,
      TransmissionType transmission_type,
      EncryptionLevel encryption_level,
      const QuicFrames& retransmittable_frames,
      const QuicFrames& nonretransmittable_frames,
      bool is_packet_recvd);

  void* getFrameType(const quic::QuicFrame& frame);

  void getVideoFrameEndTime(QuicStreamFrame* frame);
  
  std::chrono::microseconds steady_startTime_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());
  std::chrono::microseconds steady_packetTime_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch());
  std::chrono::microseconds system_startTime_ =
    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());
  std::chrono::microseconds end_time_;
  
  std::map<QuicStreamId, FrameMsg> sid_first_frame_msg_map_;
 //* for frame aggregation holder, whether or not place it here is a problem.
};
} // namespace quic
