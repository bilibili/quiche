#pragma once
#include "base/bvc-qlog/src/file_qlogger.h"
#include "gquiche/quic/core/quic_connection.h"
#include "gquiche/quic/core/quic_default_packet_writer.h"
#include "gquiche/quic/core/quic_packet_writer.h"
#include "gquiche/quic/core/quic_packets.h"
#include "gquiche/quic/core/quic_simple_buffer_allocator.h"
#include "gquiche/quic/core/quic_time.h"
#include "gquiche/quic/platform/api/quic_epoll.h"

namespace bvc {

class BvcQuicConnectionDebugVisitor : public quic::QuicConnectionDebugVisitor {
 public:
  BvcQuicConnectionDebugVisitor(quic::FileQLogger* qlogger,
                              quic::QuicConnection* connection);
  ~BvcQuicConnectionDebugVisitor() override {}

  virtual void OnPacketSent(quic::QuicPacketNumber /*packet_number*/,
                            quic::QuicPacketLength /*packet_length*/,
                            bool /*has_crypto_handshake*/,
                            quic::TransmissionType /*transmission_type*/,
                            quic::EncryptionLevel /*encryption_level*/,
                            const quic::QuicFrames& /*retransmittable_frames*/,
                            const quic::QuicFrames& /*nonretransmittable_frames*/,
                            quic::QuicTime /*sent_time*/) override;

  // Called when a coalesced packet has been sent.
  virtual void OnCoalescedPacketSent(
      const quic::QuicCoalescedPacket& /*coalesced_packet*/,
      size_t /*length*/) override {}

  // Called when a PING frame has been sent.
  virtual void OnPingSent() override {}

  // Called when a packet has been received, but before it is
  // validated or parsed.
  virtual void OnPacketReceived(const quic::QuicSocketAddress& /*self_address*/,
                                const quic::QuicSocketAddress& /*peer_address*/,
                                const quic::QuicEncryptedPacket& /*packet*/) override;

  // Called when the unauthenticated portion of the header has been parsed.
  virtual void OnUnauthenticatedHeader(const quic::QuicPacketHeader& /*header*/) override {}

  // Called when a packet is received with a connection id that does not
  // match the ID of this connection.
  virtual void OnIncorrectConnectionId(quic::QuicConnectionId /*connection_id*/) override {}

  // Called when an undecryptable packet has been received. If |dropped| is
  // true, the packet has been dropped. Otherwise, the packet will be queued and
  // connection will attempt to process it later.
  virtual void OnUndecryptablePacket(quic::EncryptionLevel /*decryption_level*/,
                                     bool /*dropped*/) override {}

  // Called when attempting to process a previously undecryptable packet.
  virtual void OnAttemptingToProcessUndecryptablePacket(
      quic::EncryptionLevel /*decryption_level*/) override {}

  // Called when a duplicate packet has been received.
  virtual void OnDuplicatePacket(quic::QuicPacketNumber /*packet_number*/) override {}

  // Called when the protocol version on the received packet doensn't match
  // current protocol version of the connection.
  virtual void OnProtocolVersionMismatch(quic::ParsedQuicVersion /*version*/) override {}

  // Called when the complete header of a packet has been parsed.
  virtual void OnPacketHeader(const quic::QuicPacketHeader& /*header*/,
                              quic::QuicTime /*receive_time*/,
                              quic::EncryptionLevel /*level*/) override;

  // Called when a StreamFrame has been parsed.
  virtual void OnStreamFrame(const quic::QuicStreamFrame& /*frame*/) override;

  // Called when a CRYPTO frame containing handshake data is received.
  virtual void OnCryptoFrame(const quic::QuicCryptoFrame& /*frame*/) override;

  // Called when a StopWaitingFrame has been parsed.
  virtual void OnStopWaitingFrame(const quic::QuicStopWaitingFrame& /*frame*/) override;

  // Called when a QuicPaddingFrame has been parsed.
  virtual void OnPaddingFrame(const quic::QuicPaddingFrame& /*frame*/) override;

  // Called when a Ping has been parsed.
  virtual void OnPingFrame(const quic::QuicPingFrame& /*frame*/,
                           quic::QuicTime::Delta /*ping_received_delay*/) override;

  // Called when a GoAway has been parsed.
  virtual void OnGoAwayFrame(const quic::QuicGoAwayFrame& /*frame*/) override;

  // Called when a RstStreamFrame has been parsed.
  virtual void OnRstStreamFrame(const quic::QuicRstStreamFrame& /*frame*/) override;

  // Called when a ConnectionCloseFrame has been parsed. All forms
  // of CONNECTION CLOSE are handled, Google QUIC, IETF QUIC
  // CONNECTION CLOSE/Transport and IETF QUIC CONNECTION CLOSE/Application
  virtual void OnConnectionCloseFrame(
      const quic::QuicConnectionCloseFrame& /*frame*/) override;

  // Called when a WindowUpdate has been parsed.
  virtual void OnWindowUpdateFrame(const quic::QuicWindowUpdateFrame& /*frame*/,
                                   const quic::QuicTime& /*receive_time*/) override;

  // Called when a BlockedFrame has been parsed.
  virtual void OnBlockedFrame(const quic::QuicBlockedFrame& /*frame*/) override;

  // Called when a NewConnectionIdFrame has been parsed.
  virtual void OnNewConnectionIdFrame(
      const quic::QuicNewConnectionIdFrame& /*frame*/) override;

  // Called when a RetireConnectionIdFrame has been parsed.
  virtual void OnRetireConnectionIdFrame(
      const quic::QuicRetireConnectionIdFrame& /*frame*/) override;

  // Called when a NewTokenFrame has been parsed.
  virtual void OnNewTokenFrame(const quic::QuicNewTokenFrame& /*frame*/) override;

  // Called when a MessageFrame has been parsed.
  virtual void OnMessageFrame(const quic::QuicMessageFrame& /*frame*/) override;

  // Called when a HandshakeDoneFrame has been parsed.
  virtual void OnHandshakeDoneFrame(const quic::QuicHandshakeDoneFrame& /*frame*/) override;

  // Called when a public reset packet has been received.
  virtual void OnPublicResetPacket(const quic::QuicPublicResetPacket& /*packet*/) override;

  // Called when a version negotiation packet has been received.
  virtual void OnVersionNegotiationPacket(
      const quic::QuicVersionNegotiationPacket& /*packet*/) override;

  // Called when the connection is closed.
  virtual void OnConnectionClosed(const quic::QuicConnectionCloseFrame& /*frame*/,
                                  quic::ConnectionCloseSource /*source*/) override;

    // Called when the version negotiation is successful.
  virtual void OnSuccessfulVersionNegotiation(
      const quic::ParsedQuicVersion& /*version*/) override {}

  // Called when a CachedNetworkParameters is sent to the client.
  virtual void OnSendConnectionState(
      const quic::CachedNetworkParameters& /*cached_network_params*/) override {}

  // Called when a CachedNetworkParameters are received from the client.
  virtual void OnReceiveConnectionState(
      const quic::CachedNetworkParameters& /*cached_network_params*/) override {}

  // Called when the connection parameters are set from the supplied
  // |config|.
  virtual void OnSetFromConfig(const quic::QuicConfig& /*config*/) override {}

  // Called when RTT may have changed, including when an RTT is read from
  // the config.
  virtual void OnRttChanged(quic::QuicTime::Delta /*rtt*/) const override {}

  // Called when a StopSendingFrame has been parsed.
  virtual void OnStopSendingFrame(const quic::QuicStopSendingFrame& /*frame*/) override;

  // Called when a PathChallengeFrame has been parsed.
  virtual void OnPathChallengeFrame(const quic::QuicPathChallengeFrame& /*frame*/) override;

  // Called when a PathResponseFrame has been parsed.
  virtual void OnPathResponseFrame(const quic::QuicPathResponseFrame& /*frame*/) override;

  // Called when a StreamsBlockedFrame has been parsed.
  virtual void OnStreamsBlockedFrame(const quic::QuicStreamsBlockedFrame& /*frame*/) override;

  // Called when a MaxStreamsFrame has been parsed.
  virtual void OnMaxStreamsFrame(const quic::QuicMaxStreamsFrame& /*frame*/) override;

  // Called when |count| packet numbers have been skipped.
  virtual void OnNPacketNumbersSkipped(quic::QuicPacketCount /*count*/,
                                       quic::QuicTime /*now*/) override {}

  // Called for QUIC+TLS versions when we send transport parameters.
  virtual void OnTransportParametersSent(
      const quic::TransportParameters& /*transport_parameters*/) override {}

  // Called for QUIC+TLS versions when we receive transport parameters.
  virtual void OnTransportParametersReceived(
      const quic::TransportParameters& /*transport_parameters*/) override {}

  // Called for QUIC+TLS versions when we resume cached transport parameters for
  // 0-RTT.
  virtual void OnTransportParametersResumed(
      const quic::TransportParameters& /*transport_parameters*/) override {}

  // Called for QUIC+TLS versions when 0-RTT is rejected.
  virtual void OnZeroRttRejected(int /*reject_reason*/) override {}

  // Called for QUIC+TLS versions when 0-RTT packet gets acked.
  virtual void OnZeroRttPacketAcked() override {}

  // Called on peer address change.
  virtual void OnPeerAddressChange(quic::AddressChangeType /*type*/,
                                   quic::QuicTime::Delta /*connection_time*/) override {}

  // Called when all frames in packet have been parsed.
  virtual void OnPacketComplete() override;

  // Called when a ack frequency frame has been parsed..
  virtual void OnAckFrequencyFrame(const quic::QuicAckFrequencyFrame& /*frame*/) override;

  // Called when ack_delay_time in ack frame has been parsed.
  virtual void OnAckFrameStart(quic::QuicTime::Delta ack_delay_time) override;

  // Called when ack_range in ack frame has been parsed.
  virtual void OnAckRange(quic::QuicPacketNumber start, quic::QuicPacketNumber end) override;

  // Done processing the ack frame.
  virtual void OnAckFrameEnd(quic::QuicPacketNumber start) override;

  // Output DebugState of congestion control for analysis.
  virtual void OnIncomingAck(quic::QuicPacketNumber /*ack_packet_number*/,
                             quic::EncryptionLevel /*ack_decrypted_level*/,
                             const quic::QuicAckFrame& /*ack_frame*/,
                             quic::QuicTime /*ack_receive_time*/,
                             quic::QuicPacketNumber /*largest_observed*/,
                             bool /*rtt_updated*/,
                             quic::QuicPacketNumber /*least_unacked_sent_packet*/) override;

  virtual void OnPacketLoss(quic::QuicPacketNumber /*lost_packet_number*/,
                            quic::EncryptionLevel /*encryption_level*/,
                            quic::TransmissionType /*transmission_type*/,
                            quic::QuicTime /*detection_time*/) override;

 private:
  quic::FileQLogger*                        qlogger_;
  quic::QuicConnection*                     connection_;
  std::unique_ptr<quic::QLogPacketEvent>    current_event_;
  std::unique_ptr<quic::QuicAckFrame>       ack_frame_;
  uint64_t                                  packet_length_;
 };
} // namespace bvc

