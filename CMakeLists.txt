CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

PROJECT(quiche)

option(ENABLE_LINK_TCMALLOC "option for link tcmalloc" ON)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
find_library(Z libz.a /usr/lib/)

INCLUDE(FindProtobuf)
FIND_PACKAGE(Protobuf REQUIRED)
INCLUDE_DIRECTORIES(${PROTOBUF_INCLUDE_DIR})

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=unused-result")

ADD_SUBDIRECTORY(third_party/fmt)
ADD_SUBDIRECTORY(third_party/spdlog)
ADD_SUBDIRECTORY(third_party/abseil-cpp)
ADD_SUBDIRECTORY(third_party/boringssl EXCLUDE_FROM_ALL)
ADD_SUBDIRECTORY(googleurl)

INCLUDE_DIRECTORIES(
    third_party/fmt/include
    third_party/spdlog/include
    third_party/abseil-cpp
    third_party/boringssl/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/quiche
    ${CMAKE_CURRENT_SOURCE_DIR}/googleurl
)

INCLUDE_DIRECTORIES(${QuicCoreProtoIncPath})
ADD_SUBDIRECTORY(gquiche/quic/core/proto)

SET(BASE_SRCS
    base/files/file_path.h
    base/files/file_path.cc
    base/files/file_path_constants.cc
    base/files/file_util.cc
    base/files/file_util_posix.cc
    base/strings/stringprintf.cc
)

SET(NET_SRCS
    net/base/io_buffer.cc
    net/http/http_util.cc
    net/http/http_request_headers.cc
)

SET(EPOLL_SERVER_SRC
    gquiche/epoll_server/simple_epoll_server.cc
)

SET(PLATFORM_SRCS
    platform/base64.cc
    platform/mem_slice_buffer.cc
    platform/string_utils.cc
    platform/quiche_platform_impl/flags_impl.cc
    platform/quiche_platform_impl/quiche_logging_impl.cc
    platform/quiche_platform_impl/quiche_time_utils_impl.cc
    platform/quiche_platform_impl/quic_mutex_impl.cc
    platform/quic_platform_impl/quic_cert_utils_impl.cc
    platform/quic_platform_impl/quic_default_proof_providers_impl.cc
    platform/quic_platform_impl/quic_file_utils_impl.cc
    platform/quic_platform_impl/quic_hostname_utils_impl.cc
    platform/quic_platform_impl/quic_mem_slice_impl.cc
    platform/quic_platform_impl/quic_mem_slice_span_impl.cc
    platform/quic_platform_impl/quic_mem_slice_storage_impl.cc
    platform/epoll_platform_impl/quic_epoll_clock.cc
)

SET(GQUICHE_SRCS
    gquiche/common/quiche_data_reader.cc
    gquiche/common/quiche_data_writer.cc
    gquiche/http2/decoder/decode_buffer.cc
    gquiche/http2/decoder/decode_http2_structures.cc
    gquiche/http2/decoder/decode_status.cc
    gquiche/http2/decoder/frame_decoder_state.cc
    gquiche/http2/decoder/http2_frame_decoder.cc
    gquiche/http2/decoder/http2_frame_decoder_listener.cc
    gquiche/http2/decoder/http2_structure_decoder.cc
    gquiche/http2/decoder/payload_decoders/altsvc_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/continuation_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/data_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/goaway_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/headers_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/ping_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/priority_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/priority_update_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/push_promise_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/rst_stream_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/settings_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/unknown_payload_decoder.cc
    gquiche/http2/decoder/payload_decoders/window_update_payload_decoder.cc
    gquiche/http2/hpack/decoder/hpack_block_decoder.cc
    gquiche/http2/hpack/decoder/hpack_decoder.cc
    gquiche/http2/hpack/decoder/hpack_decoder_listener.cc
    gquiche/http2/hpack/decoder/hpack_decoder_state.cc
    gquiche/http2/hpack/decoder/hpack_decoder_string_buffer.cc
    gquiche/http2/hpack/decoder/hpack_decoder_tables.cc
    gquiche/http2/hpack/decoder/hpack_decoding_error.cc
    gquiche/http2/hpack/decoder/hpack_entry_decoder.cc
    gquiche/http2/hpack/decoder/hpack_entry_decoder_listener.cc
    gquiche/http2/hpack/decoder/hpack_entry_type_decoder.cc
    gquiche/http2/hpack/decoder/hpack_string_decoder.cc
    gquiche/http2/hpack/decoder/hpack_string_decoder_listener.cc
    gquiche/http2/hpack/decoder/hpack_whole_entry_buffer.cc
    gquiche/http2/hpack/decoder/hpack_whole_entry_listener.cc
    gquiche/http2/hpack/http2_hpack_constants.cc
    gquiche/http2/hpack/huffman/hpack_huffman_decoder.cc
    gquiche/http2/hpack/huffman/hpack_huffman_encoder.cc
    gquiche/http2/hpack/huffman/huffman_spec_tables.cc
    gquiche/http2/hpack/varint/hpack_varint_decoder.cc
    gquiche/http2/hpack/varint/hpack_varint_encoder.cc
    gquiche/http2/http2_constants.cc
    gquiche/http2/http2_structures.cc
    gquiche/quic/core/congestion_control/bandwidth_sampler.cc
    gquiche/quic/core/congestion_control/bbr2_drain.cc
    gquiche/quic/core/congestion_control/bbr2_misc.cc
    gquiche/quic/core/congestion_control/bbr2_probe_bw.cc
    gquiche/quic/core/congestion_control/bbr2_probe_rtt.cc
    gquiche/quic/core/congestion_control/bbr2_sender.cc
    gquiche/quic/core/congestion_control/bbr2_startup.cc
    gquiche/quic/core/congestion_control/bbr_sender.cc
    gquiche/quic/core/congestion_control/cubic_bytes.cc
    gquiche/quic/core/congestion_control/general_loss_algorithm.cc
    gquiche/quic/core/congestion_control/hybrid_slow_start.cc
    gquiche/quic/core/congestion_control/pacing_sender.cc
    gquiche/quic/core/congestion_control/prr_sender.cc
    gquiche/quic/core/congestion_control/rtt_stats.cc
    gquiche/quic/core/congestion_control/send_algorithm_interface.cc
    gquiche/quic/core/congestion_control/tcp_cubic_sender_bytes.cc
    gquiche/quic/core/congestion_control/uber_loss_algorithm.cc
    gquiche/quic/core/crypto/aead_base_decrypter.cc
    gquiche/quic/core/crypto/aead_base_encrypter.cc
    gquiche/quic/core/crypto/aes_128_gcm_12_decrypter.cc
    gquiche/quic/core/crypto/aes_128_gcm_12_encrypter.cc
    gquiche/quic/core/crypto/aes_128_gcm_decrypter.cc
    gquiche/quic/core/crypto/aes_128_gcm_encrypter.cc
    gquiche/quic/core/crypto/aes_256_gcm_decrypter.cc
    gquiche/quic/core/crypto/aes_256_gcm_encrypter.cc
    gquiche/quic/core/crypto/aes_base_decrypter.cc
    gquiche/quic/core/crypto/aes_base_encrypter.cc
    gquiche/quic/core/crypto/cert_compressor.cc
    gquiche/quic/core/crypto/certificate_view.cc
    gquiche/quic/core/crypto/proof_source_x509.cc
    gquiche/quic/core/crypto/chacha20_poly1305_decrypter.cc
    gquiche/quic/core/crypto/chacha20_poly1305_encrypter.cc
    gquiche/quic/core/crypto/chacha20_poly1305_tls_decrypter.cc
    gquiche/quic/core/crypto/chacha20_poly1305_tls_encrypter.cc
    gquiche/quic/core/crypto/chacha_base_decrypter.cc
    gquiche/quic/core/crypto/chacha_base_encrypter.cc
    gquiche/quic/core/crypto/channel_id.cc
    gquiche/quic/core/crypto/common_cert_set.cc
    gquiche/quic/core/crypto/crypto_framer.cc
    gquiche/quic/core/crypto/crypto_handshake.cc
    gquiche/quic/core/crypto/crypto_handshake_message.cc
    gquiche/quic/core/crypto/crypto_secret_boxer.cc
    gquiche/quic/core/crypto/crypto_utils.cc
    gquiche/quic/core/crypto/curve25519_key_exchange.cc
    gquiche/quic/core/crypto/key_exchange.cc
    gquiche/quic/core/crypto/null_decrypter.cc
    gquiche/quic/core/crypto/null_encrypter.cc
    gquiche/quic/core/crypto/p256_key_exchange.cc
    gquiche/quic/core/crypto/proof_source.cc
    gquiche/quic/core/crypto/quic_compressed_certs_cache.cc
    gquiche/quic/core/crypto/quic_crypter.cc
    gquiche/quic/core/crypto/quic_crypto_client_config.cc
    gquiche/quic/core/crypto/quic_crypto_proof.cc
    gquiche/quic/core/crypto/quic_crypto_server_config.cc
    gquiche/quic/core/crypto/quic_decrypter.cc
    gquiche/quic/core/crypto/quic_encrypter.cc
    gquiche/quic/core/crypto/quic_hkdf.cc
    gquiche/quic/core/crypto/quic_random.cc
    gquiche/quic/core/crypto/tls_client_connection.cc
    gquiche/quic/core/crypto/tls_connection.cc
    gquiche/quic/core/crypto/tls_server_connection.cc
    gquiche/quic/core/crypto/transport_parameters.cc
    gquiche/quic/core/frames/quic_ack_frame.cc
    gquiche/quic/core/frames/quic_ack_frequency_frame.cc
    gquiche/quic/core/frames/quic_blocked_frame.cc
    gquiche/quic/core/frames/quic_connection_close_frame.cc
    gquiche/quic/core/frames/quic_crypto_frame.cc
    gquiche/quic/core/frames/quic_frame.cc
    gquiche/quic/core/frames/quic_goaway_frame.cc
    gquiche/quic/core/frames/quic_handshake_done_frame.cc
    gquiche/quic/core/frames/quic_max_streams_frame.cc
    gquiche/quic/core/frames/quic_message_frame.cc
    gquiche/quic/core/frames/quic_new_connection_id_frame.cc
    gquiche/quic/core/frames/quic_new_token_frame.cc
    gquiche/quic/core/frames/quic_padding_frame.cc
    gquiche/quic/core/frames/quic_path_challenge_frame.cc
    gquiche/quic/core/frames/quic_path_response_frame.cc
    gquiche/quic/core/frames/quic_ping_frame.cc
    gquiche/quic/core/frames/quic_retire_connection_id_frame.cc
    gquiche/quic/core/frames/quic_rst_stream_frame.cc
    gquiche/quic/core/frames/quic_stop_sending_frame.cc
    gquiche/quic/core/frames/quic_stop_waiting_frame.cc
    gquiche/quic/core/frames/quic_stream_frame.cc
    gquiche/quic/core/frames/quic_streams_blocked_frame.cc
    gquiche/quic/core/frames/quic_window_update_frame.cc
    gquiche/quic/core/http/http_constants.cc
    gquiche/quic/core/http/http_decoder.cc
    gquiche/quic/core/http/http_encoder.cc
    gquiche/quic/core/http/quic_client_promised_info.cc
    gquiche/quic/core/http/quic_client_push_promise_index.cc
    gquiche/quic/core/http/quic_header_list.cc
    gquiche/quic/core/http/quic_headers_stream.cc
    gquiche/quic/core/http/quic_receive_control_stream.cc
    gquiche/quic/core/http/quic_send_control_stream.cc
    gquiche/quic/core/http/quic_server_initiated_spdy_stream.cc
    gquiche/quic/core/http/quic_server_session_base.cc
    gquiche/quic/core/http/quic_spdy_client_session.cc
    gquiche/quic/core/http/quic_spdy_client_session_base.cc
    gquiche/quic/core/http/quic_spdy_client_stream.cc
    gquiche/quic/core/http/quic_spdy_session.cc
    gquiche/quic/core/http/quic_spdy_server_stream_base.cc
    gquiche/quic/core/http/quic_spdy_stream.cc
    gquiche/quic/core/http/quic_spdy_stream_body_manager.cc
    gquiche/quic/core/http/spdy_server_push_utils.cc
    gquiche/quic/core/http/spdy_utils.cc
    gquiche/quic/core/http/web_transport_http3.cc
    gquiche/quic/core/legacy_quic_stream_id_manager.cc
    gquiche/quic/core/qpack/qpack_blocking_manager.cc
    gquiche/quic/core/qpack/qpack_decoded_headers_accumulator.cc
    gquiche/quic/core/qpack/qpack_decoded_headers_accumulator.h
    gquiche/quic/core/qpack/qpack_decoder.cc
    gquiche/quic/core/qpack/qpack_decoder_stream_receiver.cc
    gquiche/quic/core/qpack/qpack_decoder_stream_sender.cc
    gquiche/quic/core/qpack/qpack_encoder.cc
    gquiche/quic/core/qpack/qpack_encoder_stream_receiver.cc
    gquiche/quic/core/qpack/qpack_encoder_stream_sender.cc
    gquiche/quic/core/qpack/qpack_header_table.cc
    gquiche/quic/core/qpack/qpack_index_conversions.cc
    gquiche/quic/core/qpack/qpack_instruction_decoder.cc
    gquiche/quic/core/qpack/qpack_instruction_encoder.cc
    gquiche/quic/core/qpack/qpack_instructions.cc
    gquiche/quic/core/qpack/qpack_progressive_decoder.cc
    gquiche/quic/core/qpack/qpack_receive_stream.cc
    gquiche/quic/core/qpack/qpack_required_insert_count.cc
    gquiche/quic/core/qpack/qpack_send_stream.cc
    gquiche/quic/core/qpack/qpack_static_table.cc
    gquiche/quic/core/qpack/value_splitting_header_list.cc
    gquiche/quic/core/quic_ack_listener_interface.cc
    gquiche/quic/core/quic_alarm.cc
    gquiche/quic/core/quic_bandwidth.cc
    gquiche/quic/core/quic_buffer_allocator.cc
    gquiche/quic/core/quic_buffered_packet_store.cc
    gquiche/quic/core/chlo_extractor.cc
    gquiche/quic/core/quic_clock.cc
    gquiche/quic/core/quic_coalesced_packet.cc
    gquiche/quic/core/quic_config.cc
    gquiche/quic/core/quic_connection.cc
    gquiche/quic/core/quic_connection_id.cc
    gquiche/quic/core/quic_connection_id_manager.cc
    gquiche/quic/core/quic_connection_stats.cc
    gquiche/quic/core/quic_constants.cc
    gquiche/quic/core/quic_control_frame_manager.cc
    gquiche/quic/core/quic_crypto_client_handshaker.cc
    gquiche/quic/core/quic_crypto_client_stream.cc
    gquiche/quic/core/quic_crypto_handshaker.cc
    gquiche/quic/core/quic_crypto_server_stream.cc
    gquiche/quic/core/quic_crypto_server_stream_base.cc
    gquiche/quic/core/quic_crypto_stream.cc
    gquiche/quic/core/quic_data_reader.cc
    gquiche/quic/core/quic_data_writer.cc
    gquiche/quic/core/quic_datagram_queue.cc
    gquiche/quic/core/quic_default_packet_writer.cc
    gquiche/quic/core/quic_dispatcher.cc
    gquiche/quic/core/quic_epoll_alarm_factory.cc
    gquiche/quic/core/quic_epoll_connection_helper.cc
    gquiche/quic/core/quic_error_codes.cc
    gquiche/quic/core/quic_flow_controller.cc
    gquiche/quic/core/quic_framer.cc
    gquiche/quic/core/quic_idle_network_detector.cc
    gquiche/quic/core/quic_legacy_version_encapsulator.cc
    gquiche/quic/core/quic_mtu_discovery.cc
    gquiche/quic/core/quic_network_blackhole_detector.cc
    gquiche/quic/core/quic_packet_creator.cc
    gquiche/quic/core/quic_packet_number.cc
    gquiche/quic/core/quic_packet_reader.cc
    gquiche/quic/core/quic_packets.cc
    gquiche/quic/core/quic_path_validator.cc
    gquiche/quic/core/quic_received_packet_manager.cc
    gquiche/quic/core/quic_sent_packet_manager.cc
    gquiche/quic/core/quic_server_id.cc
    gquiche/quic/core/quic_session.cc
    gquiche/quic/core/quic_simple_buffer_allocator.cc
    gquiche/quic/core/quic_socket_address_coder.cc
    gquiche/quic/core/quic_stream.cc
    gquiche/quic/core/quic_stream_id_manager.cc
    gquiche/quic/core/quic_stream_send_buffer.cc
    gquiche/quic/core/quic_stream_sequencer.cc
    gquiche/quic/core/quic_stream_sequencer_buffer.cc
    gquiche/quic/core/quic_sustained_bandwidth_recorder.cc
    gquiche/quic/core/quic_tag.cc
    gquiche/quic/core/quic_time_wait_list_manager.cc
    gquiche/quic/core/quic_time.cc
    gquiche/quic/core/quic_transmission_info.cc
    gquiche/quic/core/quic_types.cc
    gquiche/quic/core/quic_udp_socket_posix.cc
    gquiche/quic/core/quic_unacked_packet_map.cc
    gquiche/quic/core/quic_utils.cc
    gquiche/quic/core/quic_version_manager.cc
    gquiche/quic/core/quic_versions.cc
    gquiche/quic/core/quic_write_blocked_list.cc
    gquiche/quic/core/tls_chlo_extractor.cc
    gquiche/quic/core/tls_client_handshaker.cc
    gquiche/quic/core/tls_handshaker.cc
    gquiche/quic/core/tls_server_handshaker.cc
    gquiche/quic/core/uber_quic_stream_id_manager.cc
    gquiche/quic/core/uber_received_packet_manager.cc
    gquiche/quic/core/web_transport_stream_adapter.cc
    gquiche/quic/platform/api/quic_file_utils.cc
    gquiche/quic/platform/api/quic_hostname_utils.cc
    gquiche/quic/platform/api/quic_ip_address.cc
    gquiche/quic/platform/api/quic_mutex.cc
    gquiche/quic/platform/api/quic_socket_address.cc
    gquiche/spdy/core/hpack/hpack_constants.cc
    gquiche/spdy/core/hpack/hpack_decoder_adapter.cc
    gquiche/spdy/core/hpack/hpack_encoder.cc
    gquiche/spdy/core/hpack/hpack_entry.cc
    gquiche/spdy/core/hpack/hpack_header_table.cc
    gquiche/spdy/core/hpack/hpack_output_stream.cc
    gquiche/spdy/core/hpack/hpack_static_table.cc
    gquiche/spdy/core/http2_frame_decoder_adapter.cc
    gquiche/spdy/core/recording_headers_handler.cc
    gquiche/spdy/core/spdy_alt_svc_wire_format.cc
    gquiche/spdy/core/spdy_frame_builder.cc
    gquiche/spdy/core/spdy_frame_reader.cc
    gquiche/spdy/core/spdy_framer.cc
    gquiche/spdy/core/spdy_header_block.cc
    gquiche/spdy/core/spdy_header_storage.cc
    gquiche/spdy/core/spdy_no_op_visitor.cc
    gquiche/spdy/core/spdy_pinnable_buffer_piece.cc
    gquiche/spdy/core/spdy_prefixed_buffer_reader.cc
    gquiche/spdy/core/spdy_protocol.cc
    gquiche/spdy/core/spdy_simple_arena.cc
)


SET(QUIC_TOOLS_SRCS
    gquiche/quic/tools/simple_ticket_crypter.cc
)

message("PROTO_SRCS = ${CoreProtoSource}")
message("BINARY_SRC = ${CMAKE_CURRENT_BINARY_DIR}")

### quiche library
ADD_LIBRARY(quiche
    ${BASE_SRCS}
    ${NET_SRCS}
    ${PLATFORM_SRCS}
    ${GQUICHE_SRCS}
    ${CoreProtoSource}
)

TARGET_LINK_LIBRARIES(quiche
    absl::base
    absl::strings
    absl::str_format
    absl::time
    absl::flat_hash_map
    absl::synchronization
    gurl fmt ssl
    ${QuicCoreProto}
    ${Protobuf_LIBRARIES}
    ${Z}
)

if (ENABLE_LINK_TCMALLOC)
    TARGET_LINK_LIBRARIES(quiche
        libtcmalloc_minimal.a
)
endif()

### simple quic client
SET(SIMPLE_QUIC_CLIENT_SRCS
    gquiche/quic/tools/quic_client_bin.cc
    gquiche/quic/tools/quic_epoll_client_factory.cc
    gquiche/quic/tools/quic_toy_client.cc
    gquiche/quic/tools/quic_url.cc
    gquiche/quic/tools/quic_spdy_client_base.cc
    gquiche/quic/tools/quic_client_base.cc
    gquiche/quic/tools/quic_client.cc
    gquiche/quic/tools/quic_spdy_client_base.cc
    gquiche/quic/tools/quic_simple_client_stream.cc
    gquiche/quic/tools/quic_simple_client_session.cc
    gquiche/quic/tools/quic_client_epoll_network_helper.cc
)

# Build bvc quic server binaries.
ADD_EXECUTABLE(simple_quic_client ${SIMPLE_QUIC_CLIENT_SRCS} ${EPOLL_SERVER_SRC})
TARGET_LINK_LIBRARIES(simple_quic_client -static-libstdc++
    quiche
)

### simple quic client
SET(SIMPLE_QUIC_SERVER_SRCS
    gquiche/quic/tools/quic_server_bin.cc
    gquiche/quic/tools/quic_backend_response.cc
    gquiche/quic/tools/quic_epoll_server_factory.cc
    gquiche/quic/tools/quic_memory_cache_backend.cc
    gquiche/quic/tools/quic_server.cc
    gquiche/quic/tools/quic_simple_crypto_server_stream_helper.cc
    gquiche/quic/tools/quic_simple_dispatcher.cc
    gquiche/quic/tools/quic_simple_server_session.cc
    gquiche/quic/tools/quic_simple_server_stream.cc
    gquiche/quic/tools/quic_toy_server.cc
    gquiche/quic/tools/quic_url.cc
)

# Build bvc quic server binaries.
ADD_EXECUTABLE(simple_quic_server ${SIMPLE_QUIC_SERVER_SRCS} ${EPOLL_SERVER_SRC})
TARGET_LINK_LIBRARIES(simple_quic_server -static-libstdc++
    quiche
)
