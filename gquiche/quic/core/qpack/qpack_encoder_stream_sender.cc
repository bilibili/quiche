// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gquiche/quic/core/qpack/qpack_encoder_stream_sender.h"

#include <cstddef>
#include <limits>
#include <string>

#include "absl/strings/string_view.h"
#include "gquiche/quic/core/qpack/qpack_instructions.h"
#include "gquiche/quic/platform/api/quic_logging.h"

namespace quic {

QpackEncoderStreamSender::QpackEncoderStreamSender() : delegate_(nullptr) {}

void QpackEncoderStreamSender::SendInsertWithNameReference(
    bool is_static,
    uint64_t name_index,
    absl::string_view value) {
  instruction_encoder_.Encode(
      QpackInstructionWithValues::InsertWithNameReference(is_static, name_index,
                                                          value),
      &buffer_);
}

void QpackEncoderStreamSender::SendInsertWithoutNameReference(
    absl::string_view name,
    absl::string_view value) {
  instruction_encoder_.Encode(
      QpackInstructionWithValues::InsertWithoutNameReference(name, value),
      &buffer_);
}

void QpackEncoderStreamSender::SendDuplicate(uint64_t index) {
  instruction_encoder_.Encode(QpackInstructionWithValues::Duplicate(index),
                              &buffer_);
}

void QpackEncoderStreamSender::SendSetDynamicTableCapacity(uint64_t capacity) {
  instruction_encoder_.Encode(
      QpackInstructionWithValues::SetDynamicTableCapacity(capacity), &buffer_);
}

void QpackEncoderStreamSender::Flush() {
  if (buffer_.empty()) {
    return;
  }

  delegate_->WriteStreamData(buffer_);
  buffer_.clear();
}

}  // namespace quic
