#pragma once

#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"

namespace quic {

template <class T>
void AdjustTestValueImpl(quiche::QuicheStringPiece label, T* var) {}

}  // namespace quic
