#ifndef QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_SLEEP_IMPL_H_
#define QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_SLEEP_IMPL_H_

#include "gquiche/quic/core/quic_time.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wall"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#pragma GCC diagnostic pop

namespace quic {

inline void QuicSleepImpl(QuicTime::Delta duration) {
  absl::SleepFor(absl::Microseconds(duration.ToMicroseconds()));
}

}  // namespace quic

#endif  // QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_SLEEP_IMPL_H_
