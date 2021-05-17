#pragma once

// NOTE(wub): These macros are currently NOOP because they are supposed to be
// used by client-side stats. They should be implemented when QUIC client code
// is used by QUICHE to connect to backends.

namespace quic {

inline void QuicSleepImpl(QuicTime::Delta duration) {
  // TODO add sleep func here
  assert(0);
}

}  // namespace quic

