#pragma once

#include <chrono>

namespace epoll_server {

inline int64_t WallTimeNowInUsecImpl() {
  return std::chrono::duration_cast<std::chrono::microseconds>
         (std::chrono::system_clock::now().time_since_epoch()).count();
}

}  // namespace epoll_server

