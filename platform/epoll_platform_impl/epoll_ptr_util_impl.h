#pragma once

#include <memory>

namespace epoll_server {

template <typename T, typename... Args>
std::unique_ptr<T> EpollMakeUniqueImpl(Args&&... args) {
  return std::make_unique<T>(std::forward<Args>(args)...);
}

} // namespace epoll_server