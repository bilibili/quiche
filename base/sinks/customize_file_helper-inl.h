#pragma once

#ifndef SPDLOG_HEADER_ONLY
#include "spdlog/details/customize_file_helper.h"
#endif

#include "spdlog/details/os.h"
#include "spdlog/common.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <tuple>

namespace spdlog {
namespace details {

SPDLOG_INLINE customize_file_helper::~customize_file_helper() {
    close();
}

SPDLOG_INLINE void customize_file_helper::open(const filename_t &fname, bool truncate) {
    close();
    filename_ = fname;
    auto *mode = truncate ? SPDLOG_FILENAME_T("wb") : SPDLOG_FILENAME_T("ab");

    for (int tries = 0; tries < open_tries_; ++tries) {
        // create containing folder if not exists already.
        os::create_dir(os::dir_name(fname));
        if (!os::fopen_s(&fd_, fname, mode)) {
            return;
        }
        details::os::sleep_for_millis(open_interval_);
    }

    throw_spdlog_ex("Failed opening file " + os::filename_to_str(filename_) + " for writing", errno);
}

SPDLOG_INLINE void customize_file_helper::reopen(bool truncate) {
    if (filename_.empty()) {
        throw_spdlog_ex("Failed re opening file - was not opened before");
    }
    this->open(filename_, truncate);
}

SPDLOG_INLINE void customize_file_helper::flush() {
    std::fflush(fd_);
}

SPDLOG_INLINE void customize_file_helper::close() {
    if (fd_ != nullptr) {
        std::fclose(fd_);
        fd_ = nullptr;
    }
}

SPDLOG_INLINE void customize_file_helper::write(const memory_buf_t &buf, size_t pos) {
  size_t msg_size = buf.size();
  if(msg_size - 1 < pos) {
    throw_spdlog_ex("buffer pos error");
    return;
  }

  msg_size = msg_size - pos;
  auto data = buf.data() + pos;
  if (std::fwrite(data, 1, msg_size, fd_) != msg_size) {
    throw_spdlog_ex("Failed writing to file " + details::os::filename_to_str(filename_), errno);
  }
}

SPDLOG_INLINE void customize_file_helper::write(const std::string &buf) {
    size_t msg_size = buf.size();
    auto data = buf.data();
    if (std::fwrite(data, 1, msg_size, fd_) != msg_size) {
        throw_spdlog_ex("Failed writing to file " + os::filename_to_str(filename_), errno);
    }
}

SPDLOG_INLINE size_t customize_file_helper::size() const {
    if (fd_ == nullptr) {
        throw_spdlog_ex("Cannot use size() on closed file " + os::filename_to_str(filename_));
    }
    return os::filesize(fd_);
}

} // namespace details
} // namespace spdlog
