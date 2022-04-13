#pragma once

#include "spdlog/common.h"
#include <tuple>
#include <string>

namespace spdlog {
namespace details {

class SPDLOG_API customize_file_helper {
public:
    explicit customize_file_helper() = default;

    customize_file_helper(const customize_file_helper &) = delete;
    customize_file_helper &operator=(const customize_file_helper &) = delete;
    ~customize_file_helper();

    void open(const filename_t &fname, bool truncate = false);
    void reopen(bool truncate);
    void flush();
    void close();
    void write(const memory_buf_t &buf, size_t pos);
    void write(const std::string &buf);        
    size_t size() const;

private:
    const int open_tries_ = 5;
    const int open_interval_ = 10;
    std::FILE *fd_{nullptr};
    filename_t filename_;
};
} // namespace details
} // namespace spdlog

#ifdef SPDLOG_HEADER_ONLY
#include "customize_file_helper-inl.h"
#endif