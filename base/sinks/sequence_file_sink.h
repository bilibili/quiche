#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <memory>
#include <vector>

#include "customize_file_helper.h"
#include "base/bvc-qlog/src/qlogger_types.h"
#include "gquiche/quic/platform/api/quic_mutex.h"

#include "spdlog/sinks/base_sink.h"
#include "spdlog/details/file_helper.h"
#include "spdlog/details/null_mutex.h"
#include "spdlog/details/synchronous_factory.h"
#include "absl/strings/str_cat.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

using quic::QuicMutex;
namespace spdlog {
namespace sinks {

using namespace rapidjson;
using details::os::path_exists;
//
// sequence file sink based on size
//
template<typename Mutex>
class sequence_file_sink final : public base_sink<Mutex> {
public:
  sequence_file_sink(filename_t base_filename,
                     filename_t final_filename, 		      
                     std::size_t max_size,
                     std::size_t max_files,
                     std::string metadata_head,
                     std::string metadata_tail,
                     std::shared_ptr<Document> last_summary,
                     std::shared_ptr<Document> pre_summary,
		     std::shared_ptr<quic::QuicMutex> lock,
                     std::size_t free_file_number = 1 );
  static filename_t calc_filename(const filename_t &filename, std::size_t index);

  ~sequence_file_sink() {
    filename_t target = calc_filename(final_filename_, free_file_number_);
    if (!path_exists(target)) {
      spdlog::details::os::create_dir(spdlog::details::os::dir_name(target));
    }
    std::rename(base_filename_.c_str(), target.c_str());
  }

protected:
  void sink_it_(const details::log_msg &msg) override;
  void flush_() override;

private:
  void sequence_();
  std::string currentSummary();

  // delete the target if exists, and rename the src file  to target
  // return true on success, false otherwise.
  bool rename_file_(const filename_t &src_filename, const filename_t &target_filename);

  filename_t base_filename_;
  filename_t final_filename_;  
  std::size_t max_size_;
  std::size_t max_files_;
  std::size_t free_file_number_;
  std::size_t current_size_;

  std::string metadata_head_;
  std::string metadata_tail_;
  size_t metadata_head_size_;
  size_t metadata_tail_size_;
   
  std::shared_ptr<Document> last_summary_;
  std::shared_ptr<Document> pre_summary_;
  std::shared_ptr<quic::QuicMutex> lock_;

  details::customize_file_helper file_helper_;

  //std::FILE *fd_{nullptr};

  bool is_first_event_;
};

using sequence_file_sink_mt = sequence_file_sink<std::mutex>;
using sequence_file_sink_st = sequence_file_sink<details::null_mutex>;

} // namespace sinks

//
// factory functions
//
template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> sequence_logger_mt(
  const std::string &logger_name, const filename_t &filename, size_t max_file_size, size_t max_files, bool rotate_on_open = false) {
  return Factory::template create<sinks::sequence_file_sink_mt>(logger_name, filename, max_file_size, max_files, rotate_on_open);
}

template<typename Factory = spdlog::synchronous_factory>
inline std::shared_ptr<logger> sequence_logger_st(
  const std::string &logger_name, const filename_t &filename, size_t max_file_size, size_t max_files, bool rotate_on_open = false) {
  return Factory::template create<sinks::sequence_file_sink_st>(logger_name, filename, max_file_size, max_files, rotate_on_open);
}

} // namespace spdlog

#ifdef SPDLOG_HEADER_ONLY
#include "base/sinks/sequence_file_sink-inl.h"
#endif

