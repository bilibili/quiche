#pragma once

#ifndef SPDLOG_HEADER_ONLY
#include "base/sinks/sequence_file_sink.h"
#endif

#include <stdio.h>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <mutex>
#include <string>
#include <tuple>

#include "spdlog/common.h"
#include "spdlog/details/file_helper.h"
#include "spdlog/details/null_mutex.h"
#include "spdlog/fmt/fmt.h"
namespace spdlog {
namespace sinks {

template<typename Mutex>

SPDLOG_INLINE sequence_file_sink<Mutex>::sequence_file_sink(
  filename_t base_filename, filename_t final_filename, std::size_t max_size, std::size_t max_files, std::string metadata_head, 
  std::string metadata_tail, std::shared_ptr<Document> last_summary, std::shared_ptr<Document> pre_summary, std::shared_ptr<quic::QuicMutex> lock, std::size_t free_file_number)
  : base_filename_(std::move(base_filename)),
    final_filename_(std::move(final_filename)), 	
    max_size_(max_size),
    max_files_(max_files),
    free_file_number_(free_file_number),
    metadata_head_(metadata_head),
    metadata_tail_(metadata_tail),
    last_summary_(last_summary),
    pre_summary_(pre_summary),
    lock_(lock){
  //file open
  file_helper_.open(calc_filename(base_filename_, 0),true);
  current_size_ = file_helper_.size(); // expensive. called only once

  is_first_event_ = false;
  metadata_head_size_ = metadata_head_.size();
  metadata_tail_size_ = metadata_tail_.size();
}

// calc filename according to index and file extension if exists.
// e.g. calc_filename("logs/mylog.txt, 3) => "logs/mylog_3.txt".
// e.g. calc_filename("logs/mylog.txt, 0) => "logs/mylog.txt".
template<typename Mutex>
SPDLOG_INLINE filename_t sequence_file_sink<Mutex>::calc_filename(const filename_t &filename, std::size_t index) {
  if (index == 0u) {
    return filename;
  }

  filename_t basename, ext;
  std::tie(basename, ext) = details::file_helper::split_by_extension(filename);
  return fmt::format(SPDLOG_FILENAME_T("{}_{}{}"), basename, index, ext);
}

template<typename Mutex>
SPDLOG_INLINE void sequence_file_sink<Mutex>::sink_it_(const details::log_msg &msg) {
  memory_buf_t formatted;
  base_sink<Mutex>::formatter_->format(msg, formatted);

  size_t formatted_size = formatted.size();
  char begin_of_msg = formatted[0]; 

  if (begin_of_msg == ']') {
    file_helper_.write(formatted, 0);
    current_size_ += formatted_size;
    file_helper_.close();
    return;
  } 

  if (begin_of_msg == '{') {
    file_helper_.write(formatted, 0);
    current_size_ += formatted_size;
    is_first_event_ = true;
  } else if (begin_of_msg == ',') {
    if(is_first_event_) {
      file_helper_.write(formatted, 1);
      current_size_ += formatted_size-1;
      is_first_event_ = false;
    } else {
      file_helper_.write(formatted, 0);
      current_size_ += formatted_size;
    }
  } else {    // begin_of_msg == " "
    file_helper_.write(formatted, 0);
    current_size_ += formatted_size;
    is_first_event_ = false;
  }
  
  if (current_size_ > max_size_) {       
    std::string summary_data = currentSummary();
    file_helper_.write(metadata_tail_);    
    file_helper_.write(summary_data);  
    flush_();

    //split file
    sequence_();
    file_helper_.write(metadata_head_);
    current_size_ = metadata_head_size_;

    free_file_number_ = (free_file_number_ + 1) % max_files_;
    if (free_file_number_ == 0)
      free_file_number_ = 1;
  } 
}

template<typename Mutex>
SPDLOG_INLINE void sequence_file_sink<Mutex>::flush_() {
  file_helper_.flush();
}

template<typename Mutex>
SPDLOG_INLINE std::string sequence_file_sink<Mutex>::currentSummary() {  
  std::string msg;   
  absl::StrAppend(&msg, "\"summary\":");

  lock_->WriterLock();
  Document pre_summary;
  pre_summary.CopyFrom(*pre_summary_, pre_summary.GetAllocator());

  Document last_summary,tmp_summary;
  last_summary.CopyFrom(*last_summary_, last_summary.GetAllocator());
  tmp_summary.CopyFrom(*last_summary_, tmp_summary.GetAllocator());  
  *pre_summary_ = std::move(tmp_summary);  
  lock_->WriterUnlock(); 

  Document summary;
  summary.SetObject();
  Document::AllocatorType& summary_allocator = summary.GetAllocator();

  Value key,value;
  summary.AddMember("trace_count", last_summary["trace_count"].GetInt64(), summary_allocator);   
  summary.AddMember("max_duration", last_summary["max_duration"].GetInt64(), summary_allocator);  
  summary.AddMember("total_event_count", last_summary["total_event_count"].GetInt64() - pre_summary["total_event_count"].GetInt64(), summary_allocator);  

  value.SetObject();
  value = std::move(last_summary["report_summary"]);
  value["total_bytes_sent"] = value["total_bytes_sent"].GetInt64() - pre_summary["report_summary"]["total_bytes_sent"].GetInt64();
  value["total_bytes_recvd"] = value["total_bytes_recvd"].GetInt64() - pre_summary["report_summary"]["total_bytes_recvd"].GetInt64();
  value["total_packets_recvd"] = value["total_packets_recvd"].GetInt64() - pre_summary["report_summary"]["total_packets_recvd"].GetInt64();
  value["total_packets_sent"] = value["total_packets_sent"].GetInt64() - pre_summary["report_summary"]["total_packets_sent"].GetInt64();
  value["total_packets_lost"] = value["total_packets_lost"].GetInt64() - pre_summary["report_summary"]["total_packets_lost"].GetInt64();
  if(value["congestion_type"] != "Cubic") {
    value.AddMember("pre_startup_duration", value["total_startup_duration"].GetDouble() - pre_summary["report_summary"]["total_startup_duration"].GetDouble(), summary_allocator);
    value.AddMember("pre_drain_duration", value["total_drain_duration"].GetDouble() - pre_summary["report_summary"]["total_drain_duration"].GetDouble(), summary_allocator);
    value.AddMember("pre_probebw_duration", value["total_probebw_duration"].GetDouble() - pre_summary["report_summary"]["total_probebw_duration"].GetDouble(), summary_allocator);
    value.AddMember("pre_probertt_duration", value["total_probertt_duration"].GetDouble() - pre_summary["report_summary"]["total_probertt_duration"].GetDouble(), summary_allocator);
  }
  summary.AddMember("report_summary", value, summary_allocator);

  std::unordered_map<std::size_t, std::size_t> last_stream;
  std::unordered_map<std::size_t, std::size_t> pre_stream;
  auto lastStream_arr = last_summary["stream_map"].GetArray();
  auto preStream_arr = pre_summary["stream_map"].GetArray();
  for(auto it = lastStream_arr.Begin(); it != lastStream_arr.End(); it++) {
    last_stream.insert({(*it)[0].GetInt64(), (*it)[1].GetInt64()});
  }
  for(auto it = preStream_arr.Begin(); it != preStream_arr.End(); it++) {
    pre_stream.insert({(*it)[0].GetInt64(), (*it)[1].GetInt64()});
  }
  std::unordered_set<std::size_t> res;  
  for(auto it = last_stream.begin(); it!= last_stream.end(); it++) {
    res.insert(it->first);
  }
  for(auto it1 = pre_stream.begin(); it1 != pre_stream.end(); it1++) {
    auto it2 = last_stream.find(it1->first);
    if(it2 == last_stream.end()) {
      continue;
    }
    size_t frame_data = it2->second - it1->second;
    if(frame_data == 0) {
      res.erase(it2->first);
    } 
  }
#ifdef QLOG_FOR_QBONE
  value.SetArray();
  for(auto it = res.begin(); it != res.end(); it++) {
    value.PushBack(*it, summary_allocator); 
  } 
  summary.AddMember("stream_map", value, summary_allocator);
#else
  std::unordered_map<std::string, std::vector<int>> last_map;
  auto lastMap_arr = last_summary["uri_map"].GetArray();  
  for(auto it = lastMap_arr.Begin(); it != lastMap_arr.End(); it++) {
    std::vector<int> temp_vector;
    for(auto vector_it =(*it)[1].GetArray().Begin(); vector_it!= (*it)[1].GetArray().End(); vector_it++) {
      if(res.find(vector_it->GetInt64()) == res.end()) {
        continue;
      }
      temp_vector.push_back(vector_it->GetInt64());
    }
    if(temp_vector.size() == 0 ){
      continue;
    }
    last_map.insert({(*it)[0].GetString(), temp_vector});
  }
  
  Value uriMap_value;
  uriMap_value.SetArray();
  for (auto it = last_map.begin(); it != last_map.end(); it++) {
    size_t current_size =  (*it).second.size();
    Value temp_value;
    temp_value.SetArray();
    for (size_t j = 0; j < current_size; j++) {
      temp_value.PushBack(((*it).second)[j], summary_allocator); 
    }

    value.SetArray();
    value.PushBack(Value(((*it).first).c_str(), summary_allocator).Move(), summary_allocator); 
    value.PushBack(temp_value, summary_allocator); 
    uriMap_value.PushBack(value, summary_allocator);
  } 
  summary.AddMember("uri_map", uriMap_value, summary_allocator);
#endif
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  summary.Accept(writer);
  std::string str = buffer.GetString();
  absl::StrAppend(&msg, str, "}"); 
  return msg;
}

// sequence move file  :  src -> target
// $Path/tmp/Cid/Cid.qlog  ->  $Path/Cid/Cid_1.qlog
// $Path/tmp/Cid/Cid.qlog  ->  $Path/Cid/Cid_2.qlog
// $Path/tmp/Cid/Cid.qlog  ->  $Path/Cid/Cid_3.qlog
// ...
// $Path/tmp/Cid/Cid.qlog  ->  $Path/Cid/Cid_(max_size_-1).qlog
// $Path/tmp/Cid/Cid.qlog  ->  $Path/Cid/Cid_1.qlog
template<typename Mutex>
SPDLOG_INLINE void sequence_file_sink<Mutex>::sequence_() {
  using details::os::filename_to_str;

  //file close;
  file_helper_.close();

  filename_t src = calc_filename(base_filename_, 0);
  if (!path_exists(src)) {
    std::cout<<"file path " + details::os::filename_to_str(base_filename_) + " not exist"<<std::endl;
    details::os::create_dir(details::os::dir_name(src));
    file_helper_.reopen(true);
    is_first_event_ = true;
    return;
  }
  filename_t target = calc_filename(final_filename_, free_file_number_);
  if (!path_exists(target)) {
    details::os::create_dir(details::os::dir_name(target));
  }
  if (!rename_file_(src, target)) {
    details::os::sleep_for_millis(100);
    if (!rename_file_(src, target)) {
      // truncate the log file anyway to prevent it to grow beyond its limit!
      current_size_ = 0;
      std::cout<<"sequence_file_sink: failed renaming " + filename_to_str(src) + " to " + filename_to_str(target)<<std::endl;
    }
  }
  file_helper_.reopen(true);
  is_first_event_ = true;  
}

// delete the target if exists, and rename the src file  to target
// return true on success, false otherwise.
template<typename Mutex>
SPDLOG_INLINE bool sequence_file_sink<Mutex>::rename_file_(const filename_t &src_filename, const filename_t &target_filename) {
  // try to delete the target file in case it already exists.
  (void)details::os::remove(target_filename);
  return details::os::rename(src_filename, target_filename) == 0;
}

} // namespace sinks
} // namespace spdlog

