#include <sys/stat.h>
#include <sys/types.h>
#include "base/files/file_util.h"
#include "base/files/file_path.h"
#include "base/files/scoped_file.h"
#include "base/posix/eintr_wrapper.h"

namespace base {
bool ReadFileToString(const FilePath& path, std::string* contents) {
  return ReadFileToStringWithMaxSize(path, contents,
                                     std::numeric_limits<size_t>::max());
}

bool ReadFileToStringWithMaxSize(const FilePath& path,
                                 std::string* contents,
                                 size_t max_size) {
  if (contents)
    contents->clear();
  if (path.ReferencesParent())
    return false;
  ScopedFILE file_stream(OpenFile(path, "rb"));
  if (!file_stream)
    return false;
  return ReadStreamToStringWithMaxSize(file_stream.get(), max_size, contents);
}

bool ReadStreamToStringWithMaxSize(FILE* stream,
                                   size_t max_size,
                                   std::string* contents) {
  if (contents)
    contents->clear();

  // Seeking to the beginning is best-effort -- it is expected to fail for
  // certain non-file stream (e.g., pipes).
  HANDLE_EINTR(fseek(stream, 0, SEEK_SET));

  // Many files have incorrect size (proc files etc). Hence, the file is read
  // sequentially as opposed to a one-shot read, using file size as a hint for
  // chunk size if available.
  constexpr int64_t kDefaultChunkSize = 1 << 16;
  int64_t chunk_size = kDefaultChunkSize - 1;

  stat_wrapper_t file_info = {};
  if (!fstat64(fileno(stream), &file_info) && file_info.st_size > 0)
    chunk_size = file_info.st_size;

  // We need to attempt to read at EOF for feof flag to be set so here we
  // use |chunk_size| + 1.
  chunk_size = std::min<uint64_t>(chunk_size, max_size) + 1;

  size_t bytes_read_this_pass;
  size_t bytes_read_so_far = 0;
  bool read_status = true;
  std::string local_contents;
  local_contents.resize(chunk_size);

  while ((bytes_read_this_pass = fread(&local_contents[bytes_read_so_far], 1,
                                       chunk_size, stream)) > 0) {
    if ((max_size - bytes_read_so_far) < bytes_read_this_pass) {
      // Read more than max_size bytes, bail out.
      bytes_read_so_far = max_size;
      read_status = false;
      break;
    }
    // In case EOF was not reached, iterate again but revert to the default
    // chunk size.
    if (bytes_read_so_far == 0)
      chunk_size = kDefaultChunkSize;

    bytes_read_so_far += bytes_read_this_pass;
    // Last fread syscall (after EOF) can be avoided via feof, which is just a
    // flag check.
    if (feof(stream))
      break;
    local_contents.resize(bytes_read_so_far + chunk_size);
  }
  read_status = read_status && !ferror(stream);
  if (contents) {
    contents->swap(local_contents);
    contents->resize(bytes_read_so_far);
  }

  return read_status;
}

} //namespace base
