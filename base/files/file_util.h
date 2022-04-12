#ifndef QUICHE_BASE_FILES_FILE_UTIL_H_
#define QUICHE_BASE_FILES_FILE_UTIL_H_

#if defined(OS_POSIX) || defined(OS_FUCHSIA)
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <string>

#include "base/files/file_path.h"

namespace base {
class FilePath;

typedef struct stat64 stat_wrapper_t;

// Reads the file at |path| into |contents| and returns true on success and
// false on error.  For security reasons, a |path| containing path traversal
// components ('..') is treated as a read error and |contents| is set to empty.
// In case of I/O error, |contents| holds the data that could be read from the
// file before the error occurred.
// |contents| may be NULL, in which case this function is useful for its side
// effect of priming the disk cache (could be used for unit tests).
bool ReadFileToString(const FilePath& path, std::string* contents);

// Reads the file at |path| into |contents| and returns true on success and
// false on error.  For security reasons, a |path| containing path traversal
// components ('..') is treated as a read error and |contents| is set to empty.
// In case of I/O error, |contents| holds the data that could be read from the
// file before the error occurred.  When the file size exceeds |max_size|, the
// function returns false with |contents| holding the file truncated to
// |max_size|.
// |contents| may be NULL, in which case this function is useful for its side
// effect of priming the disk cache (could be used for unit tests).
bool ReadFileToStringWithMaxSize(const FilePath& path,
                                 std::string* contents,
                                 size_t max_size);

// As ReadFileToStringWithMaxSize, but reading from an open stream after seeking
// to its start (if supported by the stream).
bool ReadStreamToStringWithMaxSize(FILE* stream,
                                   size_t max_size,
                                   std::string* contents);
// Wrapper for fopen-like calls. Returns non-NULL FILE* on success. The
// underlying file descriptor (POSIX) or handle (Windows) is unconditionally
// configured to not be propagated to child processes.
FILE* OpenFile(const FilePath& filename, const char* mode);

} // namespace base

#endif //QUICHE_BASE_FILES_FILE_UTIL_H_
