#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <cstring>

#include "base/files/file_util.h"
#include "base/files/file_path.h"

#include "gquiche/quic/platform/api/quic_logging.h"

namespace base {

std::string AppendModeCharacter(const char* mode, char mode_char) {
  std::string result(mode);
  size_t comma_pos = result.find(',');
  result.insert(comma_pos == std::string::npos ? result.length() : comma_pos, 1,
                mode_char);
  return result;
}

FILE* OpenFile(const FilePath& filename, const char* mode) {
  // 'e' is unconditionally added below, so be sure there is not one already
  // present before a comma in |mode|.
  QUICHE_DCHECK(
      strchr(mode, 'e') == nullptr ||
      (strchr(mode, ',') != nullptr && strchr(mode, 'e') > strchr(mode, ',')));
  FILE* result = nullptr;
  std::string mode_with_e(AppendModeCharacter(mode, 'e'));
  const char* the_mode = mode_with_e.c_str();
  do {
    result = fopen(filename.value().c_str(), the_mode);
  } while (!result && errno == EINTR);
  return result;
}
} // namespace base
