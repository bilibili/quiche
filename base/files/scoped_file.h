#ifndef QUICHE_BASE_FILES_SCOPED_FILE_H_
#define QUICHE_BASE_FILES_SCOPED_FILE_H_

#include <stdio.h>
#include <memory>

namespace base {

namespace internal {

// Functor for |ScopedFILE| (below).
struct ScopedFILECloser {
  inline void operator()(FILE* x) const {
    if (x)
      fclose(x);
  }
};

} // namespace internal

// Automatically closes |FILE*|s.
typedef std::unique_ptr<FILE, internal::ScopedFILECloser> ScopedFILE;

} // namespace base

#endif // QUICHE_BASE_FILES_SCOPED_FILE_H_
