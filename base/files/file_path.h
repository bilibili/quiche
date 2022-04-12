#ifndef QUICHE_BASE_FILES_FILE_PATH_H_
#define QUICHE_BASE_FILES_FILE_PATH_H_

#include <string>
#include <vector>
#include "gquiche/common/platform/api/quiche_logging.h"
#include "googleurl/base/compiler_specific.h"

// Macros for string literal initialization of FilePath::CharType[].
#if defined(OS_WIN)
#define FILE_PATH_LITERAL(x) L##x
#elif defined(OS_POSIX) || defined(OS_FUCHSIA)
#define FILE_PATH_LITERAL(x) x
#endif  // OS_WIN

namespace base {

// An abstraction to isolate users from the differences between native
// pathnames on different platforms.
class FilePath {
 public:
#if defined(OS_WIN)
  // On Windows, for Unicode-aware applications, native pathnames are wchar_t
  // arrays encoded in UTF-16.
  typedef std::wstring StringType;
#elif defined(OS_POSIX) || defined(OS_FUCHSIA)
  // On most platforms, native pathnames are char arrays, and the encoding
  // may or may not be specified.  On Mac OS X, native pathnames are encoded
  // in UTF-8.
  typedef std::string StringType;
#endif  // OS_WIN

  typedef std::string StringPieceType;
  typedef StringType::value_type CharType;

  // Null-terminated array of separators used to separate components in
  // hierarchical paths.  Each character in this array is a valid separator,
  // but kSeparators[0] is treated as the canonical separator and will be used
  // when composing pathnames.
  static const CharType kSeparators[];

  // base::size(kSeparators).
  static const size_t kSeparatorsLength;

  // A special path component meaning "this directory."
  static const CharType kCurrentDirectory[];

  // A special path component meaning "the parent directory."
  static const CharType kParentDirectory[];

  // The character used to identify a file extension.
  static const CharType kExtensionSeparator;

  FilePath();
  FilePath(const FilePath& that);
  explicit FilePath(StringPieceType path);
  ~FilePath();
  FilePath& operator=(const FilePath& that);

  // Constructs FilePath with the contents of |that|, which is left in valid but
  // unspecified state.
  FilePath(FilePath&& that) noexcept;
  // Replaces the contents with those of |that|, which is left in valid but
  // unspecified state.
  FilePath& operator=(FilePath&& that) noexcept;

  bool operator==(const FilePath& that) const;

  bool operator!=(const FilePath& that) const;

  // Required for some STL containers and operations
  bool operator<(const FilePath& that) const {
    return path_ < that.path_;
  }

  const StringType& value() const { return path_; }

  bool empty() const { return path_.empty(); }

  void clear() { path_.clear(); }

  // Returns true if |character| is in kSeparators.
  static bool IsSeparator(CharType character);

    // Returns a vector of all of the components of the provided path. It is
  // equivalent to calling DirName().value() on the path's root component,
  // and BaseName().value() on each child component.
  //
  // To make sure this is lossless so we can differentiate absolute and
  // relative paths, the root slash will be included even though no other
  // slashes will be. The precise behavior is:
  //
  // Posix:  "/foo/bar"  ->  [ "/", "foo", "bar" ]
  // Windows:  "C:\foo\bar"  ->  [ "C:", "\\", "foo", "bar" ]
  void GetComponents(std::vector<FilePath::StringType>* components) const;

    // Returns a FilePath corresponding to the directory containing the path
  // named by this object, stripping away the file component.  If this object
  // only contains one component, returns a FilePath identifying
  // kCurrentDirectory.  If this object already refers to the root directory,
  // returns a FilePath identifying the root directory. Please note that this
  // doesn't resolve directory navigation, e.g. the result for "../a" is "..".
  FilePath DirName() const WARN_UNUSED_RESULT;

  // Returns a FilePath corresponding to the last path component of this
  // object, either a file or a directory.  If this object already refers to
  // the root directory, returns a FilePath identifying the root directory;
  // this is the only situation in which BaseName will return an absolute path.
  FilePath BaseName() const WARN_UNUSED_RESULT;

  // Returns true if this FilePath contains an attempt to reference a parent
  // directory (e.g. has a path component that is "..").
  bool ReferencesParent() const;

 private:
  // Remove trailing separators from this object.  If the path is absolute, it
  // will never be stripped any more than to refer to the absolute root
  // directory, so "////" will become "/", not "".  A leading pair of
  // separators is never stripped, to support alternate roots.  This is used to
  // support UNC paths on Windows.
  void StripTrailingSeparatorsInternal();

  StringType path_;
};

std::ostream& operator<<(std::ostream& out,
                         const FilePath& file_path);

} // namespace base

#endif // QUICHE_BASE_FILES_FILE_PATH_H_
