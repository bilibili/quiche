// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "platform/quic_platform_impl/quic_file_utils_impl.h"

#include "absl/strings/str_cat.h"
#include <dirent.h>
#include <string>
#include <fstream>
#include <streambuf>

namespace quic {
namespace {

static void traverseFilesInDirectory(const std::string& dirname, std::vector<std::string>& files) {
  DIR *dp = opendir(dirname.c_str());
  if (dp == nullptr) {
    return;
  }

  struct dirent *dirp = nullptr;
  while((dirp = readdir(dp)) != nullptr) {
    if (strcmp(".", dirp->d_name) == 0 || strcmp("..", dirp->d_name) == 0) {
      continue;
    }

    struct stat statbuf;
    std::string fp = dirname + (dirname[dirname.length() -1 ] == '/' ? "" : "/") + std::string(dirp->d_name);
    if(stat(fp.c_str(), &statbuf) == -1) {
      continue;
    }
    if(S_ISDIR(statbuf.st_mode)) {
      continue;
    }

    files.push_back(std::move(fp));
  }
  closedir(dp);
}

void depthFirstTraverseDirectory(const std::string& dirname, std::vector<std::string>& files) {
  DIR *dp = opendir(dirname.c_str());
  if (dp == nullptr) {
    return;
  }

  struct dirent *dirp = nullptr;
  while((dirp = readdir(dp)) != nullptr) {
    if (strcmp(".", dirp->d_name) == 0 || strcmp("..", dirp->d_name) == 0) {
      continue;
    }

    struct stat statbuf;
    std::string fp = dirname + (dirname[dirname.length() -1 ] == '/' ? "" : "/") + std::string(dirp->d_name);
    if(stat(fp.c_str(), &statbuf) == -1) {
      continue;
    }
    if(S_ISREG(statbuf.st_mode)) {
      continue;
    }

    traverseFilesInDirectory(fp, files);
  }
  closedir(dp);

  return;
}

} // namespace

// Traverses the directory |dirname| and returns all of the files it contains.
std::vector<std::string> ReadFileContentsImpl(const std::string& dirname) {
  std::vector<std::string> files;
  depthFirstTraverseDirectory(dirname, files);
  return files;
}

// Reads the contents of |filename| as a string into |contents|.
void ReadFileContentsImpl(quiche::QuicheStringPiece filename, std::string* contents) {
  std::ifstream ifs(std::string(filename.data(), filename.length()));
  ifs.seekg(0, std::ios::end);
  contents->reserve(ifs.tellg());
  ifs.seekg(0, std::ios::beg);
  contents->assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

} // namespace quic
