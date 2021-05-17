#!/bin/bash

set -e

# This script is invoked by developers to tweak google QUICHE source files into
# a form usable by BVC. Transformations performed here:
#
# - Move subtree under quiche/ base dir, for clarity in #include statements.
# - Rewrite include directives for platform/impl files to point to the directory
#   containing BVC's QUICHE platform implementation.
# - Fix include directives for non-platform/impl files to remove
#   "net/third_party" from the path. (This is an artifact of Chromium source
#   tree structure.)

# src_base_dir: Base directory of unmodified google QUICHE source files.
# dst_base_dir: Generated directory of generated quiche codes used by BVC.
src_base_dir="${PWD}/gquiche"
dst_temp_dir="${PWD}/gquiche_tmp"

# sed commands to apply to each source file.
cat <<EOF >sed_commands
# Rewrite include directives for testonly platform impl files.
# TODO

# Rewrite include directives for gquiche root dir
/^#include/ s!common/!gquiche/common/!
/^#include/ s!epoll_server/!gquiche/epoll_server/!
/^#include/ s!http2/!gquiche/http2/!
/^#include/ s!quic/!gquiche/quic/!
/^#include/ s!spdy/!gquiche/spdy/!

# Rewrite include directives for platform impl files.
/^#include/ s!net/quiche/common/platform/impl/!platform/quiche_platform_impl/!
/^#include/ s!quiche_platform_impl/!platform/quiche_platform_impl/!
/^#include/ s!net/tools/epoll_server/platform/impl/!platform/epoll_platform_impl/!
/^#include/ s!net/http2/platform/impl/!platform/http2_platform_impl/!
/^#include/ s!net/quic/platform/impl/!platform/quic_platform_impl/!
/^#include/ s!net/spdy/platform/impl/!platform/spdy_platform_impl/!

# Rewrite gmock & gtest includes.
# TODO

# Rewrite third_party includes.
/^#include/ s!third_party/boringssl/src/include/!!
/^#include/ s!third_party/zlib/zlib!zlib!

# Rewrite #pragma clang
/^#pragma/ s!clang!GCC!
/^#pragma/ s!-Weverything!-Wall!

EOF

SRCS=(`cd ${src_base_dir} && find . -name "*.h" -o -name "*.c" -o -name "*.cc" -o -name "*.inc" -o -name "*.proto" -type f | sort -r`)

len=${#SRCS[*]}
echo "Starting rewrite Google quiche source files with number: ${len}"

for src_file in "${SRCS[@]}"
do
  src="${src_base_dir}/${src_file}"
  src_path="$(dirname $src_file)"
  dst_path="${dst_temp_dir}/${src_path}"
  dst_file="${dst_temp_dir}/${src_file}"

  mkdir -p $dst_path

  # Apply text substitutions.
  #sed -E -f sed_commands "${src}" > "${dst_file}"
  sed -i -E -f sed_commands "${src}"
done

  # Rewrite DVLOG in googleurl
  sed -i 's/DVLOG(1)/GURL_DLOG(ERROR)/g' googleurl/base/strings/string_split.cc

#cp -fr $dst_temp_dir/* $src_base_dir/
rm -fr $dst_temp_dir

echo "Done rewrite Google source files."
