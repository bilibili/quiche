CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

PROJECT(googleurl)

SET(CMAKE_CXX_STANDARD 17)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
)

SET(BASE_THIRDPARTY_SRCS
    base/third_party/icu/icu_utf.cc
)

SET(BASE_SRCS
    base/compiler_specific.h
)

SET(BUILD_SRCS
    build/build_config.h
)

SET(BASE_STRINGS_SRCS
    base/strings/string16.cc
    base/strings/string_piece.cc
    base/strings/string_split.cc
    base/strings/string_util.cc
    base/strings/string_util_constants.cc
    base/strings/utf_string_conversion_utils.cc
    base/strings/utf_string_conversions.cc
)

SET(URL_SRCS
    url/gurl.cc
    url/third_party/mozilla/url_parse.cc
    url/url_canon.cc
    url/url_canon_etc.cc
    url/url_canon_filesystemurl.cc
    url/url_canon_fileurl.cc
    url/url_canon_host.cc
    url/url_canon_internal.cc
    url/url_canon_ip.cc
    url/url_canon_mailtourl.cc
    url/url_canon_path.cc
    url/url_canon_pathurl.cc
    url/url_canon_query.cc
    url/url_canon_relative.cc
    url/url_canon_stdstring.cc
    url/url_canon_stdurl.cc
    url/url_constants.cc
    url/url_idna_icu.cc
    url/url_parse_file.cc
    url/url_util.cc
)

ADD_LIBRARY(gurl
    ${BASE_SRCS}
    ${BUILD_SRCS}
    ${BASE_STRINGS_SRCS}
    ${BASE_THIRDPARTY_SRCS}
    ${URL_SRCS}
)

TARGET_LINK_LIBRARIES(gurl
    libicuuc.a
    libicudata.a
    -ldl
)
