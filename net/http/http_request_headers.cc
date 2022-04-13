// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copy from chromium/net/http_request_headers, and make some changes to compatible with quic_server_src
#include <utility>

#include "base/strings/stringprintf.h"
#include "gquiche/quic/platform/api/quic_logging.h"
#include "googleurl/base/strings/string_split.h"
#include "googleurl/base/strings/string_util.h"
#include "net/http/http_util.h"
#include "net/http/http_request_headers.h"

namespace net {

const char HttpRequestHeaders::kConnectMethod[] = "CONNECT";
const char HttpRequestHeaders::kGetMethod[] = "GET";
const char HttpRequestHeaders::kHeadMethod[] = "HEAD";
const char HttpRequestHeaders::kOptionsMethod[] = "OPTIONS";
const char HttpRequestHeaders::kPostMethod[] = "POST";
const char HttpRequestHeaders::kTraceMethod[] = "TRACE";
const char HttpRequestHeaders::kTrackMethod[] = "TRACK";
const char HttpRequestHeaders::kAccept[] = "Accept";
const char HttpRequestHeaders::kAcceptCharset[] = "Accept-Charset";
const char HttpRequestHeaders::kAcceptEncoding[] = "Accept-Encoding";
const char HttpRequestHeaders::kAcceptLanguage[] = "Accept-Language";
const char HttpRequestHeaders::kAuthorization[] = "Authorization";
const char HttpRequestHeaders::kCacheControl[] = "Cache-Control";
const char HttpRequestHeaders::kConnection[] = "Connection";
const char HttpRequestHeaders::kContentLength[] = "Content-Length";
const char HttpRequestHeaders::kContentType[] = "Content-Type";
const char HttpRequestHeaders::kCookie[] = "Cookie";
const char HttpRequestHeaders::kHost[] = "Host";
const char HttpRequestHeaders::kIfMatch[] = "If-Match";
const char HttpRequestHeaders::kIfModifiedSince[] = "If-Modified-Since";
const char HttpRequestHeaders::kIfNoneMatch[] = "If-None-Match";
const char HttpRequestHeaders::kIfRange[] = "If-Range";
const char HttpRequestHeaders::kIfUnmodifiedSince[] = "If-Unmodified-Since";
const char HttpRequestHeaders::kOrigin[] = "Origin";
const char HttpRequestHeaders::kPragma[] = "Pragma";
const char HttpRequestHeaders::kProxyAuthorization[] = "Proxy-Authorization";
const char HttpRequestHeaders::kProxyConnection[] = "Proxy-Connection";
const char HttpRequestHeaders::kRange[] = "Range";
const char HttpRequestHeaders::kReferer[] = "Referer";
const char HttpRequestHeaders::kTransferEncoding[] = "Transfer-Encoding";
const char HttpRequestHeaders::kUserAgent[] = "User-Agent";

HttpRequestHeaders::HeaderKeyValuePair::HeaderKeyValuePair() = default;

HttpRequestHeaders::HeaderKeyValuePair::HeaderKeyValuePair(
    const gurl_base::StringPiece& key,
    const gurl_base::StringPiece& value)
    : key(key.data(), key.size()), value(value.data(), value.size()) {}

HttpRequestHeaders::Iterator::Iterator(const HttpRequestHeaders& headers)
    : started_(false),
      curr_(headers.headers_.begin()),
      end_(headers.headers_.end()) {}

HttpRequestHeaders::Iterator::~Iterator() = default;

bool HttpRequestHeaders::Iterator::GetNext() {
  if (!started_) {
    started_ = true;
    return curr_ != end_;
  }

  if (curr_ == end_)
    return false;

  ++curr_;
  return curr_ != end_;
}

HttpRequestHeaders::HttpRequestHeaders() = default;
HttpRequestHeaders::HttpRequestHeaders(const HttpRequestHeaders& other) =
    default;
HttpRequestHeaders::HttpRequestHeaders(HttpRequestHeaders&& other) = default;
HttpRequestHeaders::~HttpRequestHeaders() = default;

HttpRequestHeaders& HttpRequestHeaders::operator=(
    const HttpRequestHeaders& other) = default;
HttpRequestHeaders& HttpRequestHeaders::operator=(HttpRequestHeaders&& other) =
    default;

bool HttpRequestHeaders::GetHeader(const gurl_base::StringPiece& key,
                                   std::string* out) const {
  auto it = FindHeader(key);
  if (it == headers_.end())
    return false;
  out->assign(it->value);
  return true;
}

void HttpRequestHeaders::Clear() {
  headers_.clear();
}

void HttpRequestHeaders::SetHeader(const gurl_base::StringPiece& key,
                                   const gurl_base::StringPiece& value) {
  // Invalid header names or values could mean clients can attach
  // browser-internal headers.
  QUICHE_DCHECK(HttpUtil::IsValidHeaderName(key)) << key;
  QUICHE_DCHECK(HttpUtil::IsValidHeaderValue(value)) << key << ":" << value;
  SetHeaderInternal(key, value);
}

void HttpRequestHeaders::SetHeaderIfMissing(const gurl_base::StringPiece& key,
                                            const gurl_base::StringPiece& value) {
  // Invalid header names or values could mean clients can attach
  // browser-internal headers.
  QUICHE_DCHECK(HttpUtil::IsValidHeaderName(key));
  QUICHE_DCHECK(HttpUtil::IsValidHeaderValue(value));
  auto it = FindHeader(key);
  if (it == headers_.end())
    headers_.push_back(HeaderKeyValuePair(key, value));
}

void HttpRequestHeaders::RemoveHeader(const gurl_base::StringPiece& key) {
  auto it = FindHeader(key);
  if (it != headers_.end())
    headers_.erase(it);
}

void HttpRequestHeaders::AddHeaderFromString(
    const gurl_base::StringPiece& header_line) {
  QUICHE_DCHECK_EQ(std::string::npos, header_line.find("\r\n"))
      << "\"" << header_line << "\" contains CRLF.";

  const std::string::size_type key_end_index = header_line.find(":");
  if (key_end_index == std::string::npos) {
    QUIC_LOG(DFATAL) << "\"" << header_line << "\" is missing colon delimiter.";
    return;
  }

  if (key_end_index == 0) {
    QUIC_LOG(DFATAL) << "\"" << header_line << "\" is missing header key.";
    return;
  }

  const gurl_base::StringPiece header_key(header_line.data(), key_end_index);
  if (!HttpUtil::IsValidHeaderName(header_key)) {
    QUIC_LOG(DFATAL) << "\"" << header_line << "\" has invalid header key.";
    return;
  }

  const std::string::size_type value_index = key_end_index + 1;

  if (value_index < header_line.size()) {
    gurl_base::StringPiece header_value(header_line.data() + value_index,
                                   header_line.size() - value_index);
    header_value = HttpUtil::TrimLWS(header_value);
    if (!HttpUtil::IsValidHeaderValue(header_value)) {
      QUIC_LOG(DFATAL) << "\"" << header_line << "\" has invalid header value.";
      return;
    }
    SetHeader(header_key, header_value);
  } else if (value_index == header_line.size()) {
    SetHeader(header_key, "");
  } else {
    QUIC_NOTREACHED();
  }
}

void HttpRequestHeaders::AddHeadersFromString(
    const gurl_base::StringPiece& headers) {
  for (const gurl_base::StringPiece& header : gurl_base::SplitStringPieceUsingSubstr(
           headers, "\r\n", gurl_base::TRIM_WHITESPACE, gurl_base::SPLIT_WANT_NONEMPTY)) {
    AddHeaderFromString(header);
  }
}

void HttpRequestHeaders::MergeFrom(const HttpRequestHeaders& other) {
  for (auto it = other.headers_.begin(); it != other.headers_.end(); ++it) {
    SetHeader(it->key, it->value);
  }
}

std::string HttpRequestHeaders::ToString() const {
  std::string output;
  for (auto it = headers_.begin(); it != headers_.end(); ++it) {
    base::StringAppendF(&output, "%s: %s\r\n", it->key.c_str(),
                        it->value.c_str());
  }
  output.append("\r\n");
  return output;
}

HttpRequestHeaders::HeaderVector::iterator HttpRequestHeaders::FindHeader(
    const gurl_base::StringPiece& key) {
  for (auto it = headers_.begin(); it != headers_.end(); ++it) {
    if (gurl_base::EqualsCaseInsensitiveASCII(key, it->key))
      return it;
  }

  return headers_.end();
}

HttpRequestHeaders::HeaderVector::const_iterator HttpRequestHeaders::FindHeader(
    const gurl_base::StringPiece& key) const {
  for (auto it = headers_.begin(); it != headers_.end(); ++it) {
    if (gurl_base::EqualsCaseInsensitiveASCII(key, it->key))
      return it;
  }

  return headers_.end();
}

void HttpRequestHeaders::SetHeaderInternal(const gurl_base::StringPiece& key,
                                           const gurl_base::StringPiece& value) {
  auto it = FindHeader(key);
  if (it != headers_.end())
    it->value.assign(value.data(), value.size());
  else
    headers_.push_back(HeaderKeyValuePair(key, value));
}

}  // namespace net
