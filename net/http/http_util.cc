// http_util is derived from chromium net/http/http_util
#include "net/http/http_util.h"

namespace net {

namespace {

template <typename ConstIterator>
void TrimLWSImplementation(ConstIterator* begin, ConstIterator* end) {
  // leading whitespace
  while (*begin < *end && HttpUtil::IsLWS((*begin)[0]))
    ++(*begin);

  // trailing whitespace
  while (*begin < *end && HttpUtil::IsLWS((*end)[-1]))
    --(*end);
}

} //namespace


// static
bool HttpUtil::IsValidHeaderName(gurl_base::StringPiece name) {
  // Check whether the header name is RFC 2616-compliant.
  return HttpUtil::IsToken(name);
}

// static
bool HttpUtil::IsValidHeaderValue(gurl_base::StringPiece value) {
  // Just a sanity check: disallow NUL, CR and LF.
  for (char c : value) {
    if (c == '\0' || c == '\r' || c == '\n')
      return false;
  }
  return true;
}

bool HttpUtil::IsLWS(char c) {
  const gurl_base::StringPiece kWhiteSpaceCharacters(HTTP_LWS);
  return kWhiteSpaceCharacters.find(c) != gurl_base::StringPiece::npos;
}

// static
void HttpUtil::TrimLWS(std::string::const_iterator* begin,
                       std::string::const_iterator* end) {
  TrimLWSImplementation(begin, end);
}

// static
gurl_base::StringPiece HttpUtil::TrimLWS(const gurl_base::StringPiece& string) {
  const char* begin = string.data();
  const char* end = string.data() + string.size();
  TrimLWSImplementation(&begin, &end);
  return gurl_base::StringPiece(begin, end - begin);
}

// See RFC 7230 Sec 3.2.6 for the definition of |token|.
bool HttpUtil::IsToken(gurl_base::StringPiece string) {
  if (string.empty())
    return false;
  for (char c : string) {
    if (!IsTokenChar(c))
      return false;
  }
  return true;
}

bool HttpUtil::IsTokenChar(char c) {
  return !(c >= 0x7F || c <= 0x20 || c == '(' || c == ')' || c == '<' ||
           c == '>' || c == '@' || c == ',' || c == ';' || c == ':' ||
           c == '\\' || c == '"' || c == '/' || c == '[' || c == ']' ||
           c == '?' || c == '=' || c == '{' || c == '}');
}

} // namespace net
