// http_util is derived from chromium/net/http/http_util
#ifndef QUICHE_NET_HTTP_HTTP_UTIL_H_
#define QUICHE_NET_HTTP_HTTP_UTIL_H_

#include <string>
#include "googleurl/base/strings/string_piece.h"

// This is a macro to support extending this string literal at compile time.
// Please excuse me polluting your global namespace!
#define HTTP_LWS " \t"

namespace net {

class HttpUtil {
 public:
  // Returns true if |name| is a valid HTTP header name.
  static bool IsValidHeaderName(gurl_base::StringPiece name);

  // Returns false if |value| contains NUL or CRLF. This method does not perform
  // a fully RFC-2616-compliant header value validation.
  static bool IsValidHeaderValue(gurl_base::StringPiece value);

  // Return true if the character is HTTP "linear white space" (SP | HT).
  // This definition corresponds with the HTTP_LWS macro, and does not match
  // newlines.
  static bool IsLWS(char c);

    // Trim HTTP_LWS chars from the beginning and end of the string.
  static void TrimLWS(std::string::const_iterator* begin,
                      std::string::const_iterator* end);
  static gurl_base::StringPiece TrimLWS(const gurl_base::StringPiece& string);

  // Whether the character is a valid |tchar| as defined in RFC 7230 Sec 3.2.6.
  static bool IsTokenChar(char c);
  // Whether the string is a valid |token| as defined in RFC 7230 Sec 3.2.6.
  static bool IsToken(gurl_base::StringPiece str);
};

} // namespace net

#endif // QUICHE_NET_HTTP_HTTP_UTIL_H_
