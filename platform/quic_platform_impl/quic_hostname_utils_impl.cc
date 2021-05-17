// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "platform/quic_platform_impl/quic_hostname_utils_impl.h"

#include <string>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "googleurl/url/gurl.h"

// TODO(wub): Implement both functions on top of GoogleUrl, then enable
// quiche/quic/platform/api/quic_hostname_utils_test.cc.

namespace quic {

// static
bool QuicHostnameUtilsImpl::IsValidSNI(quiche::QuicheStringPiece sni) {
  // TODO(wub): Implement it on top of GoogleUrl, once it is available.
  // add by bvc
  std::string u_sni = absl::StrCat("http://", sni);
  GURL gurl_sni = GURL(u_sni);
  return u_sni.find_last_of('.') != std::string::npos && gurl_sni.is_valid();
}

// static
std::string QuicHostnameUtilsImpl::NormalizeHostname(quiche::QuicheStringPiece hostname) {
  // TODO(wub): Implement it on top of GoogleUrl, once it is available.
  std::string host = absl::AsciiStrToLower(hostname);

  // Walk backwards over the string, stopping at the first trailing dot.
  size_t host_end = host.length();
  while (host_end != 0 && host[host_end - 1] == '.') {
    host_end--;
  }

  // Erase the trailing dots.
  if (host_end != host.length()) {
    host.erase(host_end, host.length() - host_end);
  }

  return host;
}

} // namespace quic
