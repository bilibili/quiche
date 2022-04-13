#ifndef QUICHE_HTTP2_ADAPTER_OGHTTP2_UTIL_H_
#define QUICHE_HTTP2_ADAPTER_OGHTTP2_UTIL_H_

#include "absl/types/span.h"
#include "gquiche/http2/adapter/http2_protocol.h"
#include "gquiche/common/platform/api/quiche_export.h"
#include "gquiche/spdy/core/spdy_header_block.h"

namespace http2 {
namespace adapter {

QUICHE_EXPORT_PRIVATE spdy::SpdyHeaderBlock ToHeaderBlock(
    absl::Span<const Header> headers);

}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_OGHTTP2_UTIL_H_
