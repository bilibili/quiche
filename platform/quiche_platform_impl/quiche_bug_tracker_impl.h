#pragma once

// NOLINT(namespace-quiche)
//
// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "gquiche/quic/platform/api/quic_logging.h"

#define QUICHE_BUG_IMPL(bug_id) QUIC_LOG(DFATAL)
#define QUICHE_BUG_IF_IMPL(bug_id, condition) QUIC_LOG_IF(DFATAL, condition)
#define QUICHE_PEER_BUG_IMPL(bug_id) QUIC_LOG(ERROR)
#define QUICHE_PEER_BUG_IF_IMPL(bug_id, condition) QUIC_LOG_IF(ERROR, condition)
#define QUICHE_BUG_V2_IMPL(bug_id) QUIC_LOG(DFATAL)
#define QUICHE_BUG_IF_V2_IMPL(bug_id, condition) QUIC_LOG_IF(DFATAL, condition)
#define QUICHE_PEER_BUG_V2_IMPL(bug_id) QUIC_LOG(ERROR)
#define QUICHE_PEER_BUG_IF_V2_IMPL(bug_id, condition) QUIC_LOG_IF(ERROR, condition)

