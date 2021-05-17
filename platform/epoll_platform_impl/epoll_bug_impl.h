#pragma once

#include "platform/epoll_platform_impl/epoll_logging_impl.h"

#define EPOLL_BUG_IMPL(bug_id) EPOLL_LOG_IMPL(DFATAL)
#define EPOLL_BUG_V2_IMPL(bug_id) EPOLL_LOG_IMPL(DFATAL)
