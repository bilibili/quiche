#pragma once

#include "gquiche/common/platform/api/quiche_logging.h"

#define EPOLL_QUICHE_LOG_INFO QUICHE_VLOG(1)
#define EPOLL_QUICHE_LOG_WARNING QUICHE_DLOG(WARNING)
#define EPOLL_QUICHE_LOG_ERROR QUICHE_DLOG(ERROR)
#define EPOLL_QUICHE_LOG_FATAL QUICHE_LOG(FATAL)
#define EPOLL_QUICHE_LOG_DFATAL QUICHE_LOG(DFATAL)

#define EPOLL_LOG_IMPL(severity) EPOLL_QUICHE_LOG_##severity
#define EPOLL_VLOG_IMPL(verbose_level) QUICHE_VLOG(verbose_level)
#define EPOLL_DVLOG_IMPL(verbose_level) QUICHE_DVLOG(verbose_level)
#define EPOLL_PLOG_IMPL(severity) QUICHE_DVLOG(1)
