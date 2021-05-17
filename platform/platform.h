#pragma once

// This common "platform.h" header exists to simplify the most common references
// to non-ANSI C/C++ headers, required on Windows, Posix, Linux, BSD etc,
// and to provide substitute definitions when absolutely required.
//
// The goal is to eventually not require this file of header declarations,
// but limit the use of these architecture-specific types and declarations
// to the corresponding .cc implementation files.
#include "absl/strings/string_view.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h> // for UDP_GRO
#include <sys/ioctl.h>
#include <sys/mman.h> // for mode_t
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h> // for iovec
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <endian.h>

#if defined(__linux__)
#include <linux/netfilter_ipv4.h>
#endif

#define PACKED_STRUCT(definition, ...) definition, ##__VA_ARGS__ __attribute__((packed))

#ifndef IP6T_SO_ORIGINAL_DST
// From linux/netfilter_ipv6/ip6_tables.h
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#ifndef UDP_GRO
#define UDP_GRO 104
#endif

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

typedef int os_fd_t;
typedef int filesystem_os_id_t; // NOLINT(modernize-use-using)

#define INVALID_HANDLE -1
#define INVALID_SOCKET -1
#define SOCKET_VALID(sock) ((sock) >= 0)
#define SOCKET_INVALID(sock) ((sock) == -1)
#define SOCKET_FAILURE(rc) ((rc) == -1)
#define SET_SOCKET_INVALID(sock) (sock) = -1

// arguments to shutdown
#define PLATFORM_SHUT_RD SHUT_RD
#define PLATFORM_SHUT_WR SHUT_WR
#define PLATFORM_SHUT_RDWR SHUT_RDWR

// Mapping POSIX socket errors to common error names
#define SOCKET_ERROR_AGAIN EAGAIN
#define SOCKET_ERROR_NOT_SUP ENOTSUP
#define SOCKET_ERROR_AF_NO_SUP EAFNOSUPPORT
#define SOCKET_ERROR_IN_PROGRESS EINPROGRESS
#define SOCKET_ERROR_PERM EPERM
#define SOCKET_ERROR_ACCESS EACCES
#define SOCKET_ERROR_MSG_SIZE EMSGSIZE
#define SOCKET_ERROR_INTR EINTR
#define SOCKET_ERROR_ADDR_NOT_AVAIL EADDRNOTAVAIL
#define SOCKET_ERROR_INVAL EINVAL
#define SOCKET_ERROR_ADDR_IN_USE EADDRINUSE

// Mapping POSIX file errors to common error names
#define HANDLE_ERROR_PERM EACCES
#define HANDLE_ERROR_INVALID EBADF

namespace Platform {
constexpr absl::string_view null_device_path{"/dev/null"};
}

#define PLATFORM_MMSG_MORE 1

#define SUPPORTS_GETIFADDRS

// https://android.googlesource.com/platform/bionic/+/master/docs/status.md
// ``pthread_getname_np`` is introduced in API 26
#define SUPPORTS_PTHREAD_NAMING 0
