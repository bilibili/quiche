# quiche

quiche is a work-in-progress QUIC implementation by BVC (Bilibili Video Cloud team). It is based on Google quiche(https://quiche.googlesource.com/quiche/). BVC uses this to enable gQUIC and iQUIC service capability on production, for example, there are quic proxy server and nginx quic module.

QUIC (Quick UDP Internet Connections) is a new transport which reduces latency compared to that of TCP. Look QUIC from 10000 feet, it is very similar to TCP+TLS+HTTP/2 implemented on UDP. Because TCP is implemented in operating system kernels, and middlebox firmware, making significant changes to TCP is next to impossible. However, since QUIC is built on top of UDP, it suffers from no such limitations.

Key features of QUIC+HTTP3 over existing TCP+TLS+HTTP2 include
- User space implementation
- Dramatically reduced connection establishment time
- Improved congestion control
- Multiplexing without head of line blocking
- Connection migration

Google quiche is used in Chromium (http://www.chromium.org/quic) project. This repository integrates google quiche with some common-used repositories, which are independent of Chromium platform.
- Platform related implementations of epoll server/client, http2 stack, quic stack
- Rewrite include directives for google quiche source files

## Features
- Easy building with cmake
- Only support Linux platform
- Easy to keep pace with Google quiche upgrading

## Source Layout
- `base`: Implementation of basic platform functions
- `googleurl`: Googleurl source files
- `gquiche`: Google quiche source files 
- `net`: Implementation of platform net related functions
- `platform/epoll_platform_impl`: Implementation of epoll client and server functions
- `platform/http2_platform_impl`: Implementation of http2 stack functions
- `platform/quic_platform_impl`: Implementation of quic stack functions
- `platform/quiche_platform_impl`: Implementation of google quiche platform functions
- `platform/spdy_platform_impl`: Implementation of spdy stack functions
-`third_party`: Submodules of thirdparty repositories
- `utils`: Scripts of some usefull utilities

## Building quiche

**1. Prerequisite**  

> apt-get install git cmake build-essential protobuf-compiler libprotobuf-dev golang-go libunwind-dev libicu-dev

**2. Build**  

> mkdir build && cd build  
> cmake .. && make

| extra cmake options | values | default |
| ------ | ------ | ------ |
| ENABLE_LINK_TCMALLOC | on, off | on |

## Play examples
