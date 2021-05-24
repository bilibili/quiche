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

### Features
- Easy building with cmake
- Only support Linux platform
- Easy to keep pace with Google quiche upgrading

### Source Layout
- `base`: Implementation of basic platform functions
- `googleurl`: Googleurl source files
- `gquiche`: Google quiche source files 
- `net`: Implementation of platform net related functions
- `platform/epoll_platform_impl`: Implementation of epoll client and server functions
- `platform/http2_platform_impl`: Implementation of http2 stack functions
- `platform/quic_platform_impl`: Implementation of quic stack functions
- `platform/quiche_platform_impl`: Implementation of google quiche platform functions
- `platform/spdy_platform_impl`: Implementation of spdy stack functions
- `third_party`: Submodules of thirdparty repositories
- `utils`: Scripts of some usefull utilities

## Getting Started

### Prerequisite  

```bash
apt-get install cmake build-essential protobuf-compiler libprotobuf-dev golang-go libunwind-dev libicu-dev
git submodule update --init
```

### Build  

```bash
mkdir build && cd build  
cmake .. && make
cd -
```

| extra cmake options | values | default |
| ------ | ------ | ------ |
| ENABLE_LINK_TCMALLOC | on, off | on |

### Play examples
- A sample quic server and client implementation are provided in quiche. To use these you should build the binaries.

```bash
cd build
make simple_quic_server simple_quic_client
cd -
```

- Download a copy of www.example.org, which we will serve locally using the simple_quic_server binary.

```bash
mkdir -p /data/quic-root
wget -p --save-headers https://www.example.org -P /data/quic-root
```

- In order to run the simple_quic_server, you will need a valid certificate, and a private key is pkcs8 format. If you don't have one, there are scripts to generate them.

```bash
cd utils
./generate-certs.sh
mkdir -p /data/quic-cert
mv ./out/* /data/quic-cert/
cd -
```

- Run the quic server

```bash
./build/simple_quic_server \
  --quic_response_cache_dir=/data/quic-root/ \
  --certificate_file=/data/quic-cert/leaf_cert.pem \
  --key_file=/data/quic-cert/leaf_cert.pkcs8
```

- Request the file with quic client

```bash
./build/simple_quic_client \
  --disable_certificate_verification=true \
  --host=127.0.0.1 --port=6121 \
  "https://www.example.org/index.html"
```

You can also use chormium-based browsers to access simple_quic_server at `127.0.0.1:6121`, and check the request/response protocol by DevTools -> Network panel.
