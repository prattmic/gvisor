// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_bind_to_device_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/uid_util.h"

namespace gvisor {
namespace testing {

using std::string;
using std::vector;

typedef struct EndpointConfig {
  std::string bind_to_device;
  double expected_ratio;
} EndpointConfig;

typedef struct DistributionTestCase {
  std::string name;
  std::vector<EndpointConfig> endpoints;
} DistributionTestCase;

typedef struct ListenerConnector {
  TestAddress listener;
  TestAddress connector;
} ListenerConnector;

// Test fixture for SO_BINDTODEVICE tests the distribution of packets received
// with varying SO_BINDTODEVICE settings.
class BindToDeviceDistributionTest
    : public ::testing::TestWithParam<
          ::testing::tuple<ListenerConnector, DistributionTestCase>> {
 protected:
  void SetUp() override {
    printf("Testing case: %s, listener=%s, connector=%s\n",
           ::testing::get<1>(GetParam()).name.c_str(),
           ::testing::get<0>(GetParam()).listener.description.c_str(),
           ::testing::get<0>(GetParam()).connector.description.c_str());
    ASSERT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(IsRoot()))
        << "Only root can use SO_BINDTODEVICE";
  }
};

PosixErrorOr<uint16_t> AddrPort(int family, sockaddr_storage const& addr) {
  switch (family) {
    case AF_INET:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in const*>(&addr)->sin_port);
    case AF_INET6:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in6 const*>(&addr)->sin6_port);
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}

PosixError SetAddrPort(int family, sockaddr_storage* addr, uint16_t port) {
  switch (family) {
    case AF_INET:
      reinterpret_cast<sockaddr_in*>(addr)->sin_port = port;
      return NoError();
    case AF_INET6:
      reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = port;
      return NoError();
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}
TEST_P(BindToDeviceDistributionTest, Tcp) {
  auto const& param = GetParam();
  auto const& listener_connector = ::testing::get<0>(param);
  auto const& endpoints = ::testing::get<1>(param).endpoints;

  TestAddress const& listener = listener_connector.listener;
  TestAddress const& connector = listener_connector.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;

  auto interface_names = get_interface_names();

  // Create the listening sockets.
  std::vector<FileDescriptor> listener_fds;
  std::vector<std::unique_ptr<Tunnel>> all_tunnels;
  for (const auto& endpoint : endpoints) {
    if (interface_names.find(endpoint.bind_to_device) ==
        interface_names.end()) {
      all_tunnels.push_back(NewTunnel(endpoint.bind_to_device));
      interface_names.insert(endpoint.bind_to_device);
    }

    listener_fds.push_back(ASSERT_NO_ERRNO_AND_VALUE(
        Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP)));
    int fd = listener_fds.back().get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           endpoint.bind_to_device.c_str(),
                           endpoint.bind_to_device.size() + 1),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());
    ASSERT_THAT(listen(fd, 40), SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (listener_fds.size() > 1) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10000;
  std::atomic<int> connects_received = ATOMIC_VAR_INIT(0);
  std::vector<std::unique_ptr<ScopedThread>> listen_threads;
  std::vector<std::shared_ptr<int>> accept_counts;
  // TODO(avagin): figure how to not disable S/R for the whole test.
  // We need to take into account that this test executes a lot of system
  // calls from many threads.
  DisableSave ds;

  for (const auto& listener_fd : listener_fds) {
    std::shared_ptr<int> accept_count = std::make_shared<int>(0);
    accept_counts.push_back(accept_count);
    listen_threads.push_back(absl::make_unique<ScopedThread>(
        [&listener_fd, &listener_fds, accept_count, &connects_received]() {
          do {
            auto fd = Accept(listener_fd.get(), nullptr, nullptr);
            if (!fd.ok()) {
              if (connects_received >= kConnectAttempts) {
                // Another thread have shutdown our read side causing the
                // accept to fail.
                return;
              }
              ASSERT_NO_ERRNO(fd);
              break;
            }
            // Receive some data from a socket to be sure that the connect()
            // system call has been completed on another side.
            int data;
            EXPECT_THAT(
                RetryEINTR(recv)(fd.ValueOrDie().get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
            (*accept_count)++;
          } while (++connects_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (const auto& listener_fd : listener_fds) {
            shutdown(listener_fd.get(), SHUT_RDWR);
          }
        }));
  }

  for (int i = 0; i < kConnectAttempts; i++) {
    const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(
        RetryEINTR(connect)(fd.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                            connector.addr_len),
        SyscallSucceeds());

    EXPECT_THAT(RetryEINTR(send)(fd.get(), &i, sizeof(i), 0),
                SyscallSucceedsWithValue(sizeof(i)));
  }

  // Join threads to be sure that all connections have been counted.
  for (const auto& listen_thread : listen_threads) {
    listen_thread->Join();
  }
  // Check that connections are distributed fairly between listening sockets
  for (int i = 0; i < accept_counts.size(); i++) {
    EXPECT_THAT(*accept_counts[i],
                EquivalentWithin(
                    int(kConnectAttempts * endpoints[i].expected_ratio), 0.10))
        << "endpoint " << i << " got the wrong number of packets";
  }
}

TEST_P(BindToDeviceDistributionTest, Udp) {
  auto const& param = GetParam();
  auto const& listener_connector = ::testing::get<0>(param);
  auto const& endpoints = ::testing::get<1>(param).endpoints;

  TestAddress const& listener = listener_connector.listener;
  TestAddress const& connector = listener_connector.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;

  auto interface_names = get_interface_names();

  // Create the listening socket.
  std::vector<FileDescriptor> listener_fds;
  std::vector<std::unique_ptr<Tunnel>> all_tunnels;
  for (const auto& endpoint : endpoints) {
    if (interface_names.find(endpoint.bind_to_device) ==
        interface_names.end()) {
      all_tunnels.push_back(NewTunnel(endpoint.bind_to_device));
      interface_names.insert(endpoint.bind_to_device);
    }

    listener_fds.push_back(
        ASSERT_NO_ERRNO_AND_VALUE(Socket(listener.family(), SOCK_DGRAM, 0)));
    int fd = listener_fds.back().get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           endpoint.bind_to_device.c_str(),
                           endpoint.bind_to_device.size() + 1),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (listener_fds.size() > 1) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10000;
  std::atomic<int> packets_received = ATOMIC_VAR_INIT(0);
  std::vector<std::unique_ptr<ScopedThread>> receiver_threads;
  std::vector<std::shared_ptr<int>> packets_per_socket;
  // TODO(avagin): figure how to not disable S/R for the whole test.
  DisableSave ds;  // Too expensive.

  for (const auto& listener_fd : listener_fds) {
    std::shared_ptr<int> packet_per_socket = std::make_shared<int>(0);
    packets_per_socket.push_back(packet_per_socket);
    receiver_threads.push_back(absl::make_unique<ScopedThread>(
        [&listener_fd, &listener_fds, packet_per_socket, &packets_received]() {
          do {
            struct sockaddr_storage addr = {};
            socklen_t addrlen = sizeof(addr);
            int data;

            auto ret = RetryEINTR(recvfrom)(
                listener_fd.get(), &data, sizeof(data), 0,
                reinterpret_cast<struct sockaddr*>(&addr), &addrlen);

            if (packets_received < kConnectAttempts) {
              ASSERT_THAT(ret, SyscallSucceedsWithValue(sizeof(data)));
            }

            if (ret != sizeof(data)) {
              // Another thread may have shutdown our read side causing the
              // recvfrom to fail.
              break;
            }

            packets_received++;
            (*packet_per_socket)++;

            // A response is required to synchronize with the main thread,
            // otherwise the main thread can send more than can fit into receive
            // queues.
            EXPECT_THAT(
                RetryEINTR(sendto)(listener_fd.get(), &data, sizeof(data), 0,
                                   reinterpret_cast<sockaddr*>(&addr), addrlen),
                SyscallSucceedsWithValue(sizeof(data)));
          } while (packets_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (const auto& listener_fd : listener_fds) {
            shutdown(listener_fd.get(), SHUT_RDWR);
          }
        }));
  }

  for (int i = 0; i < kConnectAttempts; i++) {
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(connector.family(), SOCK_DGRAM, 0));
    EXPECT_THAT(RetryEINTR(sendto)(fd.get(), &i, sizeof(i), 0,
                                   reinterpret_cast<sockaddr*>(&conn_addr),
                                   connector.addr_len),
                SyscallSucceedsWithValue(sizeof(i)));
    int data;
    EXPECT_THAT(RetryEINTR(recv)(fd.get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
  }

  // Join threads to be sure that all connections have been counted
  for (const auto& receiver_thread : receiver_threads) {
    receiver_thread->Join();
  }
  // Check that packets are distributed fairly between listening sockets.
  for (int i = 0; i < packets_per_socket.size(); i++) {
    EXPECT_THAT(*packets_per_socket[i],
                EquivalentWithin(
                    int(kConnectAttempts * endpoints[i].expected_ratio), 0.10));
  }
}

EndpointConfig NewEndpointConfig(std::string bind_to_device,
                                 double expected_ratio) {
  EndpointConfig endpoint_config;
  endpoint_config.bind_to_device = bind_to_device;
  endpoint_config.expected_ratio = expected_ratio;
  return endpoint_config;
}

DistributionTestCase NewDistributionTestCase(
    string name, std::vector<EndpointConfig> endpoints) {
  DistributionTestCase test_case;
  test_case.name = name;
  test_case.endpoints = endpoints;
  return test_case;
}

std::vector<DistributionTestCase> GetDistributionTestCases() {
  return std::vector<DistributionTestCase>{
      NewDistributionTestCase(
          "Even distribution among sockets not bound to device",
          {NewEndpointConfig("", 1. / 3), NewEndpointConfig("", 1. / 3),
           NewEndpointConfig("", 1. / 3)}),
      NewDistributionTestCase(
          "Sockets bound to other interfaces get no packets",
          {NewEndpointConfig("eth1", 0), NewEndpointConfig("", 1. / 2),
           NewEndpointConfig("", 1. / 2)}),
      NewDistributionTestCase(
          "Bound has priority over unbound",
          {NewEndpointConfig("eth1", 0), NewEndpointConfig("", 0),
           NewEndpointConfig("lo", 1)}),
      NewDistributionTestCase(
          "Even distribution among sockets bound to device",
          {NewEndpointConfig("eth1", 0), NewEndpointConfig("lo", 1. / 2),
           NewEndpointConfig("lo", 1. / 2)}),
  };
}

INSTANTIATE_TEST_SUITE_P(
    BindToDeviceTest, BindToDeviceDistributionTest,
    ::testing::Combine(::testing::Values(
                           // Listeners bound to IPv4 addresses refuse
                           // connections using IPv6 addresses.
                           ListenerConnector{V4Any(), V4Loopback()},
                           ListenerConnector{V4Loopback(), V4MappedLoopback()}),
                       ::testing::ValuesIn(GetDistributionTestCases())));

}  // namespace testing
}  // namespace gvisor
